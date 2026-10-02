"""Federation router for cross-server message routing."""
import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from decemsg.core.config import get_config
from decemsg.federation.discovery import get_federation_client, ServerInfo
from decemsg.federation.events import build_message_event
from decemsg.federation.delivery_queue import add_federation_delivery_job, enqueue_federation_delivery

logger = logging.getLogger(__name__)


def parse_user_id(user_id: str) -> tuple[str, Optional[str]]:
    """Parse user_id into username and domain.
    
    Args:
        user_id: Can be 'username' or 'username#domain'
    
    Returns:
        Tuple of (username, domain) - domain is None for local users
    """
    if '#' in user_id:
        parts = user_id.split('#', 1)
        return parts[0], parts[1]
    return user_id, None


def is_federated_user(user_id: str) -> bool:
    """Check if a user_id refers to a federated (remote) user.
    
    Args:
        user_id: Can be 'username' or 'username#domain'
    
    Returns:
        True if the user is on a remote server
    """
    config = get_config()
    username, domain = parse_user_id(user_id)
    
    # If no domain specified, it's a local user
    if domain is None:
        return False
    
    # If domain is our own domain, it's local
    if domain == config.server.domain:
        return False
    
    # Otherwise, it's a federated user
    return True


def get_user_domain(user_id: str) -> str:
    """Get the domain for a user_id.
    
    Args:
        user_id: Can be 'username' or 'username#domain'
    
    Returns:
        The domain (local domain if not specified)
    """
    config = get_config()
    _, domain = parse_user_id(user_id)
    return domain or config.server.domain


async def route_message(
    from_user: str,
    to_user: str,
    content: str,
    message_type: str = "text",
    conversation_id: str = "",
    db: Optional[AsyncSession] = None,
) -> bool:
    """Route a message to a federated server if needed.
    
    Args:
        from_user: Sender user_id (local format)
        to_user: Recipient user_id (can include #domain)
        content: Message content
        message_type: Type of message (text, image, file, etc.)
    
    Returns:
        True if message was sent successfully, False otherwise
    """
    config = get_config()
    
    # Check if recipient is federated
    if not is_federated_user(to_user):
        # Local user - no federation needed
        return False
    
    from_username, from_domain = parse_user_id(from_user)
    to_username, to_domain = parse_user_id(to_user)
    
    # Use local domain if not specified
    if from_domain is None:
        from_domain = config.server.domain
    if to_domain is None:
        to_domain = config.server.domain
    
    try:
        event = build_message_event(
            actor_identity=f"{from_username}#{from_domain}",
            target_identity=f"{to_username}#{to_domain}",
            conversation_id=conversation_id,
            ciphertext=content,
            message_type=message_type,
        )

        payload = {
            "from_user": from_username,
            "from_domain": from_domain,
            "to_user": to_username,
            "to_domain": to_domain,
            "content": content,
            "message_type": message_type,
            "event": event,
        }
        if db is not None:
            await add_federation_delivery_job(
                db,
                idempotency_key=f"message:{event['event_id']}",
                job_type="message",
                destination_domain=to_domain,
                payload=payload,
            )
            success = True
        else:
            success = await enqueue_federation_delivery(
                idempotency_key=f"message:{event['event_id']}",
                job_type="message",
                destination_domain=to_domain,
                payload=payload,
            )

        return success
    
    except Exception as e:
        logger.error(f"Error routing federated message: {e}")
        if db is not None:
            raise
        return False


async def lookup_federated_user(username: str, domain: str) -> Optional[dict]:
    """Look up a user on a federated server.
    
    Args:
        username: Username to look up
        domain: Domain of the user's server
    
    Returns:
        User info dict if found, None otherwise
    """
    config = get_config()
    
    # Don't lookup local domain
    if domain == config.server.domain:
        return None
    
    try:
        client = get_federation_client()
        return await client.lookup_user(username, domain)
    except Exception as e:
        logger.error(f"Error looking up federated user {username}@{domain}: {e}")
        return None


async def sync_chat_members(
    chat_id: str,
    local_members: list[str],
    remote_domains: list[str]
) -> dict:
    """Sync chat members across federated servers.
    
    Args:
        chat_id: Local chat ID
        local_members: List of local member user IDs
        remote_domains: List of remote domains with members in this chat
    
    Returns:
        Dict with sync results
    """
    config = get_config()
    results = {"success": True, "synced_domains": [], "failed_domains": []}
    
    for domain in remote_domains:
        if domain == config.server.domain:
            continue
        
        try:
            client = get_federation_client()
            success = await client.sync_chat(chat_id, local_members, domain)
            
            if success:
                results["synced_domains"].append(domain)
            else:
                results["failed_domains"].append(domain)
                results["success"] = False
        except Exception as e:
            logger.error(f"Error syncing chat {chat_id} with {domain}: {e}")
            results["failed_domains"].append(domain)
            results["success"] = False
    
    return results


async def sync_group_chat(
    chat_id: str,
    name: str,
    members: list[str],
    created_by: str
) -> dict:
    """Sync a group chat across federated servers."""
    config = get_config()
    results = {"success": True, "synced_domains": [], "failed_domains": []}
    
    # Get unique domains from members
    domains = set()
    for member in members:
        _, domain = parse_user_id(member)
        if domain and domain != config.server.domain:
            domains.add(domain)
    
    for domain in domains:
        try:
            client = get_federation_client()
            success = await client.sync_group_chat(chat_id, name, members, created_by, domain)
            
            if success:
                results["synced_domains"].append(domain)
            else:
                results["failed_domains"].append(domain)
                results["success"] = False
        except Exception as e:
            logger.error(f"Error syncing group {chat_id} with {domain}: {e}")
            results["failed_domains"].append(domain)
            results["success"] = False
    
    return results


async def send_message_update(
    message_id: str,
    chat_id: str,
    content: str
) -> dict:
    """Send a message edit to federated chat members."""
    config = get_config()
    results = {"success": True, "failed_domains": []}
    
    # Get chat members
    from decemsg.core.database import get_db
    from sqlalchemy import select
    from decemsg.models.chat import Chat, ChatMember
    
    async for db in get_db():
        result = await db.execute(
            select(ChatMember).where(ChatMember.chat_id == chat_id)
        )
        members = result.scalars().all()
        
        for member in members:
            if is_federated_user(member.user_id):
                _, domain = parse_user_id(member.user_id)
                try:
                    client = get_federation_client()
                    success = await client.send_message_update(
                        message_id, chat_id, content, domain
                    )
                    if not success:
                        results["failed_domains"].append(domain)
                        results["success"] = False
                except Exception as e:
                    logger.error(f"Error sending message update: {e}")
                    results["failed_domains"].append(domain)
                    results["success"] = False
        break
    
    return results


async def send_message_delete(
    message_id: str,
    chat_id: str
) -> dict:
    """Send a message delete to federated chat members."""
    config = get_config()
    results = {"success": True, "failed_domains": []}
    
    from decemsg.core.database import get_db
    from sqlalchemy import select
    from decemsg.models.chat import Chat, ChatMember
    
    async for db in get_db():
        result = await db.execute(
            select(ChatMember).where(ChatMember.chat_id == chat_id)
        )
        members = result.scalars().all()
        
        for member in members:
            if is_federated_user(member.user_id):
                _, domain = parse_user_id(member.user_id)
                try:
                    client = get_federation_client()
                    success = await client.send_message_delete(
                        message_id, chat_id, domain
                    )
                    if not success:
                        results["failed_domains"].append(domain)
                        results["success"] = False
                except Exception as e:
                    logger.error(f"Error sending message delete: {e}")
                    results["failed_domains"].append(domain)
                    results["success"] = False
        break
    
    return results


async def send_typing_indicator(
    chat_id: str,
    user_id: str,
    is_typing: bool
) -> dict:
    """Send typing indicator to federated chat members."""
    config = get_config()
    results = {"success": True, "failed_domains": []}
    
    from decemsg.core.database import get_db
    from sqlalchemy import select
    from decemsg.models.chat import Chat, ChatMember
    
    async for db in get_db():
        result = await db.execute(
            select(ChatMember).where(ChatMember.chat_id == chat_id)
        )
        members = result.scalars().all()
        
        for member in members:
            if is_federated_user(member.user_id):
                _, domain = parse_user_id(member.user_id)
                try:
                    client = get_federation_client()
                    success = await client.send_typing_indicator(
                        chat_id, user_id, is_typing, domain
                    )
                    if not success:
                        results["failed_domains"].append(domain)
                except Exception as e:
                    logger.error(f"Error sending typing indicator: {e}")
                    results["failed_domains"].append(domain)
        break
    
    return results
