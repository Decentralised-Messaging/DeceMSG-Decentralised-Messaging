"""Federation discovery protocol for DeceMSG."""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
import httpx
import asyncio
import socket
import dns.resolver
import dns.exception
from urllib.parse import urlparse

from decemsg.core.config import get_config
from decemsg.federation.server_auth import create_authenticated_request


# DNS SRV record service name for DeceMSG federation
DECEMSG_SERVICE = "_decemsg._tcp"


class ServerInfo(BaseModel):
    """Information about a federated server."""
    domain: str
    name: str
    version: str
    api_url: str
    is_online: bool = True
    last_seen: Optional[str] = None


class FederationRegistry:
    """Registry for known federated servers."""
    
    def __init__(self):
        self._servers: Dict[str, ServerInfo] = {}
    
    def add_server(self, domain: str, info: ServerInfo):
        """Add a server to the registry."""
        self._servers[domain] = info
    
    def remove_server(self, domain: str):
        """Remove a server from the registry."""
        if domain in self._servers:
            del self._servers[domain]
    
    def get_server(self, domain: str) -> Optional[ServerInfo]:
        """Get server info by domain."""
        return self._servers.get(domain)
    
    def get_all_servers(self) -> List[ServerInfo]:
        """Get all registered servers."""
        return list(self._servers.values())
    
    def is_server_known(self, domain: str) -> bool:
        """Check if a server is known."""
        return domain in self._servers


class FederationClient:
    """Client for federated server communication."""
    
    def __init__(self):
        self.registry = FederationRegistry()
        self._timeout = 10.0
    
    async def discover_server(self, domain: str) -> Optional[ServerInfo]:
        """Discover a server using DNS SRV records or .well-known endpoint.
        
        Discovery order:
        1. Check local cache/registry
        2. Try DNS SRV record lookup (_decemsg._tcp.domain)
        3. Fall back to .well-known/nodeinfo endpoint
        """
        config = get_config()
        
        # Don't discover self
        if domain == config.server.domain:
            return None
        
        # Check if already known
        if self.registry.is_server_known(domain):
            return self.registry.get_server(domain)
        
        # Try DNS SRV record discovery first
        srv_result = await self._discover_via_srv(domain)
        if srv_result:
            return srv_result
        
        # Fall back to .well-known endpoint
        return await self._discover_via_wellknown(domain)
    
    async def _discover_via_srv(self, domain: str) -> Optional[ServerInfo]:
        """Discover server via DNS SRV record lookup.
        
        SRV record format: _decemsg._tcp.domain -> priority weight port target
        """
        try:
            # Try to resolve SRV record
            srv_record = f"{DECEMSG_SERVICE}.{domain}"
            
            # Use socket to get SRV records (synchronous, run in executor)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self._resolve_srv_record, srv_record
            )
            
            if result:
                target_host, port = result
                # Build API URL from SRV record
                if target_host.startswith("http"):
                    api_url = target_host.rstrip("/")
                else:
                    protocol = "https" if port == 443 else "http"
                    api_url = f"{protocol}://{target_host}"
                
                # Verify server with nodeinfo and get details
                return await self._verify_and_get_info(domain, api_url)
                
        except Exception as e:
            print(f"SRV discovery failed for {domain}: {e}")
        
        return None
    
    def _resolve_srv_record(self, srv_name: str) -> Optional[tuple]:
        """Resolve SRV record using dnspython for real DNS SRV lookups.
        
        Returns (target, port) tuple or None if not found.
        """
        try:
            # First try actual DNS SRV record lookup
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 5.0
            
            srv_record = f"{DECEMSG_SERVICE}.{srv_name.replace(f'{DECEMSG_SERVICE}.', '')}"
            
            try:
                answers = resolver.resolve(srv_record, 'SRV')
                
                # Get the SRV record with lowest priority
                best_record = None
                for rdata in answers:
                    if best_record is None or rdata.priority < best_record.priority:
                        best_record = rdata
                
                if best_record:
                    target = str(best_record.target).rstrip('.')
                    port = best_record.port
                    return (target, port)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass  # No SRV record, try fallback
            
            # Fallback: Try direct connection to common ports
            target_domain = srv_name.replace(f"{DECEMSG_SERVICE}.", "")
            ports_to_try = [443, 8443, 8000, 8080]
            
            for port in ports_to_try:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target_domain, port))
                    sock.close()
                    
                    if result == 0:
                        return (target_domain, port)
                except:
                    continue
            
            # Default to HTTPS port
            return (target_domain, 443)
            
        except Exception as e:
            print(f"SRV resolution error: {e}")
        
        return None
    
    async def _discover_via_wellknown(self, domain: str) -> Optional[ServerInfo]:
        """Discover server via .well-known/nodeinfo endpoint."""
        server_url = self._build_server_url(domain)
        nodeinfo_url = f"{server_url}/.well-known/nodeinfo"
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(nodeinfo_url)
                
                if response.status_code == 200:
                    data = response.json()
                    server_info = ServerInfo(
                        domain=domain,
                        name=data.get("name", domain),
                        version=data.get("version", "unknown"),
                        api_url=server_url
                    )
                    self.registry.add_server(domain, server_info)
                    return server_info
                    
        except Exception as e:
            print(f"Well-known discovery failed for {domain}: {e}")
        
        return None
    
    async def _verify_and_get_info(self, domain: str, api_url: str) -> Optional[ServerInfo]:
        """Verify server exists at API URL and get server info."""
        nodeinfo_url = f"{api_url}/.well-known/nodeinfo"
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(nodeinfo_url)
                
                if response.status_code == 200:
                    data = response.json()
                    server_info = ServerInfo(
                        domain=domain,
                        name=data.get("name", domain),
                        version=data.get("version", "unknown"),
                        api_url=api_url
                    )
                    self.registry.add_server(domain, server_info)
                    return server_info
                    
        except Exception as e:
            print(f"Server verification failed for {domain}: {e}")
        
        return None
    
    async def lookup_user(self, username: str, domain: str) -> Optional[Dict[str, Any]]:
        """Look up a user on a federated server."""
        server_info = await self.discover_server(domain)
        
        if not server_info:
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                # Query the user lookup endpoint
                response = await client.get(
                    f"{server_info.api_url}/federation/users/{username}",
                    headers={"Accept": "application/json"}
                )
                
                if response.status_code == 200:
                    return response.json()
                    
        except Exception as e:
            print(f"User lookup failed for {username}@{domain}: {e}")
        
        return None
    
    async def send_message(
        self,
        from_user: str,
        from_domain: str,
        to_user: str,
        to_domain: str,
        content: str,
        message_type: str = "text",
        event: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send a message to a federated user."""
        server_info = await self.discover_server(to_domain)
        
        if not server_info:
            return False
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                import json
                payload = {
                    "from_user": from_user,
                    "from_domain": from_domain,
                    "to_user": to_user,
                    "content": content,
                    "message_type": message_type,
                    "encrypted": True,
                    "event": event,
                }
                body = json.dumps(
                    payload,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                headers = create_authenticated_request(
                    "POST",
                    "/federation/messages",
                    body,
                )
                headers["Content-Type"] = "application/json"
                response = await client.post(
                    f"{server_info.api_url}/federation/messages",
                    content=body,
                    headers=headers,
                )
                
                return response.status_code in (200, 201, 202)
                
        except Exception as e:
            print(f"Message send failed: {e}")
        
        return False
    
    async def broadcast_presence(
        self,
        user: str,
        domain: str,
        is_online: bool
    ):
        """Broadcast presence status to federated servers."""
        for server in self.registry.get_all_servers():
            if server.domain == domain:
                continue
            
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    await client.post(
                        f"{server.api_url}/federation/presence",
                        json={
                            "user": user,
                            "domain": domain,
                            "is_online": is_online
                        }
                    )
            except Exception:
                pass
    
    def _build_server_url(self, domain: str) -> str:
        """Build server URL from domain."""
        # Default to HTTPS
        if domain.startswith("http"):
            return domain.rstrip("/")
        return f"https://{domain}"
    
    async def discover_all_known_servers(self) -> List[ServerInfo]:
        """Discover and return all known servers."""
        # Return cached servers for now
        # In production, this would query a federation directory
        return self.registry.get_all_servers()
    
    async def health_check(self, domain: str) -> bool:
        """Check if a federated server is healthy."""
        server_info = self.registry.get_server(domain)
        
        if not server_info:
            server_info = await self.discover_server(domain)
        
        if not server_info:
            return False
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{server_info.api_url}/health")
                return response.status_code == 200
        except Exception:
            return False

    async def sync_chat(
        self,
        chat_id: str,
        member_ids: list[str],
        domain: str
    ) -> bool:
        """Sync chat membership with a federated server."""
        server_info = await self.discover_server(domain)

        if not server_info:
            return False

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{server_info.api_url}/federation/chats/sync",
                    json={
                        "chat_id": chat_id,
                        "members": member_ids
                    },
                    headers={"Content-Type": "application/json"}
                )

                return response.status_code in (200, 201, 202)

        except Exception as e:
            print(f"Chat sync failed: {e}")

        return False
    
    async def sync_group_chat(
        self,
        chat_id: str,
        name: str,
        members: list[str],
        created_by: str,
        domain: str
    ) -> bool:
        """Sync group chat with a federated server."""
        server_info = await self.discover_server(domain)

        if not server_info:
            return False

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{server_info.api_url}/federation/chats/group/sync",
                    json={
                        "chat_id": chat_id,
                        "name": name,
                        "members": members,
                        "created_by": created_by
                    },
                    headers={"Content-Type": "application/json"}
                )

                return response.status_code in (200, 201, 202)

        except Exception as e:
            print(f"Group chat sync failed: {e}")

        return False
    
    async def send_message_update(
        self,
        message_id: str,
        chat_id: str,
        content: str,
        domain: str
    ) -> bool:
        """Send message edit to federated server."""
        server_info = await self.discover_server(domain)

        if not server_info:
            return False

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{server_info.api_url}/federation/messages/update",
                    json={
                        "message_id": message_id,
                        "chat_id": chat_id,
                        "content": content
                    },
                    headers={"Content-Type": "application/json"}
                )

                return response.status_code in (200, 201, 202)

        except Exception as e:
            print(f"Message update failed: {e}")

        return False
    
    async def send_message_delete(
        self,
        message_id: str,
        chat_id: str,
        domain: str
    ) -> bool:
        """Send message delete to federated server."""
        server_info = await self.discover_server(domain)

        if not server_info:
            return False

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{server_info.api_url}/federation/messages/delete",
                    json={
                        "message_id": message_id,
                        "chat_id": chat_id
                    },
                    headers={"Content-Type": "application/json"}
                )

                return response.status_code in (200, 201, 202)

        except Exception as e:
            print(f"Message delete failed: {e}")

        return False
    
    async def send_typing_indicator(
        self,
        chat_id: str,
        user_id: str,
        is_typing: bool,
        domain: str
    ) -> bool:
        """Send typing indicator to federated server."""
        server_info = await self.discover_server(domain)

        if not server_info:
            return False

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{server_info.api_url}/federation/typing",
                    json={
                        "chat_id": chat_id,
                        "user_id": user_id,
                        "is_typing": is_typing
                    },
                    headers={"Content-Type": "application/json"}
                )

                return response.status_code in (200, 201, 202)

        except Exception as e:
            print(f"Typing indicator failed: {e}")

        return False
    
    async def send_profile_update(
        self,
        user_id: str,
        display_name: str,
        avatar_url: str,
        domain: str
    ) -> bool:
        """Send profile update to federated server."""
        server_info = await self.discover_server(domain)

        if not server_info:
            return False

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{server_info.api_url}/federation/profile/update",
                    json={
                        "user_id": user_id,
                        "display_name": display_name,
                        "avatar_url": avatar_url
                    },
                    headers={"Content-Type": "application/json"}
                )

                return response.status_code in (200, 201, 202)

        except Exception as e:
            print(f"Profile update failed: {e}")

        return False


# Global federation client instance
_federation_client: Optional[FederationClient] = None


def get_federation_client() -> FederationClient:
    """Get the global federation client instance."""
    global _federation_client
    if _federation_client is None:
        _federation_client = FederationClient()
    return _federation_client
