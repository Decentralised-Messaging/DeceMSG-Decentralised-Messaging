# DeceMSG Updated Security & Architecture Audit

## Executive Summary

DeceMSG should be treated as a decentralized messaging protocol with WhatsApp-quality UX rather than as a decentralized copy of WhatsApp.

The current implementation contains useful foundations, but several security boundaries are not yet production-safe. The highest-priority work is to secure federation authentication and authorization, integrate end-to-end encryption into the normal message path, formalize identity/device/session models, and add replay/idempotency protections.

## Identity Architecture

Separate these concepts:

- Server
- User
- UserIdentity
- Device
- FederatedIdentity
- Conversation
- ConversationParticipant
- Message/Event
- Session
- RecoveryCredential
- ServerTrustRecord

A DeceMSG account may have an identity such as `alice#provider.com`, while each device has its own cryptographic identity.

## Password Architecture

Password is used for authentication and optional recovery, not directly as a message-encryption key.

Recommended flow:

```
Password
   |
   +--> Authentication verifier
   |
   +--> Argon2id
          |
          +--> Recovery/key-encryption key
```

An encrypted identity backup may be stored by the provider, but plaintext private keys must not be stored server-side.

Changing the password should update authentication material and, where applicable, re-encrypt the encrypted recovery backup. It should not rotate the user's DeceMSG identity or invalidate existing device encryption keys.

## Multiple Devices

Each device should receive and maintain its own cryptographic identity.

Required lifecycle capabilities:

- Add a device without invalidating other devices.
- Revoke individual devices.
- Display and manage active devices.
- Support browser, phone, and other first-class clients.
- Preserve existing chats and identity across password changes.

## Web Application

The browser should be a first-class DeceMSG client.

Use Web Crypto API and protected browser storage such as IndexedDB for device key material. Do not place private keys in plaintext localStorage.

The web client must account for:

- XSS/CSP protection
- Secure session handling
- CSRF protection where cookie authentication is used
- Site-data clearing and browser-profile loss
- Explicit device revocation
- Multiple browser/device sessions

## New Device Recovery

Recommended baseline:

```
New Device
 -> Address + Password
 -> Authenticate
 -> Retrieve encrypted identity backup
 -> Argon2id(password)
 -> Decrypt locally
 -> Restore identity / authorize device
```

Alternative recovery mechanisms may include existing-device approval, passkeys, or recovery codes.

## End-to-End Encryption

The target message flow is:

```
Alice Device
 -> Encrypt + sign locally
 -> Alice Server
 -> Secure Federation
 -> Bob Server
 -> Bob Device
 -> Decrypt locally
```

Use a well-reviewed messaging cryptographic protocol rather than inventing new cryptography.

The implementation must cover 1:1 chats, groups, multi-device key management, device addition/removal/revocation, offline delivery, replay protection, and recovery.

## Federation Security

Discovery is not trust.

The federation protocol should establish:

1. Discovery
2. Identity
3. Authentication
4. Authorization
5. Trust

A signed federation event should contain fields conceptually similar to:

```
event_id
event_type
protocol_version
origin_server
origin_key_id
actor_identity
target_identity
conversation_id
created_at
sequence
ciphertext
signature
```

Federation receivers should verify origin key/domain binding, signatures, timestamps, replay/idempotency, actor ownership, origin authorization, conversation authorization, and target ownership.

## Critical Findings

1. Federation authentication middleware exists but is not installed in the main application setup.
2. Server-key/domain binding is insufficient; signature possession alone does not prove authority over a claimed domain.
3. Federation message creation and synchronization require stronger authenticated-origin and authorization checks.
4. Federation chat/group synchronization and member operations require explicit server and conversation authority validation.
5. Federation message update/delete operations need sender/origin authorization.
6. Delivery receipts require authenticated origin and message/conversation authorization.
7. E2EE is not integrated into the normal message path; the normal federation flow currently transmits plaintext message content.
8. The current in-memory key store is not suitable for production and is lost on process restart.

## High-Priority Findings

- Remote identities such as `bob#remote.example` should not be forced through local-user foreign keys. Add an explicit FederatedIdentity/RemoteUser model.
- Federated search must derive the requesting identity from authenticated credentials rather than trusting a caller-supplied user_id.
- User migration export/import requires strong authorization and explicit validation.
- Avoid passing JWTs in WebSocket query parameters.
- Revalidate session state and token expiry for long-lived WebSocket connections.
- Add server-side session revocation.
- Password changes should require appropriate re-authentication or step-up verification.
- Presence access should be authenticated and governed by explicit privacy rules.
- File uploads must enforce limits before reading entire payloads into memory and should use MIME/magic-byte validation.
- Untrusted uploads should use appropriate scanning/isolation.

## Architecture and Reliability Findings

- Federation scope is too broad for the current security maturity.
- JSON-file offline/retry queues are not sufficient for transactional multi-process deployments.
- In-memory rate limiting is not shared across workers.
- Production CORS should use an explicit allowlist.
- Database migrations should use Alembic rather than relying on create_all.
- Group functionality remains incomplete relative to the desired product.
- Ephemeral-message expiry needs a reliable lifecycle worker.
- Pagination should use deterministic ordering such as `(created_at, message_id)` or a monotonic sequence.
- The message API contains an `asyncio.create_task(...)` usage without the required import and should be fixed.
- Reaction deletion needs complete authorization checks.
- Admin configuration validation should be strengthened.
- Replace print-style logging with structured security/audit logs that avoid secrets and message content.
- ActivityPub should remain experimental until actor ownership, signature verification, replay protection, and inbox authorization are complete.

## AI Agent Identity

AI agents are first-class DeceMSG identities.

Agent controls should include:

- explicit identity
- scoped permissions
- consent
- audit logging
- rate limits
- revocation
- tool-specific authorization

## Features to Defer Until Core Security Is Ready

Prioritize a secure minimal federation core before expanding into:

- ActivityPub interoperability
- federated search
- migration
- federated files
- push integrations
- broader federation surfaces

Documentation should distinguish Implemented, Tested, Experimental, Prototype, Stub, and Planned.

## Threat Model

Explicitly model:

- malicious users
- malicious or compromised servers
- DNS manipulation
- network attackers
- replay attacks
- message injection
- spam/abuse
- Sybil behavior
- stolen JWT/session tokens
- compromised devices
- malicious or over-privileged AI agents

## Testing and CI/CD

Required test layers:

- unit tests
- API integration tests
- federation integration tests
- security/attack tests
- end-to-end encrypted message flows
- multi-device tests
- recovery tests
- performance/load tests

CI should run formatting/linting, type checks, tests, and security checks on pull requests and protected branches.

## Recommended P0-P3 Roadmap

### P0 — Security Foundation

Secure federation middleware and server authentication, implement domain-key trust binding, authorization boundaries, session revocation, WebSocket hardening, upload limits, and structured audit logging.

### P1 — Identity and E2EE

Implement UserIdentity, Device, Session, RecoveryCredential, and FederatedIdentity models. Integrate E2EE into the complete 1:1 message lifecycle and add multi-device key management.

### P2 — Federation Reliability

Introduce signed events, replay/idempotency handling, durable queues, shared rate limiting, deterministic ordering, and robust group synchronization.

### P3 — Ecosystem Expansion

Revisit ActivityPub, search, migration, federated files, and other advanced integrations after the security foundation is proven.

## Target Architecture

```
DeceMSG Account
  |
  +-- User Identity -> alice#provider.com
  |
  +-- Authentication -> Password / optional passkey / optional 2FA
  |
  +-- Devices -> Phone / Laptop / Browser
```

Secure message path:

```
Alice Device
  -> Encrypt + Sign
  -> Alice Provider
  -> Authenticated Federation Event
  -> Bob Provider
  -> Bob Device(s)
  -> Decrypt + Verify
```

## Confirmed Architectural Decisions

- DeceMSG uses `user#domain.com` identities.
- Users should not manually manage cryptographic keys.
- Password is for authentication and recovery, not directly for message encryption.
- Password changes do not change DeceMSG identity.
- Each device has its own crypto identity.
- New-device recovery should decrypt an encrypted identity backup locally.
- Web clients are first-class clients.
- Federation requires explicit identity, authentication, authorization, and trust boundaries.
- AI agents are first-class identities with scopes and revocation.

## Conclusion

The repository has a useful prototype foundation, but the next engineering phase should focus on making security boundaries explicit and enforceable before expanding protocol surface area.

The next deliverable after this audit is a detailed Alice-to-Bob protocol specification followed by an implementation task list with acceptance criteria.
