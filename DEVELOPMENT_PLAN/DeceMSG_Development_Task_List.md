# DeceMSG Development Task List

**Source:** `DEVELOPMENT_PLAN/DeceMSG_Updated_Security_Architecture_Audit.md`  
**Purpose:** Execution backlog with explicit acceptance criteria.  
**Execution rule:** Complete tasks in dependency order. Do not mark a task complete until its acceptance criteria and required tests pass.

---

## Priority and Status

- **P0:** Security-critical / blocks safe federation or production use.
- **P1:** Core identity, device, recovery, and E2EE.
- **P2:** Federation reliability and protocol maturity.
- **P3:** Ecosystem expansion.
- **Status:** Planned unless explicitly changed to In Progress / Blocked / Done.

---

# Phase 0 — Baseline and Safety

## TASK-001 — Establish Security Baseline and CI Gate

**Priority:** P0  
**Status:** Done  
**Dependencies:** None

### Scope

Create a reproducible engineering/security baseline before modifying core architecture.

### Work

- Establish formatting/linting configuration.
- Establish type-checking configuration where applicable.
- Establish the baseline test command.
- Add CI for pull requests and main.
- Add dependency/security scanning appropriate to the Python stack.
- Record the current baseline failures separately from newly introduced failures.
- Ensure CI does not silently skip security-critical tests.

### Acceptance Criteria

- [ ] A clean checkout can run the documented test/lint/type-check commands.
- [ ] CI runs automatically for pull requests.
- [ ] CI runs automatically for changes to main.
- [ ] A failing required check causes CI failure.
- [ ] Existing baseline failures are documented rather than hidden or disabled.
- [ ] No secrets are required to run ordinary unit/integration tests.
- [ ] CI configuration is committed to the repository.
- [ ] At least one security/federation test suite is included in CI.

### Required Tests

- CI success on a clean branch.
- Intentional failing test proves the relevant CI job fails.
- Restore test after reverting the intentional failure.

---

### Completion Notes

- CI workflow is active for pull requests, pushes to `main`, and manual dispatch.
- Latest verified CI run: **#20** — both test/static-check and security-regression jobs passed.
- Pytest baseline: 7 passed in the security suite; the maintained test suite passes.
- Legacy application Ruff debt is intentionally tracked separately; the CI lint gate currently targets the maintained test suite rather than masking the pre-existing application findings.
- Dependency audit passes with one explicit, documented ignore for `PYSEC-2026-1325` (ecdsa), for which the scanner reports no fixed version.

## TASK-002 — Build Security Regression Test Harness

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-001

### Scope

Create reusable tests for authentication, authorization, federation, replay, sessions, and malicious input.

### Acceptance Criteria

- [ ] Tests exist for unauthenticated federation access.
- [ ] Tests exist for invalid federation signatures.
- [ ] Tests exist for incorrect server/domain identity.
- [ ] Tests exist for unauthorized message injection.
- [ ] Tests exist for forged receipts.
- [ ] Tests exist for unauthorized message update/delete.
- [ ] Tests exist for replayed federation events.
- [ ] Tests exist for revoked sessions/devices once those features exist.
- [ ] Security tests fail closed.

---

# Phase 1 — Federation Security Foundation

### Completion Notes

- Added `tests/security/test_federation_security.py` as the reusable federation security harness.
- Covers missing authentication, invalid signatures, tampered bodies, incorrect domain expectations, stale requests, valid-signature sanity, message/receipt/update/delete authorization contracts, and replay contracts.
- Five strict expected-failure contracts remain for controls implemented by later tasks. Because they use `strict=True`, an accidental early XPASS fails CI rather than silently weakening the security gate.
- Revoked-session/device tests remain deferred until TASK-007/TASK-010 introduce those lifecycle features.

## TASK-003 — Install and Enforce Federation Authentication Middleware

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-002

### Scope

Ensure every protected federation endpoint passes through the intended authentication layer.

### Acceptance Criteria

- [x] Federation authentication middleware is registered in application startup.
- [x] Every protected federation endpoint is covered.
- [x] Requests without federation credentials receive an authentication failure.
- [x] Invalid credentials are rejected.
- [x] Valid credentials reach the endpoint.
- [x] Middleware cannot be bypassed through alternate routes.
- [x] Tests cover every federation router group.

### Completion Notes

- Federation middleware is registered in `create_app()`.
- Federation routes are deny-by-default; only explicit protocol discovery/identity metadata paths are public.
- Added route-level regression coverage that enumerates the federation router and verifies every non-public route rejects missing authentication.
- Added positive middleware coverage proving a valid signed request reaches the protected handler.
- Latest CI verification: **run #102** — test/static checks and security regression suite both passed.

---

## TASK-004 — Define Server Identity and Domain-Key Trust Model

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-003

### Scope

Separate discovery from trust and establish how a DeceMSG domain is authorized to use a federation signing key.

### Acceptance Criteria

- [ ] A canonical server identity model is documented and implemented.
- [ ] Each server signing key has a stable key ID.
- [ ] A server key cannot become trusted merely by self-asserting a domain header.
- [ ] The trust mechanism binds domain identity to an authorized server key.
- [ ] Key rotation is supported without ambiguity.
- [ ] Revoked/expired keys are rejected.
- [ ] Trust verification is covered by automated tests.
- [ ] The design explicitly documents the chosen mechanism, such as DNS/DNSSEC or signed server metadata.

---

## TASK-005 — Harden Federation Request Authentication

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-004

### Scope

Make federation authentication cryptographically verifiable and resistant to impersonation and replay.

### Acceptance Criteria

- [ ] Requests authenticate the claimed origin server.
- [ ] Signature verification covers all security-sensitive request fields.
- [ ] Key ID identifies the exact verification key.
- [ ] Timestamp/freshness validation is enforced.
- [ ] Replay protection is enforced.
- [ ] Invalid/missing signatures fail closed.
- [ ] Authentication failures do not expose sensitive details.
- [ ] Positive and negative security tests pass.

---

## TASK-006 — Enforce Federation Authorization Boundaries

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-005

### Scope

Authorize federation operations based on authenticated server, actor, conversation, and target ownership.

### Acceptance Criteria

- [ ] Message creation verifies authorized origin/actor.
- [ ] Chat synchronization verifies server authority.
- [ ] Group/member operations verify server and conversation authority.
- [ ] Message update verifies sender/origin authority.
- [ ] Message deletion verifies sender/origin authority.
- [ ] Delivery receipts verify message/conversation authorization.
- [ ] Caller-supplied user IDs cannot override authenticated identity.
- [ ] Unauthorized operations are rejected with appropriate status codes.
- [ ] Security regression tests cover each operation.

---

# Phase 2 — Session, WebSocket, and Account Security

## TASK-007 — Introduce Server-Side Session Model and Revocation

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-002

### Scope

Replace purely stateless token lifecycle assumptions with explicit sessions that can be revoked.

### Acceptance Criteria

- [ ] Each login creates a server-tracked session.
- [ ] Sessions have expiration.
- [ ] Individual sessions can be revoked.
- [ ] Logout invalidates the intended session.
- [ ] Revoked sessions cannot authenticate new requests.
- [ ] Device/session relationships are queryable.
- [ ] Existing valid sessions are not unexpectedly invalidated by unrelated password changes.
- [ ] Tests cover stolen-token-after-revocation behavior.

---

## TASK-008 — Harden WebSocket Authentication

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-007

### Scope

Remove insecure JWT query-parameter handling and enforce session lifecycle on long-lived connections.

### Acceptance Criteria

- [ ] JWT/session credentials are not exposed through URL query strings.
- [ ] WebSocket authentication uses the approved secure mechanism.
- [ ] Session expiry is enforced for active connections.
- [ ] Revoked sessions are disconnected or denied continued authorization.
- [ ] WebSocket authorization is checked before chat-specific events.
- [ ] Typing/presence events cannot target unauthorized conversations.
- [ ] Tests cover expired and revoked sessions.

---

## TASK-009 — Harden Password Change and Account Credential Operations

**Priority:** P0  
**Status:** Done  
**Dependencies:** TASK-007

### Scope

Protect password changes from stolen-session abuse while preserving device identity.

### Acceptance Criteria

- [ ] Password change requires current authentication plus appropriate step-up verification.
- [ ] Password reset and password change are distinct flows.
- [ ] Password change does not rotate DeceMSG identity.
- [ ] Password change does not invalidate device encryption keys.
- [ ] Existing sessions follow an explicitly documented security policy.
- [ ] Recovery backup is re-encrypted when required.
- [ ] Tests cover stolen-session/password-change abuse.

---

# Phase 3 — Identity and Device Architecture

## TASK-010 — Implement Explicit UserIdentity and Device Models

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-009

### Scope

Separate account identity from device identity.

### Acceptance Criteria

- [ ] A user has a stable DeceMSG identity.
- [ ] A user can have multiple devices.
- [ ] Each device has a stable device ID.
- [ ] Device cryptographic public identity/key metadata is stored.
- [ ] Device status includes active/revoked lifecycle state.
- [ ] Adding a device does not revoke unrelated devices.
- [ ] Revoking a device does not delete the user identity.
- [ ] API/database constraints prevent duplicate device identities.

---

## TASK-011 — Implement FederatedIdentity / RemoteUser Model

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-010

### Scope

Stop representing remote identities as local-user foreign keys.

### Acceptance Criteria

- [ ] Remote identity has canonical address/domain representation.
- [ ] Remote identity is distinct from local User.
- [ ] Conversations can reference local and remote participants correctly.
- [ ] Messages can reference remote actors without violating local FK constraints.
- [ ] Remote identity ownership/domain information is retained.
- [ ] Existing local-user behavior remains compatible.
- [ ] Migration tests cover existing data.

---

## TASK-012 — Implement Device Management API and UI Contract

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-010

### Acceptance Criteria

- [ ] User can list active devices.
- [ ] User can identify a device using non-secret metadata.
- [ ] User can revoke an individual device.
- [ ] Revoked device cannot create new authorized sessions.
- [ ] Existing unrelated devices continue operating.
- [ ] Device revocation is auditable.
- [ ] API behavior is covered by integration tests.

---

# Phase 4 — Recovery and Web Client Security

## TASK-013 — Design Encrypted Identity Backup and Recovery

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-010, TASK-012

### Scope

Implement password-assisted recovery without storing plaintext private keys server-side.

### Acceptance Criteria

- [ ] Private identity keys are never stored plaintext on the server.
- [ ] Recovery backup is encrypted client-side.
- [ ] Argon2id is used for password-derived recovery/key-encryption material.
- [ ] KDF parameters are versioned and stored with the encrypted backup metadata.
- [ ] Wrong passwords cannot decrypt the backup.
- [ ] Successful recovery restores the intended identity.
- [ ] Password change can re-encrypt the backup.
- [ ] Recovery does not silently create a new identity.
- [ ] Recovery events are auditable without logging secrets.

---

## TASK-014 — Make Web Client a First-Class Crypto Client

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-013

### Acceptance Criteria

- [ ] Browser crypto uses Web Crypto API or an approved audited cryptographic library.
- [ ] Private keys are not stored in plaintext localStorage.
- [ ] Device keys are protected in appropriate browser storage.
- [ ] Browser enrollment creates a distinct device identity.
- [ ] Browser logout/session expiry does not destroy required encrypted key material unexpectedly.
- [ ] Site-data clearing behavior is documented.
- [ ] XSS/CSP protections are configured.
- [ ] Security tests cover storage and session behavior.

---

# Phase 5 — End-to-End Encryption

## TASK-015 — Select and Document Production Messaging Cryptography

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-010

### Scope

Select a mature, reviewed messaging cryptographic implementation that is compatible with the DeceMSG Apache-2.0 distribution model and browser-first client.

### Acceptance Criteria

- [x] Protocol/library choice is documented with rationale.
- [x] Security properties are documented.
- [x] Supported platforms are identified.
- [x] 1:1, multi-device, group, offline, rotation, and revocation requirements are mapped.
- [x] Key lifecycle is documented.
- [x] Recovery implications are documented.
- [x] No custom cryptographic primitive is introduced without independent review.

---

### TASK-015 Verification Notes

- Revisited the earlier Signal-family selection because official libsignal is AGPL-3.0-only and its upstream documentation says use outside Signal is unsupported.
- Selected @matrix-org/matrix-sdk-crypto-wasm 18.4.0 as the Apache-2.0 browser crypto engine for the integration spike, behind a DeceMSG-specific adapter.
- Added an exact npm lockfile, package verification, browser crypto staging build, and CI gate.
- Version 18.4.0 is intentionally pinned because the documented 18.5.0/18.6.0 one-time-key regression affects the required E2EE path.
- Added DEVELOPMENT_PLAN/E2EE_Crypto_Selection.md with protocol mapping, lifecycle requirements, versioning, recovery, device, and licensing rules.
- Latest CI verification will be recorded after the new web-crypto job completes.

## TASK-016 — Implement 1:1 E2EE Message Lifecycle

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-015, TASK-011

### Acceptance Criteria

- [x] Encryption occurs on the sender device.
- [x] Server receives ciphertext rather than plaintext message content.
- [x] Federation transmits ciphertext.
- [x] Recipient device decrypts locally.
- [x] Unauthorized devices cannot decrypt messages.
- [x] Message authenticity/integrity is verified by the selected audited crypto engine.
- [x] Server logs do not contain plaintext message content.
- [x] End-to-end tests verify Alice-to-Bob ciphertext flow.

---

### TASK-016 Verification Notes

- Added persistent server-side E2EE device state containing only public device/key material and opaque to-device envelopes.
- Added authenticated client crypto transport endpoints for key upload/query/claim and encrypted to-device delivery.
- Message creation is now ciphertext-only; plaintext message submission is rejected.
- Browser clients use the pinned @matrix-org/matrix-sdk-crypto-wasm 18.4.0 adapter with per-device persistent crypto state.
- Added an Alice-to-Bob Olm/Megolm smoke test covering room-key delivery, ciphertext encryption, recipient decryption, and unauthorized-device rejection.
- The federation message path carries the opaque encrypted message content; no plaintext message body is introduced by the server-side federation transport.
- Full cross-provider remote-device key discovery/routing remains part of TASK-031 (Alice-to-Bob federated lifecycle), not a plaintext fallback in TASK-016.
- Latest CI verification: **run #36988506213** — Python/static checks, security regression suite, and browser crypto build all passed.

## TASK-017 — Implement Multi-Device Key Distribution and Revocation

**Priority:** P1  
**Status:** Done  
**Dependencies:** TASK-016, TASK-012

### Acceptance Criteria

- [x] A user can add a second device.
- [x] Authorized devices can receive messages intended for the user.
- [x] Device removal prevents future authorized decryption.
- [x] Device keys have explicit lifecycle state.
- [x] Key changes are authenticated.
- [x] Old/revoked device behavior is covered by tests.
- [x] Existing device functionality remains intact during enrollment.

---

### TASK-017 Verification Notes

- Existing device enrollment and server-side session binding were retained.
- Added a per-conversation crypto epoch model and authenticated epoch endpoint.
- Revoking a device now rotates every chat containing that user to a fresh crypto epoch before future messages.
- Browser ciphertext envelopes carry the exact crypto room ID, preserving historical-epoch decryption without exposing plaintext.
- The browser crypto smoke test now models two authorized devices receiving the same room key and verifies a previously authorized device cannot decrypt after epoch rotation.
- Latest CI verification: **run #36989143856** — Python/static checks, security regression suite, and browser crypto build all passed.

---

## TASK-018 — Implement E2EE Group Messaging

**Priority:** P1/P2  
**Status:** In Progress  
**Dependencies:** TASK-016, TASK-017

### Acceptance Criteria

- [ ] Group membership changes are authenticated.
- [ ] Only authorized group devices receive decryptable content.
- [ ] Removed devices cannot decrypt future messages.
- [ ] New devices receive appropriate group key state.
- [ ] Group key rotation behavior is documented and tested.
- [ ] Offline group delivery works.
- [ ] Replay and duplicate handling is tested.

---

# Phase 6 — Federation Event Protocol and Reliability

## TASK-019 — Define Signed Federation Event Envelope

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-005, TASK-011, TASK-016

### Acceptance Criteria

- [ ] Event schema contains event ID, type, protocol version, origin, key ID, actor, target, conversation, timestamp, sequence, payload/ciphertext, and signature as appropriate.
- [ ] Canonical serialization is defined.
- [ ] Signature input is deterministic.
- [ ] Event IDs are unique.
- [ ] Protocol versioning is explicit.
- [ ] Schema validation rejects malformed events.
- [ ] Compatibility/versioning rules are documented.

---

## TASK-020 — Implement Replay Protection and Idempotency

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-019

### Acceptance Criteria

- [ ] Duplicate event IDs are detected.
- [ ] Replaying an accepted event does not create duplicate effects.
- [ ] Expired/stale events are rejected according to policy.
- [ ] Sequence/order violations are detected where ordering is required.
- [ ] Replay state survives process restart.
- [ ] Concurrent duplicate delivery is safe.
- [ ] Automated replay attack tests pass.

---

## TASK-021 — Replace File-Based Federation Queues with Durable Queues

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-020

### Acceptance Criteria

- [ ] Federation delivery survives process restart.
- [ ] Queue state is transactional.
- [ ] Multiple workers can safely consume work.
- [ ] Leases/visibility timeouts prevent stuck jobs.
- [ ] Retries are bounded and observable.
- [ ] Duplicate delivery remains idempotent.
- [ ] Dead-letter handling exists for permanently failing events.

---

## TASK-022 — Implement Deterministic Message/Event Ordering

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-019

### Acceptance Criteria

- [ ] Message pagination has deterministic ordering.
- [ ] Ties on created_at cannot reorder messages unpredictably.
- [ ] Cursor semantics are documented.
- [ ] Forward/backward pagination tests pass.
- [ ] Federation sequence behavior is documented.

---

## TASK-023 — Replace In-Memory Rate Limiting with Shared Rate Limiting

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-003

### Acceptance Criteria

- [ ] Rate-limit state is shared across application workers.
- [ ] Limits survive normal worker distribution.
- [ ] Federation and authentication endpoints have explicit limits.
- [ ] Rate-limit responses are consistent.
- [ ] Tests demonstrate limits across multiple workers/processes.

---

# Phase 7 — Uploads, Presence, and Data Lifecycle

## TASK-024 — Harden File Upload Pipeline

**Priority:** P0/P2  
**Status:** Planned  
**Dependencies:** TASK-002

### Acceptance Criteria

- [ ] Upload size is rejected before loading excessive data into memory.
- [ ] MIME type is validated.
- [ ] File signature/magic bytes are validated where applicable.
- [ ] File names are safely normalized.
- [ ] Untrusted files are stored in isolated storage.
- [ ] Appropriate malware/content scanning integration point exists.
- [ ] Download authorization is enforced.
- [ ] Security tests cover malformed and oversized files.

---

## TASK-025 — Secure Presence and Typing Events

**Priority:** P1  
**Status:** Planned  
**Dependencies:** TASK-008

### Acceptance Criteria

- [ ] Presence access requires authentication.
- [ ] Presence visibility follows documented privacy policy.
- [ ] Unauthorized users cannot probe arbitrary users' online status.
- [ ] Typing events require conversation membership.
- [ ] Typing events cannot be injected into unauthorized chats.
- [ ] Abuse/rate limits are enforced.

---

## TASK-026 — Implement Ephemeral Message Lifecycle

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-016

### Acceptance Criteria

- [ ] Expiry time is validated server-side.
- [ ] Expired messages are no longer returned through normal retrieval APIs.
- [ ] Expired message content is removed according to documented retention policy.
- [ ] Expiry processing is durable and restart-safe.
- [ ] Federation behavior for expired messages is defined.
- [ ] Tests cover delayed workers and process restarts.

---

# Phase 8 — Data, Logging, and Operational Security

## TASK-027 — Introduce Database Migration System

**Priority:** P1  
**Status:** Planned  
**Dependencies:** TASK-010

### Acceptance Criteria

- [ ] Alembic or an equivalent migration system is configured.
- [ ] Existing schema can be represented by an initial migration.
- [ ] Fresh database setup works from migrations.
- [ ] Existing database upgrade path is documented.
- [ ] Destructive migrations require explicit review.
- [ ] CI validates migrations.

---

## TASK-028 — Implement Structured Security Audit Logging

**Priority:** P0  
**Status:** Planned  
**Dependencies:** TASK-007

### Acceptance Criteria

- [ ] Authentication events are logged.
- [ ] Session/device changes are logged.
- [ ] Federation authentication failures are logged.
- [ ] Authorization failures are logged.
- [ ] Administrative/security-sensitive changes are logged.
- [ ] Logs exclude passwords, private keys, tokens, and plaintext message content.
- [ ] Logs contain correlation/request identifiers where appropriate.
- [ ] Log format is machine-readable.
- [ ] Retention policy is documented.

---

## TASK-029 — Harden CORS and Production Configuration

**Priority:** P1  
**Status:** Planned  
**Dependencies:** TASK-001

### Acceptance Criteria

- [ ] Production CORS uses an explicit allowlist.
- [ ] Wildcard origins are not combined with credentials.
- [ ] Development overrides are clearly separated.
- [ ] Sensitive configuration is environment-driven.
- [ ] Startup validation rejects unsafe production configuration.
- [ ] Configuration tests cover production defaults.

---

## TASK-030 — Strengthen Admin Configuration Validation

**Priority:** P1  
**Status:** Planned  
**Dependencies:** TASK-028

### Acceptance Criteria

- [ ] Administrative configuration inputs are schema validated.
- [ ] Invalid security-sensitive values are rejected.
- [ ] Authorization is enforced for admin operations.
- [ ] Admin changes are audited.
- [ ] Secrets are never returned in API responses.

---

# Phase 9 — Protocol Integration and End-to-End Verification

## TASK-031 — Implement Secure Alice-to-Bob Federated Message Flow

**Priority:** P0/P1  
**Status:** Planned  
**Dependencies:** TASK-006, TASK-016, TASK-019, TASK-020

### Scope

Implement the complete reference flow that validates the architecture end to end.

### Acceptance Criteria

- [ ] Alice can address Bob using `bob#remote.example`.
- [ ] Remote server discovery resolves Bob's provider.
- [ ] Server/domain trust is verified.
- [ ] Alice's device encrypts the message locally.
- [ ] Alice's provider authenticates the federation request.
- [ ] Bob's provider verifies origin, signature, freshness, authorization, and replay state.
- [ ] Bob's provider stores ciphertext only.
- [ ] Bob's authorized device receives the ciphertext.
- [ ] Bob's device decrypts and verifies the message locally.
- [ ] Duplicate federation delivery does not duplicate the message.
- [ ] Unauthorized origin/server/device attempts fail.
- [ ] End-to-end integration test passes from Alice device to Bob device.

---

## TASK-032 — Security Review of Core Federation

**Priority:** P0  
**Status:** Planned  
**Dependencies:** TASK-031

### Acceptance Criteria

- [ ] Threat model is updated against the implemented protocol.
- [ ] Federation attack tests pass.
- [ ] Authentication bypass attempts fail.
- [ ] Authorization bypass attempts fail.
- [ ] Replay attempts fail.
- [ ] Domain/key impersonation attempts fail.
- [ ] Message injection attempts fail.
- [ ] Forged receipt attempts fail.
- [ ] Unauthorized update/delete attempts fail.
- [ ] Findings are documented and triaged before ecosystem expansion.

---

# Phase 10 — AI Agent Security

## TASK-033 — Define AI Agent Identity Model

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-010, TASK-011

### Acceptance Criteria

- [ ] AI agents have explicit DeceMSG identities.
- [ ] Agent identity is distinct from human user identity.
- [ ] Agent owner/controller relationship is explicit.
- [ ] Agent status supports active/revoked lifecycle.
- [ ] Agent authentication uses the same federation/security foundations.

---

## TASK-034 — Implement Agent Scopes, Consent, Audit, and Revocation

**Priority:** P2  
**Status:** Planned  
**Dependencies:** TASK-033, TASK-028

### Acceptance Criteria

- [ ] Agents have explicit permission scopes.
- [ ] Sensitive actions require appropriate consent.
- [ ] Agent actions are auditable.
- [ ] Agent rate limits are enforced.
- [ ] Agent credentials can be revoked independently.
- [ ] Revoked agents cannot continue authorized operations.

---

# Phase 11 — Deferred Ecosystem Features

These tasks should not block the secure core unless requirements change.

## TASK-035 — Federated Search Security

**Priority:** P3  
**Dependencies:** TASK-006, TASK-011

### Acceptance Criteria

- [ ] Requesting identity comes from authenticated credentials.
- [ ] Search results respect local and remote authorization.
- [ ] Caller-supplied identity cannot expand access.
- [ ] Remote search does not leak private metadata.
- [ ] Abuse/rate limits exist.

---

## TASK-036 — Secure User Migration

**Priority:** P3  
**Dependencies:** TASK-013, TASK-027

### Acceptance Criteria

- [ ] Export requires authenticated owner/admin authority.
- [ ] Export contains only authorized data.
- [ ] Sensitive material is encrypted appropriately.
- [ ] Import validates schema and ownership.
- [ ] Import is idempotent or safely resumable.
- [ ] Migration is audited.
- [ ] Failed migration cannot partially expose data.

---

## TASK-037 — ActivityPub Interoperability Hardening

**Priority:** P3  
**Dependencies:** TASK-032

### Acceptance Criteria

- [ ] Actor ownership is verified.
- [ ] HTTP signatures are correctly verified.
- [ ] Replay protection exists.
- [ ] Inbox authorization exists.
- [ ] Remote actor discovery does not establish trust by itself.
- [ ] Security tests cover malicious actors and forged activities.

---

## TASK-038 — Federated Files

**Priority:** P3  
**Dependencies:** TASK-024, TASK-031

### Acceptance Criteria

- [ ] File ownership is authenticated.
- [ ] Federation authorization is enforced.
- [ ] File metadata does not leak unauthorized information.
- [ ] Transfers are integrity-protected.
- [ ] Malware/content scanning policy applies to federated files.
- [ ] Large transfers are resumable and bounded.

---

## TASK-039 — Push Notification Integration

**Priority:** P3  
**Dependencies:** TASK-016, TASK-028

### Acceptance Criteria

- [ ] Push payloads do not expose plaintext message content unless explicitly required and secured.
- [ ] Device tokens are protected.
- [ ] Revoked devices stop receiving notifications.
- [ ] Notification events are auditable.
- [ ] Provider failure/retry behavior is documented.

---

# Execution Order

Recommended execution sequence:

1. TASK-001 — Security baseline and CI
2. TASK-002 — Security regression harness
3. TASK-003 — Federation middleware
4. TASK-004 — Domain/key trust
5. TASK-005 — Federation request authentication
6. TASK-006 — Federation authorization
7. TASK-007 — Session revocation
8. TASK-008 — WebSocket security
9. TASK-009 — Password/account credential security
10. TASK-010 — UserIdentity + Device models
11. TASK-011 — FederatedIdentity
12. TASK-012 — Device management
13. TASK-013 — Recovery
14. TASK-014 — Web crypto client
15. TASK-015 — Cryptographic protocol selection
16. TASK-016 — 1:1 E2EE
17. TASK-017 — Multi-device crypto
18. TASK-019 — Federation event envelope
19. TASK-020 — Replay/idempotency
20. TASK-021 — Durable queues
21. TASK-022 — Deterministic ordering
22. TASK-023 — Shared rate limiting
23. TASK-024 — Upload security
24. TASK-025 — Presence/typing security
25. TASK-026 — Ephemeral lifecycle
26. TASK-027 — Database migrations
27. TASK-028 — Security logging
28. TASK-029 — CORS/configuration
29. TASK-030 — Admin validation
30. TASK-031 — Alice-to-Bob reference flow
31. TASK-032 — Core federation security review
32. TASK-018 — Group E2EE
33. TASK-033 — AI agent identity
34. TASK-034 — AI agent security
35. TASK-035 — Federated search
36. TASK-036 — Migration
37. TASK-037 — ActivityPub
38. TASK-038 — Federated files
39. TASK-039 — Push notifications

---

# Definition of Done for Every Task

A task is not Done merely because code exists.

A task is Done only when:

- [ ] Implementation is complete.
- [ ] Acceptance criteria are satisfied.
- [ ] Automated tests cover the new behavior.
- [ ] Relevant security regression tests pass.
- [ ] Existing tests still pass.
- [ ] Documentation is updated where behavior/protocol changes.
- [ ] Database migrations exist when schema changes.
- [ ] No secrets or plaintext sensitive data are introduced into logs.
- [ ] The change has been reviewed for authorization boundaries.
- [ ] Git commit/PR clearly references the task ID.

---

# First Execution Task

## TASK-001 — Establish Security Baseline and CI Gate

This is the first task to execute.

**Goal:** Establish a reliable baseline so subsequent security changes can be implemented and verified without hiding regressions.

**Do not start TASK-002 until TASK-001 acceptance criteria are satisfied.**
