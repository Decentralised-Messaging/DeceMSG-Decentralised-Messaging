# DeceMSG Production E2EE Crypto Selection

Decision date: 2026-10-02
Status: Selected for integration spike
Project license: Apache-2.0

## Decision

DeceMSG will use Olm/Megolm through the Apache-2.0 @matrix-org/matrix-sdk-crypto-wasm implementation as the browser E2EE crypto engine, behind a DeceMSG-specific adapter.

This does not make DeceMSG a Matrix server or change the DeceMSG federation protocol. The Matrix crypto state machine is an implementation dependency used by DeceMSG clients.

## Why this replaces the earlier Signal-family selection

The earlier TASK-015 selection identified the Signal Protocol family, but the maintained official libsignal repository is AGPL-3.0-only and states that use outside Signal is unsupported. DeceMSG is Apache-2.0, so adopting libsignal would require an explicit licensing/distribution decision before integration.

The selected Matrix crypto WASM package is Apache-2.0, browser-oriented, and exposes OlmMachine with IndexedDB-backed persistent storage. Version 18.4.0 is pinned intentionally for the integration spike because an August 2026 regression affected 18.5.0 and 18.6.0 one-time-key handling; the upstream issue documents 18.4.0 as the workaround.

## Security properties required from the crypto engine

- Sender-side encryption before server submission.
- Recipient-side decryption.
- Authenticated/integrity-protected encrypted events.
- Per-device cryptographic state.
- 1:1 sessions established through device/key distribution.
- Group/session key management for future group E2EE.
- Device rotation/revocation integration.
- Offline encrypted message processing.
- Persistent browser crypto state without plaintext private keys in localStorage.
- Explicit handling of verification/trust state.

## DeceMSG protocol mapping

The crypto engine is intentionally isolated behind DeceMSGCrypto.

DeceMSG owns:

- user#domain identities.
- DeceMSG UserIdentity and Device records.
- Conversation IDs and membership authorization.
- Federation authentication and server trust.
- Federation event envelopes and replay/idempotency.
- Delivery, receipts, and message metadata.
- Recovery policy and password-derived backup encryption.

The crypto engine owns:

- Device crypto state.
- Olm/Megolm sessions.
- Room/group session state.
- Encryption/decryption.
- Crypto signatures and verification primitives.
- Persistent crypto state in its supported store.

## Browser platform

The browser implementation uses:

1. WebAssembly via @matrix-org/matrix-sdk-crypto-wasm.
2. initAsync before crypto operations.
3. IndexedDB-backed OlmMachine storage using a per-device store name.
4. A DeceMSG adapter rather than importing the crypto package throughout application code.

The package browser entry point loads its WASM payload with fetch(). The build pipeline stages the exact locked package under web/dist/vendor/.

## Required DeceMSG integration work

The crypto engine is not yet considered integrated into messaging.

TASK-016 must still implement and test:

- DeceMSG conversation-to-crypto-room mapping.
- Device/key discovery and authenticated federation transport.
- Outgoing crypto request processing.
- 1:1 room-key sharing to authorized recipient devices.
- Ciphertext-only message persistence/federation.
- Local recipient decryption.
- Unauthorized-device negative tests.
- Replay/order handling around encrypted events.
- No plaintext message logging.
- Recovery and device-revocation behavior.

## Versioning policy

- Pin the crypto package exactly; do not use a floating range.
- Keep the lockfile committed.
- Review crypto dependency security advisories before upgrades.
- Upgrade only through a dedicated crypto dependency review and regression suite.
- Do not upgrade to a version known to have a regression in the required E2EE path.

## Licensing

The selected direct dependency is Apache-2.0. DeceMSG remains Apache-2.0.

Any future crypto dependency must undergo an explicit license compatibility review before being added to the production dependency graph.
