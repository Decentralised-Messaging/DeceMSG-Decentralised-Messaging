# DeceMSG Production Messaging Cryptography

**Status:** Selected for implementation  
**Task:** TASK-015  
**Scope:** 1:1 messaging, multi-device messaging, groups, offline delivery, rotation, revocation, and recovery

## Decision

DeceMSG will use the **Signal Protocol family** through a maintained, reviewed implementation rather than implementing a new messaging cryptosystem.

The protocol layer is an implementation dependency, not an application-defined cryptographic primitive. The exact maintained libsignal release and supported language bindings must be pinned during TASK-016 after compatibility, licensing, platform, and maintenance review.

DeceMSG will not invent its own:
- key agreement primitive;
- ratchet;
- authenticated-encryption construction;
- group key schedule;
- signature format;
- forward-secrecy mechanism.

## Required security properties

The implementation must provide, as applicable:

- end-to-end confidentiality;
- sender/message authenticity;
- integrity and tamper detection;
- forward secrecy;
- post-compromise recovery;
- replay/duplicate resistance;
- asynchronous/offline delivery;
- explicit device key lifecycle;
- device revocation;
- group membership key rotation;
- recovery without server access to plaintext private identity keys.

The federation layer transports ciphertext and protocol metadata. It is not a trusted plaintext relay.

## Identity and device mapping

A DeceMSG account has one stable user identity and zero or more devices.

Each device has:
- a stable device ID;
- a device identity/public key;
- an explicit active/revoked lifecycle;
- authenticated enrollment;
- a separate session binding.

A password is an authentication/recovery input. It is not itself the messaging encryption key.

## 1:1 mapping

The 1:1 lifecycle maps to the Signal Protocol family:

1. Device publishes the required pre-key material.
2. Sender resolves the recipient's authenticated device/key bundle.
3. Sender establishes or resumes a cryptographic session locally.
4. Sender encrypts and authenticates the message locally.
5. The server stores ciphertext and protocol metadata.
6. Federation transports ciphertext.
7. Recipient device verifies and decrypts locally.
8. Ratchet state advances independently on each device.

Servers must never require plaintext message content to perform delivery.

## Multi-device mapping

Multi-device state follows a Sesame-style device/session model:

- each device has independent cryptographic state;
- adding a device does not invalidate existing devices;
- new device enrollment is authenticated;
- messages are encrypted for the recipient's currently authorized devices according to the selected protocol implementation;
- revoking a device prevents future authorized decryption and terminates its server sessions;
- device-key changes are authenticated and auditable.

The exact pre-key distribution and session fan-out are delegated to the selected maintained Signal implementation.

## Group mapping

Group messaging will use the group mechanisms supported by the selected maintained Signal implementation.

Required application behavior:

- membership changes are authenticated;
- adding a member establishes the correct future key state;
- removing a member rotates the relevant group key state;
- removed devices cannot decrypt future messages;
- offline members receive only the key state they are authorized to receive;
- duplicate/replayed group events are idempotent;
- group membership changes are represented as authenticated protocol events.

TASK-018 must complete the detailed group-key lifecycle and interoperability tests before group federation is considered production-ready.

## Offline delivery

The server may queue ciphertext while recipients are offline.

Offline queues must not contain:
- plaintext message bodies;
- plaintext identity private keys;
- reusable long-term symmetric message keys.

Delivery retries must be idempotent at the federation event layer.

## Key rotation and revocation

The application must distinguish:

- account identity rotation;
- device identity rotation;
- session revocation;
- messaging-session/ratchet rotation;
- group membership rotation.

Password changes must not silently create a new DeceMSG identity or destroy device cryptographic state.

Device revocation must stop future authorized decryption for that device and terminate its server-side sessions.

## Recovery

Identity recovery is client-side.

The recovery design uses:
- Argon2id-derived key-encryption material;
- a versioned KDF parameter set;
- authenticated encryption;
- an opaque encrypted backup stored by the server.

The server stores ciphertext only. It must never receive plaintext private identity keys.

Recovery and password-change re-encryption are addressed by TASK-013 and TASK-014.

## Federation implications

Federation events carry ciphertext plus authenticated protocol metadata.

A remote server is trusted to transport/store an event according to the federation trust model, but it is not trusted with plaintext.

The federation event envelope must bind:
- event ID;
- protocol version;
- origin server;
- origin key ID;
- actor/device identity;
- target/conversation;
- timestamp/sequence;
- ciphertext;
- signature.

This envelope is implemented by TASK-019.

## Implementation constraints

1. Pin the exact maintained cryptographic implementation before production release.
2. Do not copy cryptographic algorithms into application code.
3. Do not modify the selected protocol implementation locally.
4. Keep cryptographic state out of ordinary application logs.
5. Treat private keys and ratchet state as secret material.
6. Add interoperability and negative cryptographic tests before enabling federation E2EE.
7. Document platform/library support and upgrade policy with each dependency update.

## Acceptance mapping

| Requirement | Decision |
|---|---|
| Protocol choice | Signal Protocol family |
| 1:1 | Signal-style asynchronous sessions and ratchets |
| Multi-device | Sesame-style device/session model |
| Groups | Maintained Signal group mechanisms; detailed lifecycle in TASK-018 |
| Offline | Ciphertext-only server queues |
| Rotation | Explicit device/session/ratchet/group lifecycle |
| Revocation | Device revocation + protocol key-state update |
| Recovery | Client-side encrypted identity backup with Argon2id |
| Custom cryptography | Prohibited |
| Federation plaintext | Prohibited |
