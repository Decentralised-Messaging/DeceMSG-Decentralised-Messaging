# DeceMSG Signed Federation Event Envelope

Protocol version: 1

## Canonical fields

A message event contains:

- event_id
- event_type
- protocol_version
- origin_server
- origin_key_id
- actor_identity
- target_identity
- conversation_id
- created_at
- sequence
- message_type
- ciphertext
- signature

## Canonical serialization

The signature input is the UTF-8 JSON representation of the event with:

- signature removed or set to null
- lexicographically sorted object keys
- compact separators
- UTF-8 characters preserved without ASCII escaping

The signature is an ECDSA P-256 SHA-256 signature encoded as the existing DeceMSG server signature format: 64 raw bytes containing fixed-width r and s values, then Base64.

## Verification

Transport authentication and event authentication are separate:

1. Federation HTTP authentication proves possession of a trusted server key for the request.
2. The event envelope proves the origin server signed the exact event payload.
3. The receiver checks origin server, key ID, actor identity, target identity, protocol version, ciphertext presence, and signature before storing the event.

Replay and durable idempotency are intentionally handled by TASK-020 rather than duplicated in this envelope task.

## Message handling rule

Federated message ingress requires the signed event envelope. The server stores the ciphertext field from the verified event and never reconstructs or logs plaintext message content.

## Compatibility

Future protocol versions must preserve the canonical-signature rule or negotiate an explicit versioned serialization before accepting an event.
