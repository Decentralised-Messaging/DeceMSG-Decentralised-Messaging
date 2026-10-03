# DeceMSG Message Pagination

## Ordering

Messages are ordered by the composite key `(created_at, id)` in ascending chronological order. The message ID is the deterministic tie-breaker when multiple messages share the same timestamp.

## Cursors

The `before` and `after` query parameters on `GET /api/chats/{chat_id}/messages` are opaque base64url-encoded cursors containing the timestamp and message ID.

- No cursor: returns the newest page in chronological display order.
- `before`: returns the page immediately before the cursor.
- `after`: returns the page immediately after the cursor.
- `before` and `after` cannot be supplied together.
- Responses expose `X-Message-Before` and `X-Message-After` headers for continuing pagination.

The cursor comparison is composite, so messages with identical timestamps cannot reorder between pages.

## Federation sequence

Federated event sequence values remain an origin/actor/conversation ordering signal. TASK-020 rejects positive sequence regressions while sequence zero remains accepted for legacy/unspecified ordering.
