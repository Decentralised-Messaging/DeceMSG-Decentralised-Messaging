# Shared Rate Limiting

DeceMSG uses SlowAPI with the `limits` storage backend. The configured storage URI must be shared by all application workers so that each worker consumes the same counter.

## Configuration

```yaml
rate_limit:
  enabled: true
  login_rate: "5/minute"
  api_rate: "100/minute"
  auth_rate: "30/minute"
  federation_rate: "600/minute"
  burst_size: 10
  storage_uri: "redis://localhost:6379/1"
```

Login and registration retain their stricter `login_rate` limits. A shared middleware also applies `auth_rate` to all `/api/auth/*` routes and `federation_rate` to all `/federation/*` routes, including discovery and invalid-signature traffic, keyed by source IP. The per-family counters are shared through Redis. When Redis is unavailable, these sensitive route families fail closed with HTTP 503 instead of bypassing the limit.

429 responses use one JSON shape with `detail` and `retry_after`, plus `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers.

The shared middleware checks these route families before their handlers run, so federation requests are counted even when the server-signature headers are missing or invalid. Login and registration retain their stricter `login_rate` decorators.

Every 429 response uses the same JSON fields (`detail`, `retry_after`) and the `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers. If shared Redis storage is unavailable, sensitive auth/federation routes fail closed with HTTP 503 rather than silently falling back to process-local counters.

Use the same `redis://` or `rediss://` endpoint and database in every worker. Keep Redis private to the application network, require authentication/ACLs in deployments, and use TLS (`rediss://`) when Redis traffic crosses an untrusted network. Redis counters use the `limits` library's atomic Redis operations.

`memory://` is supported only for isolated local development/tests. It is process-local and must not be used for a multi-worker or production deployment.

To run the cross-worker-storage integration test locally, start a Redis server and set `DECEMSG_TEST_REDIS_URL`, for example `redis://localhost:6379/15`, before running `pytest -q tests/test_rate_limiter.py`.

CI starts a temporary Redis service and runs the integration test using two independent limiter instances. This verifies the persistence backend rather than only asserting a configuration string.
