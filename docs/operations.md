# Operations

## Backup

Everything is in one SQLite file plus one environment variable.

```bash
docker exec avron sqlite3 /data/gateway.db ".backup '/data/backup.db'"
cp /root/docker-storage/avron/data/backup.db /somewhere/safe/
```

Use `.backup`, not `cp` on the live file — WAL mode means a plain copy can catch
a partial transaction.

**Back up `MASTER_KEY` separately and somewhere else.** The database without it
is configuration with unusable API keys.

Restore is the reverse: stop the container, replace the file, ensure the same
`MASTER_KEY`, start.

## Upgrading

```bash
docker exec avron sqlite3 /data/gateway.db ".backup '/data/pre-upgrade.db'"
# replace avron/ with the new version
docker compose up -d --build avron
docker logs avron 2>&1 | tail -20
```

Migrations run at startup and are idempotent: columns are added if missing, new
packs and settings inserted, and corrections applied only to rows still carrying
their original value. A pattern you edited in the console is never overwritten.

## Monitoring

`GET /health` needs no auth and reports engine version, enabled entities,
threshold and endpoints. Use it as a liveness probe.

The **Analytics** screen shows p50, p95, slowest, request and failure counts and
token totals per provider, from the last 5,000 requests. p95 is the number your
users notice; an average hides the tail.

The **Endpoints** screen polls provider health every few seconds: in-flight,
successes, failures, average latency, cooldown remaining.

Log lines worth alerting on:

| Line | Meaning |
|---|---|
| `LLM pass failed` | Detection model unreachable; names are leaking |
| `Upstream N failed ... Sidelined` | A provider is in cooldown |
| `Every provider attempt failed` | The pool is exhausted; clients see 502 |
| `Recognizer registry reloaded` | Configuration changed |

`PII span extraction routed via X` records which provider handled a detection
pass. Provider only — never the text. That is your residency audit trail.

## Troubleshooting

**Container restart-loops with a Fernet error.** `MASTER_KEY` is missing or
malformed. It must be 44 characters of urlsafe base64.

**Console shows "Session expired" immediately.** `COOKIE_SECURE=true` while
serving over plain HTTP. The browser refuses to send the cookie back.

**Admin password lost.** Not recoverable — only the hash is stored. Clear the
users table and restart; patterns, endpoints and settings survive:

```bash
docker compose stop avron
docker run --rm -v /root/docker-storage/avron/data:/data alpine \
  sh -c "apk add -q sqlite && sqlite3 /data/gateway.db 'DELETE FROM users; DELETE FROM sessions;'"
docker compose start avron
docker logs avron 2>&1 | grep -A6 "first-run credentials"
```

**Every request returns 404.** No endpoint matches the path. Check the prefix in
**Endpoints**; `/v1/chat/completions` needs an endpoint at `/v1`.

**502 "Every provider attempt failed".** The `attempts` array in the response
names each provider and its error. Use the per-provider *Test* button.

**Bind mount became a directory.** Docker creates a missing bind-mount source as
an empty directory. If a config file was not present when the container first
started, remove the directory and recreate the file before starting again.

**Detection suddenly worse after enabling a pack.** Regional patterns collide.
See [detection.md](detection.md).

## Capacity

Roughly, per request: pattern matching is sub-millisecond; spaCy NER is tens of
milliseconds and scales with text length; the detection model is a full
round-trip and dominates everything else.

The container is single-process async. For real concurrency raise uvicorn
workers, but note that health and in-flight state are per process — with
multiple workers, load balancing becomes approximate.

The spaCy model holds ~600 MB resident. Budget 1.5 GB for the container.
