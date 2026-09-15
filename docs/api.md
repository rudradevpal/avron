# API reference

Three surfaces: the transparent proxy, the masking API, and the console API.

## Authentication

Clients authenticate with an Avron key, created under **API keys** in the
console:

```
Authorization: Bearer avron-…
```

`X-API-Key` works too. The key is consumed by Avron and never forwarded — the
provider credential stored on the endpoint replaces it.

Enforcement is off by default. While off, requests without a key are accepted
and any `Authorization` header is passed through to the provider unless the
endpoint has its own stored key. Turn on **Require a key** once your clients are
issued keys.

## Proxy

Anything under a configured endpoint prefix is forwarded verbatim — method,
path, query, body, headers.

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer avron-YOUR-KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"..."}]}'
```

| Covered | Behaviour |
|---|---|
| `/chat/completions` | Masked in, restored out |
| Streaming | Placeholders reassembled across chunk boundaries |
| Tool calling | `tool_calls.arguments` masked and restored |
| `/responses`, `/embeddings`, legacy `/completions` | Input masked |
| Everything else | Byte-for-byte passthrough |

Responses carry `X-Upstream` naming the provider that served them, and JSON
bodies gain `x_pii_masked` with the count of distinct values masked.

If a provider key is stored on the endpoint it replaces the client's
`Authorization` header, so clients can send any placeholder token.

## Masking API

Requires an Avron key when enforcement is on; open otherwise. Do not expose
these ports beyond your network either way.

### `POST /analyze`

```json
{"text": "...", "entities": ["IN_PAN"], "use_llm": false}
```

Returns `count` and a list of `{entity_type, start, end, score, text}`.

### `POST /anonymize`

```json
{
  "text": "...",
  "strategy": "replace",
  "per_entity": {"IN_AADHAAR": "hash", "IN_PHONE_NUMBER": "mask"}
}
```

| Strategy | Result |
|---|---|
| `replace` | `<IN_PAN>` — readable, unrecoverable, collapses all instances |
| `mask` | `**********` — keeps length |
| `hash` | SHA-256 — stable pseudonym for joins |
| `encrypt` | Reversible via `/deanonymize` |
| `redact` | Removed entirely |

Returns `anonymized_text` and `items`. **Item offsets index the output string,
not your input** — they shift as replacements change length.

Plain SHA-256 on a short numeric identifier is weak: a 12-digit space with a
known checksum is roughly 10¹¹ candidates, which a GPU exhausts quickly. Treat
those digests as identifying data.

### `POST /deanonymize`

Takes `text` and the `items` array from an `encrypt` run.

### `GET /health`

Engine version, enabled entities, threshold, detection model state, endpoints.
No authentication; useful for liveness probes.

## Console API

Everything under `/api` requires a session cookie from `POST /api/login`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/login`, `/api/logout` | Session |
| GET | `/api/me` | Current user and role |
| GET/POST/PUT/DELETE | `/api/keys` | Client API keys. Members see only their own. |
| GET/PUT | `/api/settings` | Global settings; secrets are write-only |
| GET/PUT | `/api/entities` | Per-entity toggles and replacement style |
| POST | `/api/surrogate/preview` | What a shape would produce, before saving |
| POST | `/api/surrogate/infer` | Read a shape off an example |
| GET/POST/PUT/DELETE | `/api/patterns` | Pattern CRUD |
| POST | `/api/patterns/test` | Live regex tester |
| POST | `/api/patterns/generate` | AI draft |
| GET/PUT | `/api/packs` | Region packs |
| GET/POST/PUT/DELETE | `/api/routes` | Endpoints |
| GET | `/api/routes/{id}/health` | Live provider health |
| GET | `/api/routes/{id}/models` | Merged model catalogue |
| GET | `/api/providers` | Presets |
| POST | `/api/upstreams/test` | Connection test |
| POST | `/api/playground` | Run a prompt, see every stage |
| GET | `/api/analytics` | p50/p95 and tokens per provider |
| GET | `/api/stats`, `/api/audit` | Counters and change log |
| GET/DELETE | `/api/captures` | Recorded requests; detail at `/api/captures/{id}` decrypts one |
| GET/POST/DELETE | `/api/users` | Accounts and roles. Administrators only. |
| GET | `/api/tls` | Certificate status and renewal state |
| POST | `/api/tls/upload`, `/api/tls/letsencrypt`, `/api/tls/self-signed` | Install a certificate |
| POST | `/api/tls/enable`, `/api/tls/renew` | Switch HTTPS, force a renewal |
| POST | `/api/test/detect`, `/api/test/llm`, `/api/test/proxy` | Diagnostics |
