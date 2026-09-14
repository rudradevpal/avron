# Security

## What AVRON protects against

Personal data reaching a model provider in your application's prompts. That is
the whole scope. It is not a firewall, a DLP suite, or a compliance control.

## The unavoidable disclosure

**The detection model receives text before masking.** You cannot find personal
data in text you have already scrubbed. If that model is a hosted API, your
unmasked data is disclosed to that provider on every request — and free tiers
commonly reserve the right to train on submissions.

Three ways to handle it:

1. **Run it locally.** Point the detection model at Ollama, vLLM or LM Studio.
   Nothing leaves the machine. Best answer for regulated data.
2. **Pin a specific model** rather than an auto-routing alias, so you can say
   afterwards which provider saw a given record. `X-Routed-Via` is logged for
   every pass — provider only, never the text.
3. **Turn it off** per endpoint. Every structured identifier is still caught
   offline. You lose names and free-text addresses.

The main proxy path does not have this problem: providers only ever see
placeholders.

## Secrets

| Secret | Where | If lost |
|---|---|---|
| `MASTER_KEY` | environment only | stored API keys unrecoverable |
| Provider API keys | database, Fernet-encrypted | re-enter |
| `crypto_key` | database, encrypted | `encrypt` output unrecoverable |
| Egress proxy URL | database, encrypted | re-enter |
| User passwords | database, PBKDF2-SHA256 ×600k | not recoverable by design |

`MASTER_KEY` cannot be rotated without re-entering every stored secret; there is
no re-encryption path. Treat it as permanent.

Secrets are never returned by the API. `GET /api/settings` shows `••••••••` when
one is set and nothing otherwise.

## Console

- Session cookies: HttpOnly, SameSite=strict, server-side, expiring.
- Five failed logins lock an account for five minutes.
- All accounts are full administrators. There are no read-only roles, so anyone
  who can sign in can read the egress configuration and change what is masked.
- **Serve it over HTTPS** and set `COOKIE_SECURE=true`. None of the above helps
  if the session cookie crosses the network in the clear.

## Unauthenticated surfaces

`/analyze`, `/anonymize`, `/deanonymize`, `/health` and every proxy endpoint
have no authentication. They are meant for a private network.

`/deanonymize` in particular will decrypt anything encrypted with the current
key. Do not expose port 8080 to the internet.

If you need client authentication, put a reverse proxy in front and require a
header. AVRON does not issue client API keys.

## Untrusted input

Text passing through is data, not instructions. The detection model's prompt
wraps input in tags and tells it to treat the content as data, but prompt
injection is not solved by instructions. The mitigation that actually works is
structural: the model returns only spans, and every span is verified to be an
exact substring of the input before use. A span it invents is dropped. It cannot
inject text into your output.

Regexes are user-supplied and therefore a denial-of-service vector. Nested
quantifiers are rejected at save time and patterns are capped at 500 characters.
This is a heuristic, not a proof — a determined operator can still write
something slow.

## Logging

AVRON does not log message content. It logs counts, provider names, latencies
and configuration changes.

What does record content: Portainer's log viewer shows whatever any container
prints, and an egress proxy's access log records every destination host and
timestamp. Neither sees prompt bodies over TLS, but the metadata is a record of
which provider handled what and when.

The audit log keeps the last 2,000 configuration changes with actor and
timestamp. Latency samples keep the last 5,000 requests with no text.

## Known weaknesses

- **Detection is incomplete.** Patterns miss what they do not match; the model
  misses what it does not recognise. Both produce false positives. Benchmark on
  your own labelled data.
- **Images are not scanned.** An Aadhaar card screenshot passes through intact.
- **Plain SHA-256 on short identifiers is reversible.** A 12-digit space with a
  known checksum is ~10¹¹ candidates. Treat `hash` output as identifying data,
  not anonymised data.
- **Masking is not anonymisation.** `encrypt` output plus the key is still
  personal data.
- **Portainer's socket mount is root on the host.** If you keep it, bind 9443 to
  localhost or a VPN address.
- **Single-tenant.** No isolation between users of the same instance.

## Deployment hardening

```yaml
    ports:
      - "127.0.0.1:8080:8080"    # or a VPN address
    environment:
      COOKIE_SECURE: "true"      # with TLS in front
```

Docker's port publishing writes its own iptables rules and bypasses UFW, so a
firewall rule alone will not protect a `0.0.0.0` binding. Binding to the
interface is what closes it.
