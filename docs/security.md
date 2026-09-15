# Security

## What Avron protects against

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
| Client API keys | database, SHA-256 hash | not recoverable; issue a new one |

`MASTER_KEY` cannot be rotated without re-entering every stored secret; there is
no re-encryption path. Treat it as permanent.

Secrets are never returned by the API. `GET /api/settings` shows `••••••••` when
one is set and nothing otherwise.

## Console

- Session cookies: HttpOnly, SameSite=strict, server-side, expiring.
- Five failed logins lock an account for five minutes.
- Two roles: administrator and member. Members can only manage their own API
  keys and password. Anyone with an administrator account can read the egress
  configuration and change what gets masked.
- **Serve it over HTTPS** and set `COOKIE_SECURE=true`. None of the above helps
  if the session cookie crosses the network in the clear. Avron can get a
  Let's Encrypt certificate and renew it itself — see [tls.md](tls.md).

## Client authentication

Avron issues its own API keys. Turn on **Require a key** under API keys and the
proxy plus the whole masking API refuse requests without a valid one.

It is off by default so that upgrading does not break existing clients. **While
it is off, anyone who can reach port 8080 can use your endpoints and your stored
provider credentials.** That is the single most important thing to fix after a
first install.

Keys are stored as SHA-256 hashes and shown once. They can be scoped to
particular endpoints, given an expiry, disabled without deleting, and revoked.
Use counts and last-used timestamps tell you which ones are dead.

`/health` stays open for liveness probes and exposes no data beyond
configuration shape.

`/deanonymize` will decrypt anything encrypted with the current key, so it is
worth confirming enforcement is on before exposing the port anywhere.

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

## Request inspection

**Audit log → Requests**, when switched on, stores full request and response
text — unmasked — so you can see what actually went out. This is the one feature
that deliberately writes personal data to disk.

Encrypted under `MASTER_KEY`, deleted after `capture_days` (default 1), capped
at `capture_limit` rows, administrators only, and each view is recorded in the
change log. Off by default. Turn it off again when you are done.

Raising `capture_days` raises your exposure window in direct proportion. A week
of recorded traffic is a week of unmasked personal data sitting in a file.

If your policy forbids storing this at all, leave `capture_enabled` off and use
the Playground, which holds nothing.

## Logging

Avron does not log message content. It logs counts, provider names, latencies
and configuration changes.

What does record content: Portainer's log viewer shows whatever any container
prints, and an egress proxy's access log records every destination host and
timestamp. Neither sees prompt bodies over TLS, but the metadata is a record of
which provider handled what and when.

The audit log keeps the last 2,000 configuration changes with actor and
timestamp. Latency samples keep the last 5,000 requests with no text.

## Lookalikes

A lookalike is a fake value with the real one's shape, so the model can examine
it. What keeps it safe, and what does not:

- Keyed per request, so it cannot correlate one request with another.
- Generated to fail the format's checksum where one exists, so it cannot be a
  real number.
- Checked against every other value in the request and every lookalike already
  issued, so two records never share one.
- **Formats with no checksum — PAN, IFSC, most national IDs — carry residual
  risk.** A well-formed lookalike could coincidentally be somebody's real one.
  This cannot be engineered away; it is the cost of letting the model inspect
  the value. Use tags where you do not need that.

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
- **Single-tenant.** Members are isolated from each other's API keys, but every
  key reaches the same endpoints and the same provider credentials unless you
  scope it.

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
