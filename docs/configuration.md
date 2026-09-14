# Configuration

Everything except `MASTER_KEY` is configured in the console and stored in
SQLite. Environment variables seed the database on first boot only; after that
they are ignored.

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `MASTER_KEY` | yes | Fernet key encrypting stored API keys |
| `DB_PATH` | no | defaults to `/data/gateway.db` |
| `COOKIE_SECURE` | no | set `true` when serving over HTTPS |
| `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `LLM_MODEL`, `USE_LLM`, `SCORE_THRESHOLD` | no | first-boot seeds only |

## Endpoints

An endpoint is a path on AVRON that forwards to a pool of providers.

| Field | Notes |
|---|---|
| Path | `/v1`, `/secure/v1`, anything. Longest match wins. Reserved paths are rejected. |
| Providers | One or more. See below. |
| Strategy | `failover`, `round_robin`, `least_busy`, `weighted` |
| Retries | How many providers one request may try |
| Masked roles | Default `user`. `system` is available but not advised — masking your own instructions corrupts them. |
| Detection model | Per-endpoint override of the global setting |
| Entities | Empty means "whatever is enabled globally" |
| Timeout | Seconds |

Several endpoints can carry different policies — `/v1` with the detection model
on for quality, `/fast/v1` with it off for latency.

## Providers

| Field | Notes |
|---|---|
| Type | Fills base URL, default model and auth header style |
| Address | The `/v1` base URL |
| API key | Stored encrypted. Replaces whatever the client sent, so agents never hold a real provider credential. |
| Force a model | Overrides the client's choice |
| Order | Lower goes first under `failover` |
| Weight | Relative share under `weighted` |

Presets: OpenAI, Azure OpenAI, OpenRouter, Groq, Mistral, DeepSeek, Together,
Cerebras, Google AI Studio, Anthropic, Ollama, vLLM/LM Studio, FreeLLMAPI,
Custom. All speak the OpenAI wire format except Anthropic, whose preset sets the
base URL and `x-api-key` header but does not translate the request shape.

### Strategies

| Strategy | Behaviour |
|---|---|
| `failover` | Active/passive. Lowest order number that is healthy. |
| `round_robin` | Rotate through healthy providers. |
| `least_busy` | Fewest requests in flight. Good when one provider degrades under load. |
| `weighted` | Random, biased by weight. |

Whatever the strategy picks, a failed attempt falls through to the next, so
every strategy is also a failover chain. A failing provider is sidelined with
compounding backoff — 10s, 20s, 40s, capped at five minutes — and a success
clears it. It is pushed to the back rather than removed, so if everything is
cooling the request is still attempted.

5xx and 429 trigger failover. Other 4xx do not: a malformed request fails the
same way everywhere.

## Entities

Per-type on/off plus a global confidence threshold (default 0.4). Raise the
threshold if harmless text is being masked; lower it if identifiers slip
through.

`ORGANIZATION` and `DATE_TIME` are off by default. Models and spaCy tag field
labels like "PAN" and "SSN" as organisations, which masks the label instead of
the value; `DATE_TIME` catches every timestamp in a log line and breaks
scheduling.

## Detection model

The second pass that finds names and addresses. It is **not** the model that
answers your prompts.

| Field | Notes |
|---|---|
| Base URL, key, model | Any OpenAI-compatible endpoint |
| Timeout | Seconds; the pass fails open on timeout |
| Score | Confidence assigned to its findings |
| Ask it to find | Which entity types to request |

It receives text **unmasked**. See [security.md](security.md).

## Egress

Routes every outbound call — detection model, all providers, both connection
tests — through an HTTP proxy.

The bypass list must contain `avron` plus any sibling container it talks to.
Sending container-to-container traffic through an external proxy fails in a way
that looks like broken DNS. "Check where traffic exits" shows the exit IP with and
without the proxy side by side.

## Users

All accounts are full administrators; there are no restricted roles. Passwords
are PBKDF2-SHA256 at 600,000 iterations. Five failed attempts lock an account
for five minutes.
