# Architecture

## Built on

Detection is [Microsoft Presidio](https://github.com/data-privacy-stack/presidio)
(MIT) driving [spaCy](https://spacy.io) (MIT) with the `en_core_web_lg` model.
AVRON supplies the regional pattern packs, the checksum validators, the
placeholder vault, the proxy and the console. Presidio supplies the analyzer,
the recognizer registry, the context-aware scoring, the anonymizer operators and
the built-in recognizers for cards, email, IBAN, IP and several national IDs.

Full attribution in [../NOTICE.md](../NOTICE.md).

## Components

```
                 ┌──────────────────────────────────────────────┐
  your app ────► │  AVRON                            :8080       │
                 │                                              │
                 │   /v1/*       transparent proxy, masked      │
                 │   /analyze    detection only                 │
                 │   /anonymize  masking without a model call   │
                 │   /api/*      console API, session auth      │
                 │   /           console (static, offline)      │
                 └───────┬──────────────────────┬───────────────┘
                         │                      │
              detection pass            proxied request
                         │                      │
                 ┌───────▼──────┐      ┌────────▼────────┐
                 │ detection    │      │ provider pool   │
                 │ model        │      │ openai, groq,   │
                 │ (unmasked)   │      │ ollama, custom  │
                 └──────────────┘      └─────────────────┘
```

Everything runs in one container. SQLite holds configuration; there is no
external database, queue or cache.

## Request flow

1. A client POSTs to a configured endpoint prefix, e.g. `/v1/chat/completions`.
2. `openai_proxy` matches the longest configured prefix and loads the endpoint's
   provider pool, entity set, masked roles and strategy.
3. For each message whose role is masked, the text goes to `analyze_text`:
   - the Presidio engine runs every enabled pattern plus spaCy NER;
   - if the detection model is on for this endpoint, the text is also sent to it
     and the returned spans are merged;
   - overlapping spans are deduplicated, highest score winning.
4. Placeholders are allocated **in reading order**, then substituted
   right-to-left so earlier offsets stay valid. `<PERSON_1>` is the first person
   mentioned.
5. `balancer` orders the pool by strategy. The request is sent to the first
   candidate; 5xx and 429 fall through to the next, other 4xx return as-is.
6. The reply is walked and every placeholder restored, including bare tokens the
   model stripped the brackets from. Streaming responses are restored chunk by
   chunk with a hold-back buffer.
7. A latency sample is recorded. The vault is discarded when the request ends.

## Key design decisions

**Placeholders are indexed, not flat.** `<PERSON>` for everyone makes the model
conflate people. Numbering them preserves identity and coreference.

**The vault is per-request and in memory.** Nothing is persisted, so a database
compromise does not expose mappings. The trade-off: you cannot re-identify an
old response. Use `/anonymize` with the `encrypt` operator if you need that.

**Validators only reject.** Presidio promotes a `True` from `validate_result` to
the maximum score, which flattens every checksummed pattern to 1.0 and makes
overlaps arbitrary. AVRON's validators return `None` on success, so the score
still reflects pattern specificity plus context.

**Configuration is hot-reloaded atomically.** Saving a pattern builds a fresh
recognizer registry, smoke-tests it, and only then swaps the live reference. A
broken pattern is rejected at save time and the running engine is untouched.

**The proxy route is registered last.** FastAPI matches in registration order,
so `/api`, `/health` and the static mount always win over the catch-all.

## Modules

| File | Responsibility |
|---|---|
| `main.py` | App wiring, startup, masking API, overlap dedupe |
| `openai_proxy.py` | Catch-all proxy, masking, failover, streaming |
| `balancer.py` | Pool ordering, health, cooldown, in-flight tracking |
| `vault.py` | Placeholder allocation and restoration |
| `patterns.py` | Seed patterns, packs, checksum validators |
| `config.py` | Live engine, hot reload, endpoint/pack lookups |
| `db.py` | SQLite schema, migrations, encryption, samples |
| `auth.py` | Sessions, PBKDF2, lockout |
| `admin_api.py` | Console REST API |
| `net.py` | Outbound proxy and bypass handling |
| `providers.py` | Provider presets and auth header styles |
| `llm_pass.py` | Detection-model span extraction |

## Data model

```
settings        key/value; secrets encrypted with MASTER_KEY
users           PBKDF2 hashes
sessions        server-side, expiring
routes          endpoint prefix, strategy, masked roles, entity set
upstreams       provider pool per endpoint, tokens encrypted
patterns        regex, score, context, validator, pack, enabled
packs           per-region on/off
entity_toggles  per-entity on/off
samples         per-request latency and tokens, capped at 5,000
stats           hourly counters
audit           configuration changes, capped at 2,000
```

Health and in-flight state live in memory, not the database: they are per
process and worthless after a restart, and writing a row per request would be
the slowest part of the hot path.
