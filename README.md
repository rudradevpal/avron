# AVRON — PII detection, masking and LLM proxy

PII detection with regional pattern packs, a second pass through
a language model for the things patterns cannot describe, and a transparent
OpenAI-compatible proxy so agents never see real data. Everything is configured
from a web console; nothing but the encryption key lives in the environment.

Detection is built on [Microsoft Presidio](https://github.com/data-privacy-stack/presidio)
(MIT) and [spaCy](https://spacy.io) (MIT). See [NOTICE.md](NOTICE.md) for the
full attribution list.

Full documentation is in [docs/](docs/) — [overview](docs/overview.md),
[architecture](docs/architecture.md), [installation](docs/installation.md),
[configuration](docs/configuration.md), [detection](docs/detection.md),
[API](docs/api.md), [usage](docs/usage.md), [operations](docs/operations.md),
[security](docs/security.md).

> Presidio 2.2.364. The project moved out of `microsoft/` — the repo is now
> `data-privacy-stack/presidio`. The old `mcr.microsoft.com/presidio-*` images
> are frozen.

## 1. Run it

```bash
mkdir -p /root/docker-storage/avron/{data,cache}
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put that into `docker-compose.yml` in place of `REPLACE_WITH_FERNET_KEY`,
`chmod 600` it, then:

```bash
docker compose up -d --build
docker logs avron 2>&1 | grep -A6 "first-run credentials"
```

Full steps in [docs/installation.md](docs/installation.md).

The first-run admin password is printed once and is not recoverable from the
database. Open <http://localhost:8080>, sign in as `admin`, and change it — the
console will insist.

### Why MASTER_KEY stays in the environment

It encrypts the upstream API keys stored in the database, so it cannot live in
the database it protects. Lose it and every stored key must be re-entered;
change it and the stored keys silently decrypt to empty.

## 2. The console

| Section | What it does |
|---|---|
| **Overview** | traffic, values masked, engine state |
| **Endpoints** | path → providers, keys, masked roles, entity set, strategy, timeout |
| **Analytics** | p50 / p95 latency and token use per provider |
| **Entities** | per-entity on/off and the confidence threshold |
| **Patterns** | region packs, add or edit rules, AI drafting, live tester |
| **Playground** | pick a model from the endpoint's providers, run a prompt, see every stage |
| **Detection model** | the model that *finds* PII — base URL, key, entities, connection test |
| **Egress** | outbound proxy for all traffic, with an exit-IP check |
| **Scan text** | paste text, see every span AVRON finds |
| **Users** | add and remove accounts — all accounts are full admins |
| **Audit log** | every config change and who made it |

### Region packs

Patterns ship grouped by region: India, United States, United Kingdom, European
Union, Asia-Pacific, Global, plus a region-free Network pack for IP and MAC
addresses.

Only the packs listed in `DEFAULT_PACKS` start enabled — currently India and
Network. That default is a judgement call, not a neutral one; change the
constant in `avron/patterns.py` if your deployment is somewhere else, or just
flip the switches in the console.

Turn on only where your data comes from. Every region has bare digit runs that
look alike — an Indian mobile, a UK NHS number and a Canadian SIN are all
nine-or-ten digit strings — so enabling everything trades precision for recall.
Those patterns carry low base scores deliberately and only fire when nearby
words support them.

A pack also gates Presidio's own recognizers. Presidio loads its US and UK
recognizers for English whatever you configure, so switching the UK pack off
disables `UK_NHS` and `UK_NINO` as entities too, not just the patterns here.

### Drafting a pattern with AI

**Generate with AI** takes a plain description and returns a regex, context
words, a suggested score and test samples from the detection model. The draft
opens in the normal editor with the tester already loaded, and the same safety
check applies before it can be saved. Use fake values in the examples box — that
text goes to the detection model.

### Patterns

A pattern is a regex plus a score, optional context words that raise confidence
when they appear nearby, and an optional check that rejects matches outright.
The Aadhaar patterns use the Verhoeff checksum, which is what stops every
12-digit order number being masked.

The live tester shows matches as you type: solid highlight means the check
passed, struck through means the pattern matched but the check rejected it.
Patterns are validated on save — a broken one is refused and the previous
version stays live rather than taking the analyzer down.

Nested quantifiers like `(a+)+` are rejected: they let a crafted input hang the
process.

### Endpoints and provider pools

Each endpoint is a path on this gateway that forwards to one or more providers.

Pick a provider type and the base URL, default model and auth header fill
themselves: OpenAI, Azure OpenAI, OpenRouter, Groq, Mistral, DeepSeek, Together,
Cerebras, Google AI Studio, Anthropic, Ollama, vLLM, FreeLLMAPI, or Custom.

All of these speak the OpenAI wire format. Anthropic's native API does not — the
preset sets the base URL and `x-api-key` header, but the client has to speak
Anthropic itself; requests are not translated.
Point any framework at it:

```python
ChatOpenAI(base_url="http://localhost:8080/v1",
           api_key="anything", model="gpt-4o-mini")
```

Store the real key on each provider and it replaces whatever the client sends,
so agents never hold a provider credential at all.

**Sharing traffic across several providers.** An endpoint holds a pool and a
strategy:

| Strategy | Behaviour |
|---|---|
| `failover` | Active / passive. Always the lowest order number that is healthy. |
| `round_robin` | Rotate through healthy providers in turn. |
| `least_busy` | Fewest requests currently in flight — good when one provider is slow under load. |
| `weighted` | Random, biased by weight. Send 3 in 4 to the fast one. |

Whatever the strategy picks, a failed attempt falls through to the next
candidate, so every strategy is also a failover chain. `retries` caps how many
providers one request will try.

A failing provider is sidelined with compounding backoff — 10s, 20s, 40s, up to
five minutes — and a success clears it. It is pushed to the back of the queue
rather than removed, so if everything is in cooldown the request is still
attempted instead of failing outright.

5xx and 429 trigger failover. Other 4xx do not: a malformed request fails the
same way everywhere, so retrying it just burns the pool and delays the error.

The Endpoints screen shows in-flight count, successes, failures, average
latency and cooldown per provider, refreshed while you watch it. Responses carry an
`X-Upstream` header naming which one served them.

Different paths can carry different policies — `/v1` with the detection model on
for quality, `/fast/v1` with it off for latency. Longest matching path wins.

Covered: `/chat/completions`, streaming, tool calls, `/responses`,
`/embeddings`, legacy `/completions`. Everything else forwards byte for byte.

**Placeholders are indexed.** Two people become `<PERSON_1>` and `<PERSON_2>`
and keep those identities across every message. Flat `<PERSON>` tags would make
the model conflate them.

**Images are not scanned.** Text baked into a screenshot passes through. If your
agents send images, that is an open hole.

### Two different models

These are easy to confuse, so the console separates them:

- **Detection model** (Setup → Detection model) reads text to find names and
  addresses. It never writes replies. It receives text **unmasked**.
- **Chat model** is whatever your client asks for, chosen per request and served
  by the upstreams on a route. It only ever sees placeholders.

The **Playground** shows the difference concretely: it prints what the model
received, the placeholder table, the raw reply, and the restored reply side by
side. If you want to know whether masking is working, that screen answers it.

### Outbound proxy

Under **Network**, point every outbound call — the model pass and all proxy
upstreams — at an HTTP proxy, so traffic leaves from one address you control.
The URL is stored encrypted since it usually carries credentials. Percent-encode
any `@` in the password as `%40`, or the URL parses as a different host.

The bypass list matters: `avron` and any sibling container must stay on it,
otherwise container-to-container traffic takes the long way out and fails in a
way that looks like broken DNS.

"Check where traffic exits" reports the exit IP with and without the proxy side
by side. Same address twice means the proxy is on the same host and nothing has
changed.

## 3. Direct masking API

Unchanged and unauthenticated on the local network:

```bash
curl -s localhost:8080/analyze -H 'Content-Type: application/json' \
  -d '{"text":"PAN ABCPE1234F, Aadhaar 3456 7890 1238"}'

curl -s localhost:8080/anonymize -H 'Content-Type: application/json' \
  -d '{"text":"...","strategy":"replace",
       "per_entity":{"IN_AADHAAR":"hash","IN_PHONE_NUMBER":"mask"}}'
```

`replace` collapses everything of a type into one tag. `hash` gives a stable
pseudonym for joins. `mask` keeps the length. `encrypt` is reversible through
`/deanonymize`.

Plain SHA-256 on Aadhaar is weak: 12 digits with a known checksum is roughly
10¹¹ candidates, which a GPU exhausts quickly. Treat those digests as
identifying data, not anonymised data.

## 4. Why two detection layers

Regex can match `ABCPE1234F` because PAN has a fixed shape. It cannot decide
whether a given phrase is a person or a place, and spaCy's English NER
underperforms badly on names outside its training distribution — Indian,
Arabic, transliterated. The model pass covers that, and only returns spans — it never rewrites text, so masking stays
deterministic. A span it invents is not found in the source and is dropped.

The pass fails open: if the API times out you still get every rule-based
detection, and the names quietly leak. Watch the logs for it.

## 5. Before production

- **The model pass sends unmasked text.** That is unavoidable — you cannot find
  PII in text you have already scrubbed. If the upstream is a hosted free tier,
  your Aadhaar and PAN data is being disclosed to a provider you have no
  agreement with, and free tiers commonly train on submissions. Point it at a
  local model, or turn it off per endpoint.
- **Pin a model rather than `auto`** so you can say afterwards which provider
  saw a given record. The gateway logs the `X-Routed-Via` provider for every
  pass — provider only, never the text.
- **Serve the console over HTTPS** and set `COOKIE_SECURE=true`. Session cookies
  are HttpOnly and SameSite=strict, passwords are PBKDF2-SHA256 at 600k
  iterations, and logins lock out for 5 minutes after 5 failures — none of which
  helps if the session cookie crosses the network in the clear.
- **IP addresses are masked by default.** `ipv4_octets` rejects version strings
  and dates that look like addresses. If you would rather keep internal ranges
  readable for debugging and mask only external visitors, switch the IPv4
  pattern's check to `public_ipv4`, which passes over private, loopback and
  CGNAT ranges.
- **Analytics are percentiles, not averages.** p95 is the slow tail, which is
  what people actually notice. Samples are capped at the last 5,000 requests.
- **Watch for recognizers fighting.** A bare 10-digit number matches both
  `IN_PHONE_NUMBER` and `IN_BANK_ACCOUNT`; the `bank_not_mobile` check keeps
  accounts from swallowing contact numbers. If you add your own numeric
  patterns, give them a validator or they will collide the same way.
- **`ORGANIZATION` is off by default in the detection model.** Models label
  field names like "PAN" and "IFSC" as organisations, which masks the label
  instead of the value and makes the prompt harder for the chat model to read.
  Turn it on only if you actually need employer names hidden.
- **Benchmark on your own labelled sample.** The regexes are the easy part;
  name and address recall is where the gaps are.

## Licence

AVRON is MIT licensed — see [LICENSE](LICENSE). Fill in the copyright holder
before you publish it.

Third-party components and their licences are listed in [NOTICE.md](NOTICE.md).
All dependencies are permissive (MIT, BSD-3-Clause, Apache-2.0); none impose
copyleft obligations on AVRON or on code that calls it.
