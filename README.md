<div align="center">

<img src="avron/static/logo.svg" width="72" alt="">

# Avron

**Your prompts reach the model. Your customers' data doesn't.**

A self-hosted gateway that finds personal data in outbound LLM traffic, swaps it
for stand-ins the model can still reason about, and puts the real values back in
the reply. One OpenAI-compatible endpoint. No client changes.

</div>

---

Every prompt your application sends is a disclosure. The support ticket carries
a phone number, the CRM note carries a national ID, the log line carries a
customer's IP. Once it leaves, it is on someone else's disk, under someone
else's terms, often in someone else's country.

The obvious fix breaks the model. Strip the names and it cannot tell two people
apart. Strip the identifiers and it cannot answer questions about them.

Avron takes a third path. Each distinct value is replaced by a **stable stand-in**
— and you choose what kind, per data type:

```
you send    Priya Raghunathan, PAN ABGPP3432K, called from 9876543210
model sees  <PERSON_1>,        PAN KHZKQ0604D, called from ••••••3210
comes back  Priya Raghunathan, PAN ABGPP3432K, called from 9876543210
```

A name tag keeps two people distinct. A lookalike has the same shape, so the
model can count the characters and validate the format. A masked tail is enough
for a human to recognise the record. Real values never leave your infrastructure.

## Install

```bash
mkdir -p /root/docker-storage/avron/{data,cache}
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put that key into `docker-compose.yml` in place of `REPLACE_WITH_FERNET_KEY`,
`chmod 600` it, then:

```bash
docker compose up -d --build
docker logs avron 2>&1 | grep -A6 "first-run credentials"
```

Open <http://localhost:8080>, sign in as `admin` with the printed password, and
change it — the console will insist. One container, one secret, no database
server. [Full steps →](docs/installation.md)

## Point anything at it

```python
from openai import OpenAI
client = OpenAI(base_url="http://avron:8080/v1", api_key="avron-YOUR-KEY")
```

That is the whole integration. The same line works for LangChain, LangGraph,
CrewAI, AutoGen, LlamaIndex, Pydantic-AI, Aider, Continue, Copilot, n8n — every
client that accepts an OpenAI base URL.

Covered: chat completions, **streaming**, tool calls, `/responses`,
`/embeddings`, legacy `/completions`. Everything else forwards byte for byte.

## Three ways to stand in for a value

The one decision that matters, set per data type in the console.

| | Model sees | Good for | The model can… |
|---|---|---|---|
| **Name tag** | `<PERSON_1>` | names, addresses, companies | tell them apart, refer to them |
| **Lookalike** | `KHZKQ0604D` | PAN, Aadhaar, cards, phones, any ID | examine the format, count characters, spot what is wrong |
| **Last 4** | `••••••3210` | phone and card in replies a human reads | help someone identify the record |

Lookalikes are generated from a shape — `AAAAA9999A` for a PAN — keyed per
request, so the same value gets a different stand-in next time and nothing can
be correlated across requests. Where the format carries a checksum, the
lookalike is generated to **fail** it, so it is the right shape and cannot be
anybody's real number. [How it works →](docs/detection.md)

## Detection

Two layers. Patterns find things with a fixed shape; a language model finds the
things only context reveals.

**Regional packs**, on or off as a group — India, United States, United Kingdom,
European Union, Asia-Pacific, Global, plus a region-free Network pack for IP and
MAC addresses. Turn on only where your data comes from: every region has
nine-digit numbers that look alike, and enabling everything trades precision for
recall.

**Real checksums**, not just shapes. Aadhaar runs Verhoeff, NHS numbers run
mod-11, routing numbers run the ABA weights, Canadian SINs run Luhn. That is
what stops every twelve-digit order number being masked.

**Write your own** in the console, with a live tester that highlights matches as
you type — green for kept, struck through for rejected by the check. Or describe
it in plain words and let the model draft the regex, context words, score and
test samples for you.

**A detection model** catches what no pattern can describe: names spaCy was
never trained on, transliterated addresses, a diagnosis in free text. It returns
only spans, never rewritten text, so masking stays deterministic. It fails open
— if it times out you still get every rule-based detection.

## Endpoints and provider pools

An endpoint is a path on Avron that forwards to one or more providers.

| Strategy | Behaviour |
|---|---|
| `failover` | Active / passive. The healthiest highest-priority provider. |
| `round_robin` | Rotate through healthy providers. |
| `least_busy` | Fewest requests in flight. For when one provider degrades under load. |
| `weighted` | Random, biased by weight. |

Whatever the strategy picks, a failed attempt falls through to the next, so
every strategy is also a failover chain. A failing provider is sidelined with
compounding backoff and restored on success. 5xx and 429 fail over; other 4xx do
not, because a malformed request fails the same way everywhere.

Presets fill the base URL, default model and auth header for OpenAI, Azure
OpenAI, OpenRouter, Groq, Mistral, DeepSeek, Together, Cerebras, Google AI
Studio, Anthropic, Ollama, vLLM and any custom endpoint. Store the key on the
provider and it replaces whatever the client sends — your agents never hold a
provider credential.

## See what actually happened

**Playground** — run a prompt and see four panels side by side: what the model
received, the stand-in table, the raw reply, the restored reply. If you want to
know whether masking is working, that screen answers it.

**Audit log → Requests** — the same four panels for real traffic, streaming
included. Off by default, encrypted at rest, deleted after a day you can
configure. It stores unmasked text, which is the one thing this product exists
to avoid, so it is opt-in and loud about it.

**Analytics** — p50, p95 and slowest per provider, with token counts. p95 is the
number your users notice; an average hides the tail.

## Access

Avron issues its own API keys. A client sends an `avron-…` key; Avron verifies
it, consumes it, and substitutes the real provider credential outbound. A leaked
client key gets someone your gateway, not your OpenAI account.

Keys can be scoped to endpoints, given an expiry, disabled, and revoked, and
each shows its use count and last use. Two roles: administrators change
everything, members manage only their own keys.

Enforcement is off by default so an upgrade cannot break existing clients —
which means **a fresh install lets anyone who can reach port 8080 use it**.
Issue keys, then switch it on. That is the first thing to do after installing.

## Everything is in the console

Nothing but the encryption key lives in the environment. Endpoints, providers,
patterns, entities, replacement styles, thresholds, egress proxy, keys, users,
retention — all of it is edited in the browser and stored in one SQLite file.

The console is hand-written HTML, CSS and JavaScript. No framework, no build
step, no CDN. It works with the machine fully offline.

## Before production

- **The detection model receives unmasked text.** Unavoidable — you cannot find
  personal data in text you have already scrubbed. Point it at a local model, or
  switch it off per endpoint. [Details →](docs/security.md)
- **Turn on key enforcement.**
- **Serve the console over HTTPS** and set `COOKIE_SECURE=true`.
- **Images are not scanned.** Text inside a screenshot passes through.
- **Benchmark on your own labelled sample.** The regexes are the easy part; name
  and address recall is where the gaps are.

## Documentation

| | |
|---|---|
| [Overview](docs/overview.md) | What it does and who it is for |
| [Architecture](docs/architecture.md) | Components, request flow, data model |
| [Installation](docs/installation.md) | Getting it running |
| [Configuration](docs/configuration.md) | Every setting |
| [Detection](docs/detection.md) | Packs, patterns, shapes, tuning |
| [API](docs/api.md) | HTTP reference |
| [Usage](docs/usage.md) | SDKs, agents, pipelines |
| [Operations](docs/operations.md) | Backup, upgrade, monitoring |
| [Security](docs/security.md) | Threat model and known limits |
| [Egress proxy](docs/egress-proxy.md) | Routing outbound traffic |

## Built on

[Microsoft Presidio](https://github.com/data-privacy-stack/presidio) (MIT) and
[spaCy](https://spacy.io) (MIT). Avron adds the regional packs, the checksum
validators, the stand-in engine, the proxy and the console. Full attribution in
[NOTICE.md](NOTICE.md).

## Licence

MIT — see [LICENSE](LICENSE). Fill in the copyright holder before you publish.
All dependencies are permissive; none impose copyleft obligations.
