# Usage

## As a drop-in endpoint

Change the base URL. Nothing else.

```python
# OpenAI SDK
from openai import OpenAI
client = OpenAI(base_url="http://avron:8080/v1", api_key="anything")

# LangChain / LangGraph
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(base_url="http://avron:8080/v1",
                 api_key="anything", model="gpt-4o-mini")
```

The same applies to CrewAI, AutoGen, LlamaIndex, Pydantic-AI, Aider, Continue,
and anything else that accepts an OpenAI base URL. In n8n, set the Base URL
field on the OpenAI credential.

If a provider key is stored on the endpoint, `api_key` can be any placeholder —
clients never hold the real credential.

## Agents

Agent loops leak through tool calls as often as through messages, so
`tool_calls.arguments` are masked and restored too.

Placeholders are stable across every message in a request, which is what lets an
agent reason about "the second customer" without seeing a name.

Two things to weigh:

- **Latency roughly doubles** when the detection model is on, because each
  message needs a detection round-trip before the real call. Turn it off on the
  endpoint your agents use if responsiveness matters more than name coverage.
- **`system` is not masked** by default. That is deliberate: system prompts are
  your instructions, not user data, and masking them corrupts the agent.

## Batch and pipelines

For documents rather than chat, call the masking API directly.

```python
import httpx

def mask(text):
    r = httpx.post("http://avron:8080/anonymize", json={
        "text": text,
        "strategy": "replace",
        "per_entity": {"IN_AADHAAR": "hash"},
    }, timeout=120)
    return r.json()["anonymized_text"]
```

Use `hash` for fields you need to join on and `replace` for free text. Set
`"use_llm": false` for throughput when your data is structured.

## Reversible masking

When something downstream must recover the original:

```bash
# mask
curl -s localhost:8080/anonymize -H 'Content-Type: application/json' \
  -d '{"text":"...","strategy":"encrypt"}' > masked.json

# later
curl -s localhost:8080/deanonymize -H 'Content-Type: application/json' \
  -d @masked.json
```

Keep the `items` array; without it the ciphertext cannot be located. The key is
the console's `crypto_key`, encrypted at rest under `MASTER_KEY`.

## Verifying it works

The **Playground** is the fastest answer to "is masking working". Pick an
endpoint, load the model catalogue, run a prompt. You get four panels: what the
model received with placeholders highlighted, the placeholder-to-value table,
the raw reply, and the restored reply.

A useful test prompt names three people with separate identifiers. If the reply
pairs the right identifier with the right person, indexing is working; if it
merges them, something is wrong.

From the shell:

```bash
curl -s localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user",
       "content":"Who holds which ID? Priya, PAN ABCPE1234F. Mohammed, PAN BZTPK5678L."}]}' \
  -i | grep -iE 'HTTP/|X-Upstream|x_pii_masked'
```

## Common mistakes

| Mistake | Symptom |
|---|---|
| `localhost` inside a container | Connection refused; use the service name |
| Host-published port used from inside the network | Use the container's internal port, not the host mapping |
| Masking `system` | Agent ignores its instructions |
| Expecting image PII to be caught | Screenshots pass through |
| Assuming `/analyze` offsets match `/anonymize` items | They index different strings |
