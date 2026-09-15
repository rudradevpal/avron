# Avron documentation

Avron sits between your applications and any OpenAI-compatible model API. It
finds personal data in outbound text, replaces it with placeholders, forwards
the request, and puts the real values back in the reply. The model never sees
the data; your code never sees a placeholder.

| Document | What it covers |
|---|---|
| [overview.md](overview.md) | What the product does and who it is for |
| [architecture.md](architecture.md) | Components, request flow, data model |
| [installation.md](installation.md) | Getting it running |
| [configuration.md](configuration.md) | Every setting in the console |
| [detection.md](detection.md) | Packs, patterns, validators, tuning |
| [api.md](api.md) | HTTP reference for the proxy and the masking API |
| [usage.md](usage.md) | Wiring up SDKs, agents and pipelines |
| [operations.md](operations.md) | Backup, upgrade, monitoring, troubleshooting |
| [security.md](security.md) | Threat model, key handling, known limits |
| [tls.md](tls.md) | HTTPS, Let's Encrypt, automatic renewal |
| [egress-proxy.md](egress-proxy.md) | Routing outbound traffic through a proxy |
| [../NOTICE.md](../NOTICE.md) | Third-party components and licences |

## Read this first

Detection is imperfect. Regular expressions miss things that do not match, the
language model misses things it does not recognise, and both produce false
positives. Avron reduces exposure; it does not eliminate it. Benchmark against
your own labelled data before you rely on it for anything that matters.

The language model detection pass receives text **before** masking. That is
unavoidable — you cannot find personal data in text you have already scrubbed —
and it means the pass is a disclosure to whichever provider you point it at.
[security.md](security.md) covers the options.
