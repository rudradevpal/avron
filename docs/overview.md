# Overview

## The problem

Applications that call language models routinely send personal data to a third
party: a support ticket with a customer's phone number, a CRM note with a
national ID, a log line with a user's IP address. Once sent, that data is
outside your control and often outside your jurisdiction.

Removing the data before sending is the obvious fix, and the obvious fix breaks
the model. Strip the names and the model cannot tell two people apart. Strip the
identifiers and it cannot answer questions about them. Strip nothing and you
have a disclosure.

## The approach

Avron replaces each distinct value with a stable stand-in, and you choose what
kind per data type: a numbered tag, a lookalike with the same shape, or a masked
tail.

```
in   Priya Raghunathan (PAN ABCPE1234F) escalated to Mohammed Ashraf.
sent <PERSON_1> (PAN <IN_PAN_1>) escalated to <PERSON_2>.
back <PERSON_1> should be contacted first.
out  Priya Raghunathan should be contacted first.
```

The model reasons normally because the structure of the text is intact and each
person stays distinguishable. The real values never leave your infrastructure.

## What is in the box

- **Detection.** [Microsoft Presidio](https://github.com/data-privacy-stack/presidio)
  (MIT) with regional pattern packs, checksum
  validators, and an optional language-model pass for names and addresses that
  no pattern can describe.
- **Proxy.** A transparent OpenAI-compatible endpoint. Point any SDK or agent
  framework at it and masking happens in the path; no client changes.
- **Console.** Everything is configured in a web UI — endpoints, providers,
  patterns, entities, thresholds, egress. Only the encryption key lives in the
  environment.
- **Provider pools.** Several upstreams per endpoint with failover,
  round-robin, least-busy or weighted selection, and per-provider latency
  analytics.

## Who it is for

Teams sending regulated or sensitive text to a model API they do not control,
and who need a defensible answer to "what did the provider see?".

It is not a compliance product. It produces no certifications and makes no legal
claims. It reduces what leaves the building and records which provider received
each request.

## What it does not do

- **Images.** Text inside a screenshot or a scan passes through unexamined.
- **Non-OpenAI wire formats.** Anthropic's native API is not translated.
- **Guarantees.** See the caveats in [detection.md](detection.md).
