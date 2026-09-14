# Third-party notices

AVRON is built on open-source components. Their licences are reproduced or
referenced below. Nothing here is legal advice; verify against the versions you
actually ship.

Licence data was read from package metadata on 14 September 2026. Licences can
change between releases — re-check when you upgrade.

## Detection engine

**Microsoft Presidio** — `presidio-analyzer`, `presidio-anonymizer` 2.2.364
MIT License. Copyright (c) Microsoft Corporation.
The project is now maintained at <https://github.com/data-privacy-stack/presidio>.

AVRON uses Presidio as a library: its `AnalyzerEngine`, `RecognizerRegistry`,
`PatternRecognizer`, `AnonymizerEngine` and `DeanonymizeEngine`, plus the
built-in recognizers it ships for credit cards, email addresses, IBAN, IP
addresses, US and UK identifiers and others. The regional pattern packs in
`avron/patterns.py` are AVRON's own work, registered into Presidio's registry.

**spaCy** 3.8.x — MIT License. Copyright (c) Explosion AI.

**en_core_web_lg** — MIT License. Copyright (c) Explosion AI.
Downloaded during the image build, not redistributed in this archive. The model
was trained on OntoNotes 5, which Explosion licensed commercially; the released
model weights are MIT.

## Runtime

| Component | Licence |
|---|---|
| FastAPI | MIT |
| Starlette | BSD-3-Clause |
| Uvicorn | BSD-3-Clause |
| Pydantic | MIT |
| httpx | BSD-3-Clause |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| phonenumbers | Apache-2.0 |
| tldextract | BSD-3-Clause |
| NumPy | BSD-3-Clause (with 0BSD, MIT, Zlib, CC0-1.0 components) |
| regex | Apache-2.0 AND CNRI-Python |
| click | BSD-3-Clause |
| PyYAML | MIT |

All are permissive. None impose copyleft obligations on AVRON or on code that
calls it.

## Console

The web console is hand-written HTML, CSS and JavaScript with no framework, no
build step and no third-party assets. Nothing is fetched from a CDN at runtime,
so the console works with the machine fully offline.

## Base image

`python:3.11-slim` is pulled at build time, not redistributed here. It carries
the Python Software Foundation License plus the licences of the Debian packages
in the image.

The stack references no other images. Any model provider you configure in the
console is a service you run or subscribe to yourself, under its own terms.

## Your obligations if you redistribute

MIT and BSD-3-Clause both require that you keep the copyright notice and
licence text with any copy or substantial portion. Shipping this file alongside
the software satisfies that for the Python dependencies.

If you publish AVRON itself, fill in the copyright holder in `LICENSE`, or
replace it with whatever licence you intend.
