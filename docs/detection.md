# Detection

Two layers. Patterns find things with a fixed shape; a language model finds
things that only context reveals.

## Layer 1: patterns

A pattern is a regex, a base score, context words that raise confidence when
they appear nearby, and an optional check that rejects matches outright.

Presidio's context enhancer adds roughly 0.35 when a context word is within the
surrounding window. That is why a bank account pattern carries a base score of
0.15: a bare fourteen-digit number in an invoice should not be masked, the same
number after "account number" should.

Checks only ever reject. Returning `True` would make Presidio promote the hit to
the maximum score, flattening every checksummed pattern to 1.0 and making
overlaps a coin toss.

### Validators

| Name | Effect |
|---|---|
| `none` | Accept every regex match |
| `verhoeff` | Aadhaar checksum |
| `luhn` | Card/account checksum, 12+ digits |
| `luhn9` | Luhn over exactly 9 digits (Canadian SIN) |
| `phone_len` | Digit count must be 10, 11 or 12 |
| `not_repdigit` | Reject one- or two-digit repeats |
| `bank_not_mobile` | Account number, but not a 10-digit mobile |
| `nhs_mod11` | NHS number check digit |
| `aba_routing` | US routing number checksum |
| `us_ssn` | Valid SSN ranges; rejects 000, 666, 9xx |
| `ipv4_octets` | Every octet 0-255; rejects version strings |
| `public_ipv4` | Valid IPv4 excluding private, loopback and CGNAT |

## Packs

| Pack | Contents | Default |
|---|---|---|
| `india` | Aadhaar, PAN, GSTIN, UPI, IFSC, phone, voter ID, passport, DL, vehicle, PIN, bank account | on |
| `network` | IPv4, IPv4:port, CIDR, IPv6, MAC | on |
| `us` | SSN, EIN, ABA routing, ZIP | off |
| `uk` | NINO, NHS number, sort code, postcode | off |
| `eu` | VAT, German tax ID | off |
| `apac` | Singapore NRIC, Australian TFN/ABN, Canadian SIN | off |
| `global` | Date of birth, generic passport, SWIFT/BIC | off |

The defaults live in `DEFAULT_PACKS` in `avron/patterns.py`. That choice is a
judgement call, not a neutral one — change the constant, or flip the switches in
the console.

**Enable only your region.** Every region has bare digit runs that look alike: a
ten-digit Indian mobile, a UK NHS number and a nine-digit Canadian SIN are
indistinguishable without context. Enabling everything trades precision for
recall. Those patterns carry deliberately low base scores so they only fire when
surrounding words support them.

A pack also gates Presidio's own recognizers. Presidio loads its US and UK
recognizers for English whatever you configure, so switching the UK pack off
disables the `UK_NHS` and `UK_NINO` entities too.

## Layer 2: the detection model

Regex cannot decide whether a phrase is a person or a place, and spaCy's English
NER underperforms on names outside its training distribution.

The model receives the text and returns a JSON array of spans. It never rewrites
anything, so masking stays deterministic. A span it invents is not found in the
source and is silently dropped — it cannot reach the output.

The pass **fails open**: on timeout or error you still get every rule-based
detection, and names leak quietly. Watch the logs for `LLM pass failed`.

## What the model sees instead

Detection decides *what* to hide. This decides *what goes in its place*, and it
is set per entity under **Entities → Model sees**, or per pattern in the editor.

| Style | Model sees | The model can | Use for |
|---|---|---|---|
| `tag` | `<PERSON_1>` | tell values apart, refer to them | names, addresses, organisations |
| `surrogate` | `KHZKQ0604D` | examine the format, count characters | national IDs, cards, phones, any structured identifier |
| `last4` | `••••••3210` | nothing useful; a human can recognise the record | phone and card in replies people read |

The rule of thumb: **is the value the subject of the question, or just context?**
"Summarise this ticket about Priya, PAN ABGPP3432K" only needs a tag. "Is this
PAN valid" needs a lookalike, because a tag gives the model nothing to inspect —
it will invent an answer.

### Shapes

A lookalike is generated from a shape, which is the format written out:

| Token | Means |
|---|---|
| `A` | an upper-case letter |
| `a` | a lower-case letter |
| `9` | a digit |
| `?` | a letter or a digit |
| `[2-9]` | an explicit set, for positions the format constrains |
| `{19}` | literal text |

`AAAAA9999A` is a PAN. `[2-9]999 9999 9999` is an Aadhaar — the class matters,
because an Aadhaar never starts with 0 or 1. `aaaaaaaa{@okhdfcbank}` is a UPI
handle; without the braces the bank name would be rewritten letter by letter,
since every `a` in it looks like a slot. The same trap catches literal digits:
write `{19}` for a century, not `19`.

**From example** in the editor reads a shape off a sample, so you can paste
`ABCPE1234F` and get `AAAAA9999A` rather than hand-writing it.

### What makes a lookalike safe

- **Keyed per request.** The same real value gets a different lookalike in the
  next request, so lookalikes cannot be used to correlate requests. Within a
  request the mapping is stable, which is what the model needs.
- **Checksums are broken on purpose.** Where a format carries one — Aadhaar's
  Verhoeff digit, Luhn on cards, mod-11 on NHS numbers, the ABA weights — the
  lookalike is generated to fail it. It is the right shape and cannot be
  anybody's real number.
- **Reserved ranges where they exist.** IP lookalikes land in `203.0.113.0/24`,
  which RFC 5737 reserves for documentation. MAC lookalikes set the
  locally-administered bit.
- **Never collides.** A lookalike is checked against every other value in the
  request and every lookalike already issued. If a shape is too small to give
  everyone a distinct value, the remainder fall back to name tags rather than
  two records quietly sharing one.

### The honest limits

- **Formats without a checksum carry residual risk.** PAN and IFSC have no check
  digit, so a well-formed lookalike could in principle be somebody's real one.
  Nothing in the design removes this; it is the price of the model being able to
  examine the value at all.
- **Transformations do not survive.** Ask the model to "fix the fourth
  character" and it fixes the lookalike. You get something safe but not useful.
  No masking scheme solves that.
- **Errors are harder to spot.** A wrong tag is obvious; a wrong lookalike looks
  like data. The stand-in table in the Playground and the request inspector is
  where you check.

## Writing a pattern

1. **Patterns** → *Add a pattern*, or *Generate with AI* to draft one from a
   description.
2. Give it an `UPPER_SNAKE_CASE` entity name.
3. Write the regex. Anchor with `\b`. Nested quantifiers like `(a+)+` are
   rejected — they let a crafted input hang the process.
4. Pick a score: 0.8 for a distinctive shape, 0.5 moderate, 0.2 for bare digits
   that need context to be believable.
5. Add context words.
6. Choose what the model sees instead, and preview it on a couple of fake
   examples before saving.
6. Watch the live tester. Green passed the check; red struck through means the
   pattern matched but the check rejected it.

Saves are transactional: a broken pattern is refused and the previous version
restored, so the running engine never goes down.

## Tuning

| Symptom | Fix |
|---|---|
| Harmless text masked | Raise the threshold, or disable that entity |
| Identifiers slipping through | Lower the threshold, add context words |
| Two patterns fighting | Give the more specific one a validator and a higher score |
| Field labels masked | Turn off `ORGANIZATION` |
| Every timestamp masked | Turn off `DATE_TIME` |
| Latency too high | Turn the detection model off per endpoint |

## Known gaps

- **Images are not scanned.** Text in a screenshot passes through.
- **`A/c 50100234567890` is missed.** spaCy splits `A/c` into separate tokens so
  it never matches as a context word. `account number 50100234567890` works.
- **Free-text addresses** depend entirely on the detection model.
- **Non-English text** is untested. The engine is configured for English only.
