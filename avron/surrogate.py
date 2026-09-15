"""Format-preserving surrogates.

A name tag like <IN_PAN_1> tells a model nothing about the value, so it cannot
answer "is this a valid PAN" or "what is wrong with the fourth character". A
surrogate is a fake value with the same shape — QWXYZ8871M for a PAN — which
the model can examine and reason about while the real value never leaves.

Three properties matter, in this order:

1. **Never emit a real value.** Where a format carries a checksum the surrogate
   is generated to FAIL it, so it is structurally valid and cannot belong to
   anybody. Formats without a checksum (PAN, IFSC) carry residual risk that no
   amount of care removes; that is documented, not hidden.
2. **Stable within a request.** The same real value must map to the same
   surrogate every time it appears, or the model sees two different people.
3. **Unpredictable across requests.** Derivation is keyed by a per-request
   salt, so a surrogate cannot be used to correlate one request with another.
"""

import hashlib
import hmac
import os
import re
import secrets
from typing import Dict, Optional, Tuple

# Shape alphabet. Anything else in a shape is a literal.
#   A       an upper-case letter
#   a       a lower-case letter
#   9       a digit
#   ?       a letter or a digit
#   [2-9]   an explicit set, for formats that constrain a position
#   {text}  literal text, for anything containing A, a, 9 or ? that must
#           survive as written - a domain, a year prefix, a bank handle
#   \a      a single escaped literal
#
# The literal form is not decoration. Without it "aaaa@okhdfcbank" would have
# the bank name rewritten letter by letter, because every "a" in it looks like
# a slot.
#
# The bracket form exists because real formats do: an Aadhaar never starts
# with 0 or 1, an Indian mobile never starts below 6. A surrogate that broke
# those rules would be the wrong shape, which defeats the point.
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
ALNUM = LETTERS + DIGITS

SLOTS = {
    "A": LETTERS,
    "a": LOWER,
    "9": DIGITS,
    "?": ALNUM,
}

MAX_SHAPE = 128
CLASS_RE = re.compile(r"\[([^\]]{1,40})\]")
LITERAL_RE = re.compile(r"\{([^}]{0,80})\}")


def _expand_class(spec: str) -> str:
    """Turn '2-9' or 'ABX' into the characters it allows."""
    out = []
    i = 0
    while i < len(spec):
        if i + 2 < len(spec) and spec[i + 1] == "-":
            lo, hi = spec[i], spec[i + 2]
            if ord(lo) <= ord(hi):
                out.extend(chr(c) for c in range(ord(lo), ord(hi) + 1))
            i += 3
        else:
            out.append(spec[i])
            i += 1
    return "".join(dict.fromkeys(out))


def parse_shape(shape: str):
    """Compile a shape into a list of slots.

    Each entry is either a literal string or a string of allowed characters
    for one varying position.
    """
    slots = []
    i = 0
    while i < len(shape):
        if shape[i] == "\\" and i + 1 < len(shape):
            slots.append(("lit", shape[i + 1]))
            i += 2
            continue
        m = LITERAL_RE.match(shape, i)
        if m:
            slots.append(("lit", m.group(1)))
            i = m.end()
            continue
        m = CLASS_RE.match(shape, i)
        if m:
            allowed = _expand_class(m.group(1))
            slots.append(("var", allowed or "0"))
            i = m.end()
            continue
        ch = shape[i]
        if ch in SLOTS:
            slots.append(("var", SLOTS[ch]))
        else:
            slots.append(("lit", ch))
        i += 1
    return slots

# Shapes the built-in packs use. A pattern can override with its own.
DEFAULT_SHAPES = {
    "IN_PAN": "AAAAA9999A",
    "IN_AADHAAR": "[2-9]999 9999 9999",
    "IN_GSTIN": "[0-3][1-7]AAAAA9999A[1-9]{Z}[0-9]",
    "IN_PHONE_NUMBER": "[6-9]999999999",
    "IN_IFSC": "AAAA0999999",
    "IN_BANK_ACCOUNT": "999999999999",
    "IN_UPI_ID": "aaaaaaaa{@okhdfcbank}",
    "IN_VOTER_ID": "AAA9999999",
    "IN_PASSPORT": "A9999999",
    "IN_DRIVING_LICENCE": "AA[0-3][1-9] {19}[5-9][0-9]9999999",
    "IN_VEHICLE_REGISTRATION": "AA[0-3][1-9]AA[1-9]999",
    "IN_PINCODE": "[1-9]99999",
    "US_SSN": "[1-8]99-99-9999",
    "US_EIN": "99-9999999",
    "US_ROUTING": "999999999",
    "US_ZIP": "99999",
    "UK_NINO": "[A-CEGHJ-PR-TW-Z][A-CEGHJ-PR-TW-Z]999999[A-D]",
    "UK_NHS": "999 999 9999",
    "UK_SORT_CODE": "99-99-99",
    "UK_POSTCODE": "AA[1-9] [1-9][A-HJ-NP-UW-Z][A-HJ-NP-UW-Z]",
    "EU_VAT": "AA999999999",
    "SG_NRIC": "[STFG]9999999A",
    "AU_TFN": "999 999 999",
    "AU_ABN": "99 999 999 999",
    "CA_SIN": "999 999 999",
    "CREDIT_CARD": "4999 9999 9999 9999",
    # RFC 5737 reserves this block for documentation, so a surrogate here
    # can never be a routable host. Only 254 values exist; see shape_warning.
    "IP_ADDRESS": "{203.0.113.}[1-9][0-9]",
    # Locally-administered bit set, so it cannot be a manufacturer address.
    "MAC_ADDRESS": "{02:}[0-9A-F][0-9A-F]{:}[0-9A-F][0-9A-F]{:}[0-9A-F][0-9A-F]{:}[0-9A-F][0-9A-F]{:}[0-9A-F][0-9A-F]",
    "EMAIL_ADDRESS": "aaaaaaaa{@example.com}",
    # {19} not 19: a bare 9 is a slot, so the century would be randomised.
    "DATE_OF_BIRTH": "[0-2][1-8]/0[1-9]/{19}[5-9][0-9]",
    "SWIFT_BIC": "AAAAAA99",
}

# Entities whose surrogate must fail a checksum so it can never be a real
# number. Keyed to the check the detection side uses.
CHECKSUMMED = {
    "IN_AADHAAR": "verhoeff",
    "CREDIT_CARD": "luhn",
    "UK_NHS": "nhs",
    "CA_SIN": "luhn9",
    "US_ROUTING": "aba",
}


def shape_problem(shape: str) -> str:
    """Validate a shape before it is saved. Returns '' when it is usable."""
    if not shape or not shape.strip():
        return "A shape is required when you choose a lookalike."
    if len(shape) > MAX_SHAPE:
        return f"A shape cannot be longer than {MAX_SHAPE} characters."
    if shape.count("[") != shape.count("]"):
        return "Unbalanced [ ] in the shape."
    if shape.count("{") != shape.count("}"):
        return "Unbalanced { } in the shape."
    try:
        slots = parse_shape(shape)
    except Exception:  # noqa: BLE001
        return "That shape could not be read."
    varying = [a for kind, a in slots if kind == "var"]
    if not varying:
        return "A shape needs at least one A, a, 9, ? or [set] to vary."
    return ""


def shape_space(shape: str) -> int:
    """How many different values a shape can produce, capped.

    A small space is not an error. An IPv4 documentation range holds 254
    addresses and that is simply the truth about IPv4; refusing the shape
    would be worse than living with it, because the factory falls back to a
    name tag when it runs out. The number is surfaced as a warning so the
    trade-off is visible rather than silent.
    """
    try:
        slots = parse_shape(shape)
    except Exception:  # noqa: BLE001
        return 0
    space = 1
    for kind, value in slots:
        if kind == "var":
            space *= max(1, len(value))
            if space > 1_000_000:
                return 1_000_000
    return space


def shape_warning(shape: str) -> str:
    """Advisory shown next to a shape. Never blocks a save."""
    space = shape_space(shape)
    if space < 100:
        return (f"Only about {space} different values are possible, so "
                "distinct records will end up sharing one. Add varying "
                "positions if the format allows it.")
    if space < 10_000:
        return (f"About {space} different values are possible. Fine for a few "
                "values per request, tight for large documents.")
    return ""


def _escape_literal(text: str) -> str:
    """Wrap literal text so slot characters inside it are not substituted."""
    return "{" + text.replace("}", "") + "}" if text else ""


def infer_shape(sample: str) -> str:
    """Turn a real-looking example into a shape.

    Used by the editor's "learn from example" so nobody has to hand-write
    AAAAA9999A while looking at ABCPE1234F.
    """
    sample = (sample or "")[:MAX_SHAPE]
    head, sep, tail = sample.partition("@")
    # Everything after an @ is a domain or a handle: a real thing that must
    # survive intact, not a pattern of letters to reshuffle.
    body = head if sep else sample
    out = []
    for ch in body:
        if ch.isdigit():
            out.append("9")
        elif ch.isupper():
            out.append("A")
        elif ch.islower():
            out.append("a")
        else:
            out.append(ch)
    if sep:
        out.append(_escape_literal("@" + tail))
    return "".join(out)


# ------------------------------------------------------------- checksums
def _digits(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


_VD = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VP = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _passes(kind: str, value: str) -> bool:
    """Does this value pass the named checksum? Used to force a failure."""
    d = _digits(value)
    if kind == "verhoeff":
        if len(d) != 12:
            return False
        c = 0
        for i, ch in enumerate(reversed(d)):
            c = _VD[c][_VP[i % 8][int(ch)]]
        return c == 0
    if kind in ("luhn", "luhn9"):
        if not d:
            return False
        total, alt = 0, False
        for ch in reversed(d):
            n = int(ch)
            if alt:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
            alt = not alt
        return total % 10 == 0
    if kind == "nhs":
        if len(d) != 10:
            return False
        total = sum(int(d[i]) * (10 - i) for i in range(9))
        check = 11 - (total % 11)
        if check == 11:
            check = 0
        return check != 10 and check == int(d[9])
    if kind == "aba":
        if len(d) != 9:
            return False
        w = [3, 7, 1, 3, 7, 1, 3, 7, 1]
        return sum(int(a) * b for a, b in zip(d, w)) % 10 == 0
    return False


def _break_checksum(value: str, kind: str) -> str:
    """Nudge the last digit until the checksum fails.

    A surrogate that happens to be checksum-valid could be a real person's
    number. Ten candidates always contain at least one failure, because only
    one residue can be correct.
    """
    positions = [i for i, ch in enumerate(value) if ch.isdigit()]
    if not positions:
        return value
    last = positions[-1]
    for bump in range(10):
        candidate = (
            value[:last]
            + str((int(value[last]) + bump) % 10)
            + value[last + 1 :]
        )
        if not _passes(kind, candidate):
            return candidate
    return value


# ------------------------------------------------------------ generation
class SurrogateFactory:
    """Generates surrogates for one request.

    A fresh random salt per instance means the same real value gets a
    different surrogate in a different request, so surrogates cannot be used
    to link one request to another. Within the instance the mapping is stable.
    """

    def __init__(self, salt: Optional[bytes] = None) -> None:
        self.salt = salt or secrets.token_bytes(32)
        self._used: Dict[str, str] = {}   # surrogate -> real
        self._made: Dict[Tuple[str, str], str] = {}  # (entity, real) -> surrogate

    def _stream(self, entity: str, real: str, counter: int) -> bytes:
        msg = f"{entity}\x00{real}\x00{counter}".encode()
        out = b""
        block = 0
        while len(out) < MAX_SHAPE:
            out += hmac.new(self.salt, msg + bytes([block]), hashlib.sha256).digest()
            block += 1
        return out

    def _fill(self, shape: str, stream: bytes) -> str:
        out = []
        i = 0
        for kind, value in parse_shape(shape):
            if kind == "lit":
                out.append(value)
                continue
            # Modulo bias over a 26 or 10 character alphabet is irrelevant
            # here: a surrogate is a stand-in, not a secret.
            out.append(value[stream[i % len(stream)] % len(value)])
            i += 1
        return "".join(out)

    def make(self, entity: str, real: str, shape: Optional[str] = None,
             avoid=()) -> str:
        """Return a stable surrogate for `real`.

        `avoid` is the set of real values present in this text, so a surrogate
        can never collide with something the model is also being shown.
        """
        key = (entity, real)
        if key in self._made:
            return self._made[key]

        shape = shape or DEFAULT_SHAPES.get(entity) or infer_shape(real)
        if shape_problem(shape):
            shape = infer_shape(real) or "AAAAAAAA"
        checksum = CHECKSUMMED.get(entity)

        for counter in range(64):
            candidate = self._fill(shape, self._stream(entity, real, counter))
            if checksum:
                candidate = _break_checksum(candidate, checksum)
            if candidate == real or candidate in avoid:
                continue
            owner = self._used.get(candidate)
            if owner is not None and owner != real:
                continue          # already stands for a different value
            self._used[candidate] = real
            self._made[key] = candidate
            return candidate

        # 64 collisions is not luck, it is a shape with almost no variation
        # (something like "AA"). Fall back to a tag rather than return a
        # surrogate that means two things at once.
        fallback = f"<{entity}_{len(self._made) + 1}>"
        self._made[key] = fallback
        self._used[fallback] = real
        return fallback


# ---------------------------------------------------------------- last 4
def last_four(value: str, keep: int = 4, char: str = "\u2022") -> str:
    """Mask everything but the tail, preserving separators so it still reads
    like the original: 9876543210 -> ••••••3210."""
    keepable = [i for i, ch in enumerate(value) if ch.isalnum()]
    show = set(keepable[-keep:]) if keep > 0 else set()
    return "".join(
        ch if (i in show or not ch.isalnum()) else char
        for i, ch in enumerate(value)
    )


STRATEGIES = {
    "tag": "Name tag — <PERSON_1>. The model refers to it but cannot inspect it.",
    "surrogate": "Lookalike — a fake value with the same shape, so the model can examine it.",
    "last4": "Show last 4 — ••••••3210. Enough for a human to recognise.",
}
