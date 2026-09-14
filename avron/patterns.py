"""Seed detection patterns and validators, grouped into regional packs.

These are inserted into the `patterns` table on first boot and are editable from
the console afterwards. Editing this file has no effect on an existing database.

Packs let one deployment run a single region's rules without carrying every
other region's false positives. Add a pack by appending a list here and an entry
to PACKS; nothing else needs to change.

A validator is a named function that can reject a regex match. Regex gives
recall; the validator kills false positives no pattern can exclude.
"""

import re
from typing import Callable, Dict

# ----------------------------------------------- checksums and validators
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _digits(text: str) -> str:
    return "".join(ch for ch in text if ch.isdigit())


def verhoeff(text: str) -> bool:
    d = _digits(text)
    if len(d) != 12 or len(set(d)) <= 2:
        return False
    c = 0
    for i, item in enumerate(reversed(d)):
        c = _D[c][_P[i % 8][int(item)]]
    return c == 0


def luhn(text: str) -> bool:
    d = _digits(text)
    if len(d) < 12:
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


def luhn9(text: str) -> bool:
    """Luhn over exactly 9 digits. The general luhn() requires 12+ because it
    is aimed at card and account numbers; a Canadian SIN is 9."""
    d = _digits(text)
    if len(d) != 9 or len(set(d)) <= 2:
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


def phone_len(text: str) -> bool:
    return len(_digits(text)) in (10, 11, 12)


def not_repdigit(text: str) -> bool:
    d = _digits(text)
    return len(set(d)) > 2 if d else True


def bank_not_mobile(text: str) -> bool:
    """Reject anything shaped like an Indian mobile number.

    A bare 10-digit string starting 6-9 is overwhelmingly a phone, not an
    account number, and without this the two recognizers fight over every
    contact number in a ticket. Paired with the India pack.
    """
    d = _digits(text)
    if len(d) < 9 or len(set(d)) <= 2:
        return False
    if len(d) == 10 and d[0] in "6789":
        return False
    return True


def nhs_mod11(text: str) -> bool:
    """NHS number check digit, weights 10..2 with an 11-modulus."""
    d = _digits(text)
    if len(d) != 10 or len(set(d)) <= 2:
        return False
    total = sum(int(d[i]) * (10 - i) for i in range(9))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == int(d[9])


def aba_routing(text: str) -> bool:
    """US routing number, 3-7-1 weighted checksum."""
    d = _digits(text)
    if len(d) != 9 or len(set(d)) <= 2:
        return False
    w = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    return sum(int(a) * b for a, b in zip(d, w)) % 10 == 0


def us_ssn(text: str) -> bool:
    """Rejects the ranges the SSA never issues."""
    d = _digits(text)
    if len(d) != 9 or len(set(d)) <= 2:
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    if area in ("000", "666") or area[0] == "9":
        return False
    return group != "00" and serial != "0000"


def ipv4_octets(text: str) -> bool:
    """Every octet 0-255. Without this, version strings and dates match."""
    parts = text.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    # Leading zeros mean it is almost certainly not an address.
    if any(len(p) > 1 and p[0] == "0" for p in parts):
        return False
    # 0.0.0.0 and 255.255.255.255 are not identifying.
    if all(n == 0 for n in nums) or all(n == 255 for n in nums):
        return False
    return True


def public_ipv4(text: str) -> bool:
    """IPv4 that is not loopback, link-local, private or documentation.

    Use this when you want to mask who connected from outside but keep
    10.x and 192.168.x readable for debugging.
    """
    if not ipv4_octets(text):
        return False
    a, b = (int(x) for x in text.split(".")[:2])
    if a == 10 or a == 127 or a == 0:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:  # CGNAT, includes Tailscale
        return False
    return True


VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "none": lambda _: True,
    "verhoeff": verhoeff,
    "luhn": luhn,
    "luhn9": luhn9,
    "phone_len": phone_len,
    "not_repdigit": not_repdigit,
    "bank_not_mobile": bank_not_mobile,
    "nhs_mod11": nhs_mod11,
    "aba_routing": aba_routing,
    "us_ssn": us_ssn,
    "ipv4_octets": ipv4_octets,
    "public_ipv4": public_ipv4,
}

VALIDATOR_HELP = {
    "none": "Accept every regex match.",
    "verhoeff": "Aadhaar checksum. Rejects invalid 12-digit numbers.",
    "luhn": "Card / account checksum, 12 digits or more.",
    "luhn9": "Luhn checksum over exactly 9 digits.",
    "phone_len": "Digit count must be 10, 11 or 12.",
    "not_repdigit": "Reject numbers made of one or two repeating digits.",
    "bank_not_mobile": "Account number, but not a 10-digit mobile number.",
    "nhs_mod11": "NHS number check digit.",
    "aba_routing": "US routing number checksum.",
    "us_ssn": "Valid SSN ranges only. Rejects 000, 666 and 9xx areas.",
    "ipv4_octets": "Every octet 0-255. Rejects version numbers and dates.",
    "public_ipv4": "Valid IPv4, excluding private, loopback and CGNAT ranges.",
}

# ================================================================== packs
INDIA_PATTERNS = [
    {"entity": "IN_AADHAAR", "name": "Aadhaar (spaced)", "score": 0.5,
     "regex": r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b", "validator": "verhoeff",
     "context": ["aadhaar", "aadhar", "uid", "uidai"]},
    {"entity": "IN_AADHAAR", "name": "Aadhaar (dashed)", "score": 0.5,
     "regex": r"\b[2-9]\d{3}-\d{4}-\d{4}\b", "validator": "verhoeff",
     "context": ["aadhaar", "aadhar", "uid", "uidai"]},
    {"entity": "IN_AADHAAR", "name": "Aadhaar (plain)", "score": 0.3,
     "regex": r"\b[2-9]\d{11}\b", "validator": "verhoeff",
     "context": ["aadhaar", "aadhar", "uid", "uidai"]},
    {"entity": "IN_PAN", "name": "PAN", "score": 0.7,
     "regex": r"\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b", "validator": "none",
     "context": ["pan", "permanent account number", "income tax", "itr"]},
    {"entity": "IN_GSTIN", "name": "GSTIN", "score": 0.8,
     "regex": r"\b[0-3][0-9][A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
     "validator": "none", "context": ["gst", "gstin", "invoice", "supplier"]},
    {"entity": "IN_PHONE_NUMBER", "name": "Mobile", "score": 0.75,
     "regex": r"(?:\+91[\-\s]?|0)?[6-9]\d{4}[\-\s]?\d{5}\b",
     "validator": "phone_len",
     "context": ["mobile", "phone", "contact", "whatsapp", "call", "otp"]},
    {"entity": "IN_IFSC", "name": "IFSC", "score": 0.75,
     "regex": r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "validator": "none",
     "context": ["ifsc", "bank", "branch", "neft", "rtgs", "imps"]},
    {"entity": "IN_BANK_ACCOUNT", "name": "Bank account", "score": 0.15,
     "regex": r"\b\d{9,18}\b", "validator": "bank_not_mobile",
     "context": ["account", "a/c", "acct", "bank", "savings", "beneficiary",
                 "ifsc", "neft", "imps", "rtgs", "branch", "payee"]},
    {"entity": "IN_UPI_ID", "name": "UPI VPA", "score": 0.85,
     "regex": r"\b[\w.\-]{2,64}@(?:okhdfcbank|okicici|oksbi|okaxis|ybl|paytm|apl|upi|ibl|axl|hdfcbank|icici|sbi|axisbank|federal)\b",
     "validator": "none", "context": ["upi", "vpa", "gpay", "phonepe", "paytm"]},
    {"entity": "IN_VOTER_ID", "name": "EPIC", "score": 0.5,
     "regex": r"\b[A-Z]{3}\d{7}\b", "validator": "none",
     "context": ["voter", "epic", "election", "electoral", "eci"]},
    {"entity": "IN_PASSPORT", "name": "Passport", "score": 0.5,
     "regex": r"\b[A-PR-WYZ][1-9]\d\s?\d{4}[1-9]\b", "validator": "none",
     "context": ["passport", "visa", "immigration"]},
    {"entity": "IN_DRIVING_LICENCE", "name": "Driving licence", "score": 0.7,
     "regex": r"\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19|20)\d{2}[-\s]?\d{7}\b",
     "validator": "none", "context": ["driving", "licence", "license", "rto"]},
    {"entity": "IN_VEHICLE_REGISTRATION", "name": "Vehicle number", "score": 0.6,
     "regex": r"\b[A-Z]{2}[-\s]?\d{1,2}[-\s]?[A-Z]{1,3}[-\s]?\d{4}\b",
     "validator": "none", "context": ["vehicle", "car", "registration", "rc"]},
    # --- network identifiers -----------------------------------------
    {"entity": "IP_ADDRESS", "name": "IPv4", "score": 0.6,
     "regex": r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "validator": "ipv4_octets",
     "context": ["ip", "address", "host", "client", "server", "remote",
                 "source", "src", "dest", "gateway", "login", "session"]},
    {"entity": "IP_ADDRESS", "name": "IPv4 with port", "score": 0.7,
     "regex": r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b", "validator": "none",
     "context": ["ip", "address", "host", "endpoint", "connection"]},
    {"entity": "IP_ADDRESS", "name": "IPv4 CIDR", "score": 0.7,
     "regex": r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", "validator": "none",
     "context": ["subnet", "cidr", "network", "range", "mask"]},
    {"entity": "IP_ADDRESS", "name": "IPv6", "score": 0.7,
     "regex": r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})\b",
     "validator": "none",
     "context": ["ip", "ipv6", "address", "host", "client", "remote"]},
    {"entity": "MAC_ADDRESS", "name": "MAC address", "score": 0.8,
     "regex": r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b",
     "validator": "none",
     "context": ["mac", "hardware", "device", "adapter", "nic", "bssid"]},
    {"entity": "IN_PINCODE", "name": "PIN code", "score": 0.2,
     "regex": r"\b[1-9]\d{5}\b", "validator": "none",
     "context": ["pin", "pincode", "postal", "address", "district"]},
]

# Each pack toggles as a group. A deployment in one region should not carry
# another region's false positives, so only the packs in DEFAULT_PACKS start
# enabled. Everything else is one switch away in the console.

US_PATTERNS = [
    {"entity": "US_SSN", "name": "Social Security number", "score": 0.7,
     "regex": r"\b\d{3}[- ]\d{2}[- ]\d{4}\b", "validator": "us_ssn",
     "context": ["ssn", "social security", "taxpayer", "tin"]},
    {"entity": "US_EIN", "name": "Employer ID number", "score": 0.55,
     "regex": r"\b\d{2}-\d{7}\b", "validator": "none",
     "context": ["ein", "employer identification", "tax id", "irs"]},
    {"entity": "US_ROUTING", "name": "ABA routing number", "score": 0.35,
     "regex": r"\b\d{9}\b", "validator": "aba_routing",
     "context": ["routing", "aba", "wire", "ach", "bank"]},
    {"entity": "US_ZIP", "name": "ZIP code", "score": 0.2,
     "regex": r"\b\d{5}(?:-\d{4})?\b", "validator": "none",
     "context": ["zip", "postal", "address", "city", "state"]},
]

UK_PATTERNS = [
    {"entity": "UK_NINO", "name": "National Insurance number", "score": 0.8,
     "regex": r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
     "validator": "none",
     "context": ["national insurance", "nino", "ni number", "hmrc"]},
    {"entity": "UK_NHS", "name": "NHS number", "score": 0.3,
     "regex": r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b", "validator": "nhs_mod11",
     "context": ["nhs", "patient", "health", "gp"]},
    {"entity": "UK_SORT_CODE", "name": "Sort code", "score": 0.6,
     "regex": r"\b\d{2}-\d{2}-\d{2}\b", "validator": "none",
     "context": ["sort code", "bank", "account", "branch"]},
    {"entity": "UK_POSTCODE", "name": "Postcode", "score": 0.5,
     "regex": r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b", "validator": "none",
     "context": ["postcode", "address", "post code", "delivery"]},
]

EU_PATTERNS = [
    {"entity": "EU_VAT", "name": "VAT number", "score": 0.65,
     "regex": r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[0-9A-Z]{8,12}\b",
     "validator": "none", "context": ["vat", "tax", "invoice", "ust", "tva"]},
    {"entity": "EU_NATIONAL_ID", "name": "German tax ID", "score": 0.25,
     "regex": r"\b\d{11}\b", "validator": "not_repdigit",
     "context": ["steuer", "tax id", "identifikationsnummer", "national id"]},
]

APAC_PATTERNS = [
    {"entity": "SG_NRIC", "name": "Singapore NRIC / FIN", "score": 0.8,
     "regex": r"\b[STFGM]\d{7}[A-Z]\b", "validator": "none",
     "context": ["nric", "fin", "identity card", "singapore"]},
    {"entity": "AU_TFN", "name": "Australian tax file number", "score": 0.2,
     "regex": r"\b\d{3}\s?\d{3}\s?\d{3}\b", "validator": "not_repdigit",
     "context": ["tfn", "tax file", "ato", "australian"]},
    {"entity": "AU_ABN", "name": "Australian business number", "score": 0.25,
     "regex": r"\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b", "validator": "not_repdigit",
     "context": ["abn", "business number", "ato", "gst"]},
    {"entity": "CA_SIN", "name": "Canadian social insurance number", "score": 0.3,
     "regex": r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b", "validator": "luhn9",
     "context": ["sin", "social insurance", "cra", "canadian"]},
]

GLOBAL_PATTERNS = [
    {"entity": "DATE_OF_BIRTH", "name": "Date of birth", "score": 0.45,
     "regex": r"\b(?:0?[1-9]|[12]\d|3[01])[/.-](?:0?[1-9]|1[0-2])[/.-](?:19|20)\d{2}\b",
     "validator": "none",
     "context": ["dob", "born", "birth", "date of birth", "birthday", "age"]},
    {"entity": "PASSPORT", "name": "Passport (generic)", "score": 0.3,
     "regex": r"\b[A-Z]{1,2}\d{6,8}\b", "validator": "none",
     "context": ["passport", "travel document", "visa", "immigration"]},
    {"entity": "SWIFT_BIC", "name": "SWIFT / BIC", "score": 0.6,
     "regex": r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
     "validator": "none",
     "context": ["swift", "bic", "wire", "international", "transfer"]},
]

# Packs enabled on a fresh install. Regional defaults are a judgement call
# rather than a neutral one; change this list to match where your data is from.
DEFAULT_PACKS = {"india", "network"}

# pack key -> (label, description, patterns, on by default)
PACKS = {
    "india": ("India", "Aadhaar, PAN, GSTIN, UPI, IFSC and the rest.",
              INDIA_PATTERNS, "india" in DEFAULT_PACKS),
    "network": ("Network", "IP addresses and MAC addresses.",
                [], True),  # filled below from the India list split
    "us": ("United States", "SSN, EIN, routing numbers, ZIP.", US_PATTERNS, "us" in DEFAULT_PACKS),
    "uk": ("United Kingdom", "NINO, NHS number, sort code, postcode.",
           UK_PATTERNS, "uk" in DEFAULT_PACKS),
    "eu": ("European Union", "VAT and national tax identifiers.", EU_PATTERNS, "eu" in DEFAULT_PACKS),
    "apac": ("Asia-Pacific", "Singapore NRIC, Australian TFN/ABN, Canadian SIN.",
             APAC_PATTERNS, "apac" in DEFAULT_PACKS),
    "global": ("Global", "Dates of birth, generic passports, SWIFT codes.",
               GLOBAL_PATTERNS, "global" in DEFAULT_PACKS),
}

# Network identifiers were defined alongside the India list; split them out so
# they can be toggled independently of any region.
_NETWORK_ENTITIES = {"IP_ADDRESS", "MAC_ADDRESS"}
PACKS["network"] = (
    PACKS["network"][0], PACKS["network"][1],
    [p for p in INDIA_PATTERNS if p["entity"] in _NETWORK_ENTITIES], True,
)
INDIA_PATTERNS = [p for p in INDIA_PATTERNS if p["entity"] not in _NETWORK_ENTITIES]
PACKS["india"] = (PACKS["india"][0], PACKS["india"][1], INDIA_PATTERNS, True)

SEED_PATTERNS = []
for _key, (_label, _desc, _pats, _on) in PACKS.items():
    for _p in _pats:
        SEED_PATTERNS.append({**_p, "pack": _key, "pack_default_on": _on})

# Presidio loads its own US and UK recognizers for English no matter what we
# configure, so those entities have to be gated by pack too. Otherwise turning
# the UK pack off still leaves NhsRecognizer matching any ten-digit number.
PACK_BUILTIN_ENTITIES = {
    "us": {"US_SSN", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN",
           "US_PASSPORT"},
    "uk": {"UK_NHS", "UK_NINO"},
    "eu": {"ES_NIF", "ES_NIE", "IT_DRIVER_LICENSE", "IT_FISCAL_CODE",
           "IT_VAT_CODE", "IT_IDENTITY_CARD", "IT_PASSPORT", "PL_PESEL"},
    "apac": {"AU_ABN", "AU_ACN", "AU_TFN", "AU_MEDICARE", "SG_NRIC_FIN",
             "IN_PAN_BUILTIN"},
    "global": {"MEDICAL_LICENSE"},
}


def pack_entities(pack_key: str) -> set:
    """Every entity a pack owns: its own patterns plus Presidio's built-ins."""
    own = {p["entity"] for p in PACKS.get(pack_key, (None, None, [], None))[2]}
    return own | PACK_BUILTIN_ENTITIES.get(pack_key, set())


ENTITY_PACK = {}
for _k in PACKS:
    for _e in pack_entities(_k):
        ENTITY_PACK.setdefault(_e, _k)

PACK_INFO = [
    {"key": k, "label": v[0], "description": v[1], "patterns": len(v[2]),
     "default_on": v[3]}
    for k, v in PACKS.items()
]

SEED_ENTITIES = sorted({p["entity"] for p in SEED_PATTERNS})

PRESIDIO_ENTITIES = [
    "EMAIL_ADDRESS", "CREDIT_CARD", "IP_ADDRESS", "MAC_ADDRESS", "PERSON",
    "LOCATION", "DATE_TIME", "URL", "IBAN_CODE", "NRP", "CRYPTO",
    "MEDICAL_LICENSE", "US_SSN", "US_BANK_NUMBER", "US_DRIVER_LICENSE",
    "US_ITIN", "US_PASSPORT", "UK_NHS", "UK_NINO",
]

LLM_ONLY_ENTITIES = [
    "IN_ADDRESS", "IN_RELIGION_CASTE", "MEDICAL_CONDITION", "ORGANIZATION",
]

# ORGANIZATION is deliberately not on by default: models label field names
# like "PAN" and "IFSC" as organisations, which masks the word rather than
# the value and makes the prompt unreadable.
DEFAULT_LLM_ENTITIES = ["PERSON", "IN_ADDRESS", "IN_RELIGION_CASTE",
                        "MEDICAL_CONDITION"]

# Detected but not masked unless you ask. ORGANIZATION catches field labels;
# DATE_TIME catches every timestamp in a log line and breaks scheduling.
OFF_BY_DEFAULT = {"ORGANIZATION", "DATE_TIME"}

ALL_ENTITIES = sorted(set(SEED_ENTITIES + PRESIDIO_ENTITIES + LLM_ONLY_ENTITIES))

# Nested quantifiers can hang the process on a crafted input. Rejected on save.
_DANGEROUS = re.compile(r"\([^)]*[+*]\)[+*]")


def regex_problem(pattern: str) -> str:
    """Return an error string, or '' if the pattern is safe to compile."""
    if len(pattern) > 500:
        return "Pattern is too long (max 500 characters)."
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"Invalid regex: {exc}"
    if _DANGEROUS.search(pattern):
        return "Nested quantifier detected - risks catastrophic backtracking."
    return ""
