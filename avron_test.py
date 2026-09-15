#!/usr/bin/env python3
"""Avron test harness.

Runs a corpus of cases against a live Avron and writes everything it saw to a
JSON file, plus a readable summary. Nothing outside the standard library, so it
runs on the box Avron is on without installing anything.

    python3 avron_test.py --base-url http://localhost:8080 --key avron-...

    # include a real model round trip (needs a working provider)
    python3 avron_test.py --base-url http://localhost:8080 --key avron-... \
        --chat --model gpt-4o-mini

    # only one group
    python3 avron_test.py --base-url ... --group false-positives

Every value in the corpus is synthetic. The PAN and Aadhaar numbers are
structurally valid so the checksums fire, but they are not anybody's.

Send the JSON file back for analysis. It contains the test inputs and Avron's
outputs — no real personal data, unless you add cases of your own.
"""

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ============================================================== the corpus
# expect: entity types that MUST be found
# forbid: entity types that must NOT be found anywhere in the text
# at:     exact substrings that must be detected, whatever the type
CASES = [
    # ---------------------------------------------------------- India
    dict(id="in-pan-1", group="india", text="PAN ABCPE1234F on file.",
         expect=["IN_PAN"], at=["ABCPE1234F"]),
    dict(id="in-pan-2", group="india",
         text="Two cards: ABGPP3432K and BZTPK5678L.",
         expect=["IN_PAN"], at=["ABGPP3432K", "BZTPK5678L"]),
    dict(id="in-pan-invalid", group="india",
         text="SSG3J3432K has a digit in the name block.",
         forbid=["IN_PAN"],
         note="4th-to-8th chars must be digits; this should not match"),
    dict(id="in-aadhaar-spaced", group="india",
         text="Aadhaar 3456 7890 1238 verified.",
         expect=["IN_AADHAAR"], at=["3456 7890 1238"]),
    dict(id="in-aadhaar-bad-checksum", group="india",
         text="Aadhaar 3456 7890 1239 verified.",
         forbid=["IN_AADHAAR"], note="Verhoeff must reject this"),
    dict(id="in-aadhaar-repdigit", group="india",
         text="Aadhaar 2222 2222 2222 on the form.",
         forbid=["IN_AADHAAR"], note="repeated digits are not an Aadhaar"),
    dict(id="in-phone", group="india",
         text="Call her on 9876543210 or +91 91234 56780.",
         expect=["IN_PHONE_NUMBER"]),
    dict(id="in-phone-vs-account", group="india",
         text="Mobile 9876543210, account number 50100234567890.",
         expect=["IN_PHONE_NUMBER", "IN_BANK_ACCOUNT"],
         note="the ten-digit number must be a phone, not an account"),
    dict(id="in-ifsc", group="india", text="IFSC HDFC0001234 branch Jayanagar.",
         expect=["IN_IFSC"], at=["HDFC0001234"]),
    dict(id="in-upi", group="india", text="Pay to priya@okhdfcbank today.",
         expect=["IN_UPI_ID"], at=["priya@okhdfcbank"]),
    dict(id="in-gstin", group="india", text="GSTIN 27ABCPE1234F1ZX for the invoice.",
         expect=["IN_GSTIN"]),
    dict(id="in-vehicle", group="india", text="Vehicle KA01AB1234 registered.",
         expect=["IN_VEHICLE_REGISTRATION"]),
    dict(id="in-voter", group="india", text="Voter ID ABC1234567 on the roll.",
         expect=["IN_VOTER_ID"]),
    dict(id="in-dl", group="india",
         text="Driving licence KA05 20119876543 expires soon.",
         expect=["IN_DRIVING_LICENCE"]),

    # --------------------------------------------------------- network
    dict(id="net-ipv4", group="network", text="Login came from 203.0.113.45.",
         expect=["IP_ADDRESS"], at=["203.0.113.45"]),
    dict(id="net-ipv4-private", group="network", text="Worker at 10.4.18.9 failed.",
         expect=["IP_ADDRESS"], at=["10.4.18.9"]),
    dict(id="net-ipv4-port", group="network", text="Endpoint 10.0.0.4:8080 is down.",
         expect=["IP_ADDRESS"]),
    dict(id="net-cidr", group="network", text="Subnet 172.16.0.0/12 reserved.",
         expect=["IP_ADDRESS"]),
    dict(id="net-mac", group="network", text="Device 00:1A:2B:3C:4D:5E joined.",
         expect=["MAC_ADDRESS"], at=["00:1A:2B:3C:4D:5E"]),
    dict(id="net-not-ip", group="network",
         text="Running version 2.2.364 build 1.0.7 today.",
         forbid=["IP_ADDRESS"],
         note="three-part version strings are not addresses"),
    dict(id="net-looks-like-ip", group="network",
         text="Semantic version 10.4.18.9 of the schema.",
         note="four dotted numbers are indistinguishable from an address; "
              "recorded to show the ambiguity rather than asserted either way"),
    dict(id="net-bad-octet", group="network", text="Value 999.1.1.1 is nonsense.",
         forbid=["IP_ADDRESS"], note="octets above 255"),

    # ------------------------------------------------------------ global
    dict(id="glob-email", group="global", text="Write to priya.r@example.com please.",
         expect=["EMAIL_ADDRESS"], at=["priya.r@example.com"]),
    dict(id="glob-card", group="global", text="Card 4111 1111 1111 1111 declined.",
         expect=["CREDIT_CARD"],
         note="passes Luhn; a card that fails it is correctly ignored"),
    dict(id="glob-card-bad-luhn", group="global",
         text="Card 4539 8821 0037 4418 declined.",
         forbid=["CREDIT_CARD"], note="fails Luhn, so it is not a card"),
    dict(id="glob-url", group="global", text="See https://example.com/report for detail.",
         expect=[], note="URL may or may not be enabled; recorded either way"),

    # ------------------------------------------------ other regions (off
    # by default; these should find nothing unless you enabled the pack)
    dict(id="us-ssn", group="regions-off", text="SSN 123-45-6789 on record.",
         note="expects nothing unless the US pack is on"),
    dict(id="uk-nino", group="regions-off", text="NINO AB123456C on record.",
         note="expects nothing unless the UK pack is on"),
    dict(id="sg-nric", group="regions-off", text="NRIC S1234567D on record.",
         note="expects nothing unless the APAC pack is on"),

    # -------------------------------------------------------- people
    dict(id="person-simple", group="people",
         text="Raised by Priya Raghunathan this morning.",
         expect=["PERSON"], llm=True),
    dict(id="person-three", group="people",
         text=("Priya Raghunathan escalated to Mohammed Ashraf, "
               "with Lakshmi Narayanan as joint holder."),
         expect=["PERSON"], llm=True,
         note="three distinct people must get three distinct stand-ins"),
    dict(id="person-address", group="people",
         text=("Lives at 12/3 Kalpana Nivas, 4th Cross, Jayanagar, "
               "Bengaluru 560041."),
         llm=True, note="free-text address; needs the detection model"),

    # ------------------------------------------------ false positives
    dict(id="fp-numbers", group="false-positives",
         text="Order 100000000, ticket 4471, total 999.99, build 021000022.",
         forbid=["IN_AADHAAR", "IN_PAN", "US_SSN"],
         note="ordinary numbers must survive untouched"),
    dict(id="fp-code", group="false-positives",
         text="Files: db.py, README.md, index.html, app.js in src/avron.",
         forbid=["URL", "EMAIL_ADDRESS"],
         note="filenames must not be read as domains"),
    dict(id="fp-dates", group="false-positives",
         text="Invoice dated 12/03/2024, due 2024-04-01.",
         forbid=["IN_AADHAAR", "IN_PHONE_NUMBER"]),
    dict(id="fp-filenames", group="false-positives",
         text="Edit db.py then README.md and rebuild src/avron/app.js.",
         forbid=["URL", "PERSON", "LOCATION"],
         note="file names must not be read as hosts or people"),
    dict(id="fp-real-url", group="false-positives",
         text="Docs are at https://example.com/guide and www.example.org.",
         expect=["URL"], note="real URLs must still be found"),
    dict(id="fp-prose", group="false-positives",
         text="Please check order 1 and item 2 in the list.",
         forbid=["IN_PAN", "IN_AADHAAR"],
         note="ordinary words that look like tags"),

    # ------------------------------------------------------- mixed
    dict(id="mix-ticket", group="mixed",
         text=("Ticket 4471 raised by Priya Raghunathan, PAN ABCPE1234F, "
               "Aadhaar 3456 7890 1238, mobile 9876543210, UPI "
               "priya@okhdfcbank, login from 203.0.113.45. Escalated to "
               "Mohammed Ashraf, PAN BZTPK5678L, mobile 9123456780, "
               "working from 10.4.18.9. Account 50100234567890 "
               "IFSC HDFC0001234."),
         expect=["IN_PAN", "IN_AADHAAR", "IN_PHONE_NUMBER", "IN_IFSC",
                 "IN_UPI_ID", "IP_ADDRESS"],
         llm=True, note="the realistic case: many types, two people"),
    dict(id="mix-repeat", group="mixed",
         text=("PAN ABCPE1234F appears here, and PAN ABCPE1234F again, "
               "and once more ABCPE1234F."),
         expect=["IN_PAN"],
         note="one value repeated must map to one stand-in"),
]

# Replies a model might plausibly return, used to check restoration survives
# the ways models mangle a tag.
MANGLE_FORMS = [
    "{t}", "<{bare}>", "**{bare}**", "`{bare}`", "[{bare}]", "({bare})",
    "{bare}'s record", "{title}", "{lower}",
]


# ================================================================ client
class Avron:
    def __init__(self, base, key="", timeout=120, insecure=False):
        self.base = base.rstrip("/")
        self.key = key
        self.timeout = timeout
        self.ctx = None
        if insecure:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _req(self, path, payload=None, method=None, raw=False):
        url = self.base + path
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data,
                                     method=method or ("POST" if data else "GET"))
        req.add_header("Content-Type", "application/json")
        if self.key:
            req.add_header("Authorization", f"Bearer {self.key}")
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self.ctx) as r:
                body = r.read().decode("utf-8", "replace")
                ms = int(1000 * (time.monotonic() - started))
                if raw:
                    return {"status": r.status, "ms": ms, "text": body}
                return {"status": r.status, "ms": ms, "json": json.loads(body)}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            return {"status": e.code, "ms": int(1000 * (time.monotonic() - started)),
                    "error": body[:600]}
        except Exception as exc:  # noqa: BLE001
            return {"status": 0, "ms": int(1000 * (time.monotonic() - started)),
                    "error": f"{type(exc).__name__}: {exc}"}

    def health(self):
        return self._req("/health")

    def analyze(self, text, use_llm=None):
        payload = {"text": text}
        if use_llm is not None:
            payload["use_llm"] = use_llm
        return self._req("/analyze", payload)

    def anonymize(self, text, strategy="replace", per_entity=None, use_llm=None):
        payload = {"text": text, "strategy": strategy,
                   "per_entity": per_entity or {}}
        if use_llm is not None:
            payload["use_llm"] = use_llm
        return self._req("/anonymize", payload)

    def chat(self, model, messages, prefix="/v1", stream=False, max_tokens=400):
        payload = {"model": model, "messages": messages,
                   "max_tokens": max_tokens, "stream": stream}
        return self._req(f"{prefix}/chat/completions", payload)


# =============================================================== checking
TOKEN_RE = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")


def evaluate(case, result):
    """Turn one /analyze response into pass/fail notes."""
    problems = []
    if "json" not in result:
        return ["request failed: " + str(result.get("error", result.get("status")))], []

    found = result["json"].get("results", [])
    types = {r["entity_type"] for r in found}
    texts = [r["text"] for r in found]

    for want in case.get("expect", []):
        if want not in types:
            problems.append(f"missed {want}")
    for never in case.get("forbid", []):
        if never in types:
            hits = [r["text"] for r in found if r["entity_type"] == never]
            problems.append(f"false positive {never} on {hits}")
    for fragment in case.get("at", []):
        if not any(fragment in t or t in fragment for t in texts):
            problems.append(f"did not detect {fragment!r}")
    return problems, found


def check_roundtrip(original, masked_text, restored_text):
    """Masking must hide something and restoring must give the text back."""
    problems = []
    if masked_text == original:
        problems.append("nothing was masked")
    if restored_text is not None and restored_text != original:
        problems.append("round trip was not lossless")
    leftover = TOKEN_RE.findall(restored_text or "")
    if leftover:
        problems.append(f"placeholders survived: {leftover[:4]}")
    return problems


# =================================================================== runs
def run_detection(av, cases, use_llm):
    out = []
    for case in cases:
        want_llm = use_llm if case.get("llm") else False
        res = av.analyze(case["text"], use_llm=want_llm)
        problems, found = evaluate(case, res)
        out.append({
            "id": case["id"], "group": case["group"], "kind": "detect",
            "input": case["text"], "note": case.get("note", ""),
            "used_llm": want_llm,
            "expect": case.get("expect", []), "forbid": case.get("forbid", []),
            "found": [{"type": r["entity_type"], "text": r["text"],
                       "score": r["score"]} for r in found],
            "ms": res.get("ms"), "status": res.get("status"),
            "problems": problems,
            "ok": not problems,
        })
        print_line(out[-1])
    return out


def run_masking(av, cases, use_llm):
    """Mask, then restore by hand from the items map, and compare."""
    out = []
    for case in cases:
        if case.get("group") in ("regions-off",):
            continue
        want_llm = use_llm if case.get("llm") else False
        res = av.anonymize(case["text"], use_llm=want_llm)
        row = {"id": case["id"], "group": case["group"], "kind": "mask",
               "input": case["text"], "used_llm": want_llm,
               "ms": res.get("ms"), "status": res.get("status")}
        if "json" not in res:
            row["problems"] = ["request failed: "
                               + str(res.get("error", res.get("status")))]
            row["ok"] = False
        else:
            masked = res["json"].get("anonymized_text", "")
            items = res["json"].get("items", [])
            row["masked"] = masked
            row["items"] = len(items)
            problems = []
            if case.get("expect") and masked == case["text"]:
                problems.append("nothing was masked")
            # A value that appears twice must be replaced consistently.
            row["distinct_tokens"] = len(set(TOKEN_RE.findall(masked)))
            row["problems"] = problems
            row["ok"] = not problems
        out.append(row)
        print_line(row)
    return out


def run_chat(av, model, prefix, cases, mangle=True):
    """The real path: send through the proxy and inspect what came back."""
    out = []
    for case in cases:
        messages = [
            {"role": "system",
             "content": "Reply in one short sentence. Repeat any identifiers "
                        "exactly as they appear."},
            {"role": "user", "content": "Summarise: " + case["text"]},
        ]
        res = av.chat(model, messages, prefix=prefix)
        row = {"id": case["id"], "group": case["group"], "kind": "chat",
               "input": case["text"], "model": model,
               "ms": res.get("ms"), "status": res.get("status")}
        if "json" not in res:
            row["problems"] = ["request failed: "
                               + str(res.get("error", res.get("status")))]
            row["ok"] = False
        else:
            body = res["json"]
            reply = ""
            try:
                reply = body["choices"][0]["message"]["content"] or ""
            except Exception:  # noqa: BLE001
                pass
            row["reply"] = reply
            row["masked_count"] = body.get("x_pii_masked", 0)
            problems = []
            leftover = TOKEN_RE.findall(reply)
            if leftover:
                problems.append(f"placeholder in reply: {leftover[:4]}")
            # A bare token is the failure that is easy to miss.
            bare = re.findall(r"\b[A-Z][A-Z0-9]*_\d+\b", reply)
            if bare:
                problems.append(f"bare placeholder in reply: {bare[:4]}")
            row["problems"] = problems
            row["ok"] = not problems
        out.append(row)
        print_line(row)
    return out


def run_stream(av, model, prefix, text):
    """Streaming has its own restoration path, so it needs its own check."""
    url = f"{av.base}{prefix}/chat/completions"
    payload = {"model": model, "stream": True, "max_tokens": 300,
               "messages": [{"role": "user",
                             "content": "Repeat this back verbatim: " + text}]}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    if av.key:
        req.add_header("Authorization", f"Bearer {av.key}")
    started = time.monotonic()
    pieces, status, err = [], 0, ""
    try:
        with urllib.request.urlopen(req, timeout=av.timeout, context=av.ctx) as r:
            status = r.status
            for raw in r:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                chunk = line[5:].strip()
                if chunk == "[DONE]":
                    break
                try:
                    obj = json.loads(chunk)
                    piece = obj["choices"][0].get("delta", {}).get("content")
                    if piece:
                        pieces.append(piece)
                except Exception:  # noqa: BLE001
                    continue
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"

    reply = "".join(pieces)
    problems = []
    if err:
        problems.append(err)
    leftover = TOKEN_RE.findall(reply) + re.findall(r"\b[A-Z][A-Z0-9]*_\d+\b", reply)
    if leftover:
        problems.append(f"placeholder in stream: {leftover[:4]}")
    if not reply and not err:
        problems.append("stream produced no content")
    row = {"id": "stream-1", "group": "streaming", "kind": "stream",
           "input": text, "reply": reply, "status": status,
           "ms": int(1000 * (time.monotonic() - started)),
           "problems": problems, "ok": not problems}
    print_line(row)
    return [row]


# ================================================================ output
def print_line(row):
    mark = "ok  " if row.get("ok") else "FAIL"
    print(f"  [{mark}] {row['group']:16} {row['id']:22} {row.get('ms', 0):>5} ms")
    for p in row.get("problems", []):
        print(f"         - {p}")


def main():
    ap = argparse.ArgumentParser(description="Exercise a running Avron.")
    ap.add_argument("--base-url", required=True,
                    help="http://host:8080 or https://host")
    ap.add_argument("--key", default="", help="an avron-... key, if required")
    ap.add_argument("--group", default="", help="run only one group")
    ap.add_argument("--no-llm", action="store_true",
                    help="skip the detection model everywhere")
    ap.add_argument("--chat", action="store_true",
                    help="also send prompts through the proxy to a real model")
    ap.add_argument("--model", default="", help="model id for --chat")
    ap.add_argument("--prefix", default="/v1", help="endpoint path")
    ap.add_argument("--insecure", action="store_true",
                    help="accept a self-signed certificate")
    ap.add_argument("--out", default="", help="where to write the report")
    args = ap.parse_args()

    if args.chat and not args.model:
        sys.exit("--chat needs --model. Pick one from the Playground.")

    av = Avron(args.base_url, args.key, insecure=args.insecure)
    cases = [c for c in CASES if not args.group or c["group"] == args.group]

    print(f"Avron test harness -> {args.base_url}")
    health = av.health()
    if "json" not in health:
        sys.exit(f"Cannot reach Avron: {health.get('error', health)}")
    cfg = health["json"]
    print(f"  entities enabled : {len(cfg.get('entities_enabled', []))}")
    print(f"  threshold        : {cfg.get('score_threshold')}")
    print(f"  detection model  : {cfg.get('llm', {}).get('enabled')} "
          f"({cfg.get('llm', {}).get('model') or 'unset'})")
    print(f"  endpoints        : {[r['prefix'] for r in cfg.get('routes', [])]}")
    print(f"  cases            : {len(cases)}")
    print()

    rows = []
    use_llm = None if not args.no_llm else False

    print("Detection")
    rows += run_detection(av, cases, use_llm)
    print()
    print("Masking")
    rows += run_masking(av, cases, use_llm)

    if args.chat:
        print()
        print("Through the proxy")
        sample = [c for c in cases if c["group"] in ("mixed", "people")][:4]
        rows += run_chat(av, args.model, args.prefix, sample)
        print()
        print("Streaming")
        rows += run_stream(av, args.model, args.prefix,
                           "Priya Raghunathan, PAN ABCPE1234F, "
                           "mobile 9876543210, from 203.0.113.45")

    failed = [r for r in rows if not r.get("ok")]
    by_group = {}
    for r in rows:
        g = by_group.setdefault(r["group"], {"total": 0, "failed": 0})
        g["total"] += 1
        if not r.get("ok"):
            g["failed"] += 1

    print()
    print("=" * 62)
    print(f"  {len(rows) - len(failed)} of {len(rows)} passed")
    for g, v in sorted(by_group.items()):
        flag = "" if not v["failed"] else f"   <-- {v['failed']} failed"
        print(f"    {g:18} {v['total'] - v['failed']:>3}/{v['total']:<3}{flag}")
    print("=" * 62)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = args.out or f"avron-report-{stamp}.json"
    report = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_url": args.base_url,
        "harness_version": 1,
        "config": cfg,
        "options": {"chat": args.chat, "model": args.model,
                    "prefix": args.prefix, "no_llm": args.no_llm,
                    "group": args.group},
        "summary": {"total": len(rows), "failed": len(failed),
                    "by_group": by_group},
        "results": rows,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(f"\nWrote {path}")
    print("Send that file back for analysis. It holds the test inputs and "
          "Avron's outputs, all synthetic.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
