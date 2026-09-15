"""TLS: uploaded certificates and Let's Encrypt with automatic renewal.

Two ways to get a certificate:

* **Upload** a PEM chain and key you already have.
* **Let's Encrypt**, issued over ACME v2 with an HTTP-01 challenge answered by
  Avron itself on port 80, then renewed in the background.

Both end in the same place: a chain and a key on disk under /data/tls, and a
flag in settings. Uvicorn binds its TLS socket at launch, so turning TLS on
restarts the process — see run.py.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

import db

logger = logging.getLogger("avron.tls")

TLS_DIR = Path(os.getenv("TLS_DIR", "/data/tls"))
CERT_PATH = TLS_DIR / "fullchain.pem"
KEY_PATH = TLS_DIR / "privkey.pem"
ACCOUNT_KEY_PATH = TLS_DIR / "acme-account.key"

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

# Answers to in-flight HTTP-01 challenges: token -> keyauthorization.
# Held in memory only; a challenge is valid for minutes, not restarts.
CHALLENGES: Dict[str, str] = {}

RENEW_WHEN_DAYS_LEFT = 30
CHECK_EVERY_HOURS = 12


# ------------------------------------------------------------ inspection
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def describe(pem: bytes) -> dict:
    """Read a certificate so the console can show what was installed."""
    cert = x509.load_pem_x509_certificate(pem)
    try:
        sans = [
            n.value
            for n in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        ]
    except x509.ExtensionNotFound:
        sans = []
    common = ""
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        common = attrs[0].value
    issuer = ""
    iattrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if iattrs:
        issuer = iattrs[0].value
    not_after = cert.not_valid_after_utc
    return {
        "subject": common,
        "issuer": issuer,
        "domains": sans or ([common] if common else []),
        "not_before": cert.not_valid_before_utc.isoformat(timespec="seconds"),
        "not_after": not_after.isoformat(timespec="seconds"),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
        "serial": format(cert.serial_number, "x"),
    }


def key_matches(cert_pem: bytes, key_pem: bytes) -> bool:
    """A cert and key that do not belong together produce a TLS socket that
    fails at handshake time, long after the upload looked successful."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    a = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return a == b


def validate_pair(cert_pem: bytes, key_pem: bytes) -> str:
    """Return an error message, or '' when the pair is usable."""
    try:
        info = describe(cert_pem)
    except Exception as exc:  # noqa: BLE001
        return f"That does not look like a PEM certificate: {exc}"
    try:
        serialization.load_pem_private_key(key_pem, password=None)
    except TypeError:
        return "The private key is encrypted. Remove the passphrase first."
    except Exception as exc:  # noqa: BLE001
        return f"That does not look like a PEM private key: {exc}"
    if not key_matches(cert_pem, key_pem):
        return "The key does not match the certificate."
    if info["days_left"] < 0:
        return f"That certificate expired on {info['not_after'][:10]}."
    if cert_pem.count(b"BEGIN CERTIFICATE") < 2:
        # Not fatal: a self-signed cert is legitimately one block, and some
        # clients carry the intermediates themselves.
        logger.warning("Certificate has no intermediate chain; some clients "
                       "will not trust it.")
    return ""


def install(cert_pem: bytes, key_pem: bytes) -> dict:
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    CERT_PATH.write_bytes(cert_pem)
    KEY_PATH.write_bytes(key_pem)
    os.chmod(KEY_PATH, 0o600)
    return describe(cert_pem)


def current() -> Optional[dict]:
    if not CERT_PATH.exists():
        return None
    try:
        return describe(CERT_PATH.read_bytes())
    except Exception as exc:  # noqa: BLE001
        logger.error("Stored certificate is unreadable: %s", exc)
        return None


def enabled() -> bool:
    return (
        db.get_setting("tls_enabled", "false") == "true"
        and CERT_PATH.exists()
        and KEY_PATH.exists()
    )


def paths() -> Tuple[Optional[str], Optional[str]]:
    return (str(CERT_PATH), str(KEY_PATH)) if enabled() else (None, None)


def self_signed(domain: str) -> Tuple[bytes, bytes]:
    """A stop-gap so HTTPS can be switched on before a real certificate
    exists. Browsers will warn; that is the point of calling it a stop-gap."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


# ------------------------------------------------------------------ ACME
class AcmeError(RuntimeError):
    pass


class AcmeClient:
    """A small ACME v2 client: RS256 JWS, HTTP-01 only.

    Deliberately not a general implementation. It does one thing — get a
    certificate for a list of domains that resolve to this host — and it
    reports failures in the words the console can show a person.
    """

    def __init__(self, directory: str, contact: str = "") -> None:
        self.directory_url = directory
        self.contact = contact
        self.directory: dict = {}
        self.kid: Optional[str] = None
        self.nonce: Optional[str] = None
        self.key = self._account_key()

    # -- account key ----------------------------------------------------
    def _account_key(self):
        TLS_DIR.mkdir(parents=True, exist_ok=True)
        if ACCOUNT_KEY_PATH.exists():
            return serialization.load_pem_private_key(
                ACCOUNT_KEY_PATH.read_bytes(), password=None
            )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ACCOUNT_KEY_PATH.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(ACCOUNT_KEY_PATH, 0o600)
        return key

    @property
    def jwk(self) -> dict:
        numbers = self.key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }

    def thumbprint(self) -> str:
        canonical = json.dumps(self.jwk, sort_keys=True, separators=(",", ":"))
        return _b64(hashlib.sha256(canonical.encode()).digest())

    # -- transport ------------------------------------------------------
    async def _load_directory(self, client: httpx.AsyncClient) -> None:
        r = await client.get(self.directory_url)
        r.raise_for_status()
        self.directory = r.json()

    async def _fresh_nonce(self, client: httpx.AsyncClient) -> str:
        if self.nonce:
            nonce, self.nonce = self.nonce, None
            return nonce
        r = await client.head(self.directory["newNonce"])
        return r.headers["replay-nonce"]

    async def _post(self, client: httpx.AsyncClient, url: str,
                    payload, use_jwk: bool = False) -> httpx.Response:
        protected = {
            "alg": "RS256",
            "nonce": await self._fresh_nonce(client),
            "url": url,
        }
        if use_jwk or not self.kid:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.kid

        payload_b64 = "" if payload == "" else _b64(json.dumps(payload).encode())
        protected_b64 = _b64(json.dumps(protected).encode())
        signature = self.key.sign(
            f"{protected_b64}.{payload_b64}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        r = await client.post(
            url,
            json={
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": _b64(signature),
            },
            headers={"Content-Type": "application/jose+json"},
        )
        self.nonce = r.headers.get("replay-nonce")
        if r.status_code >= 400:
            raise AcmeError(_readable(r))
        return r

    # -- flow -----------------------------------------------------------
    async def obtain(self, domains) -> Tuple[bytes, bytes]:
        domains = [d.strip().lower() for d in domains if d.strip()]
        if not domains:
            raise AcmeError("No domain given.")
        for d in domains:
            if not re.fullmatch(r"[a-z0-9.-]{3,253}", d) or "." not in d:
                raise AcmeError(f"{d} is not a domain name.")
            if d.endswith(".local") or d in ("localhost",):
                raise AcmeError(
                    f"Let's Encrypt cannot issue for {d}. It must be a public "
                    "name that resolves to this server."
                )

        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            await self._load_directory(client)

            payload = {"termsOfServiceAgreed": True}
            if self.contact:
                payload["contact"] = [f"mailto:{self.contact}"]
            account = await self._post(
                client, self.directory["newAccount"], payload, use_jwk=True
            )
            self.kid = account.headers["location"]

            order_res = await self._post(
                client,
                self.directory["newOrder"],
                {"identifiers": [{"type": "dns", "value": d} for d in domains]},
            )
            order = order_res.json()
            order_url = order_res.headers["location"]

            for auth_url in order["authorizations"]:
                await self._authorize(client, auth_url)

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            await self._post(
                client,
                order["finalize"],
                {"csr": _b64(csr.public_bytes(serialization.Encoding.DER))},
            )

            cert_url = await self._await_order(client, order_url)
            chain = await self._post(client, cert_url, "")
            return chain.content, key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )

    async def _authorize(self, client: httpx.AsyncClient, auth_url: str) -> None:
        auth = (await self._post(client, auth_url, "")).json()
        domain = auth["identifier"]["value"]
        if auth["status"] == "valid":
            return

        challenge = next(
            (c for c in auth["challenges"] if c["type"] == "http-01"), None
        )
        if not challenge:
            raise AcmeError(f"No HTTP-01 challenge offered for {domain}.")

        token = challenge["token"]
        CHALLENGES[token] = f"{token}.{self.thumbprint()}"
        try:
            await self._post(client, challenge["url"], {})
            for _ in range(40):          # up to ~80 seconds
                await asyncio.sleep(2)
                state = (await self._post(client, auth_url, "")).json()
                if state["status"] == "valid":
                    return
                if state["status"] in ("invalid", "revoked", "expired"):
                    detail = ""
                    for c in state.get("challenges", []):
                        if c.get("error"):
                            detail = c["error"].get("detail", "")
                    raise AcmeError(
                        f"Let's Encrypt could not reach {domain}. {detail} "
                        "Check that the name resolves to this server and that "
                        "port 80 is open."
                    )
            raise AcmeError(f"Validation for {domain} timed out.")
        finally:
            CHALLENGES.pop(token, None)

    async def _await_order(self, client: httpx.AsyncClient, order_url: str) -> str:
        for _ in range(40):
            order = (await self._post(client, order_url, "")).json()
            if order["status"] == "valid":
                return order["certificate"]
            if order["status"] == "invalid":
                raise AcmeError("The order was rejected. " + _readable_order(order))
            await asyncio.sleep(2)
        raise AcmeError("Issuance timed out.")


def _readable(r: httpx.Response) -> str:
    try:
        body = r.json()
        return body.get("detail") or body.get("type") or r.text[:200]
    except Exception:  # noqa: BLE001
        return f"{r.status_code} {r.text[:200]}"


def _readable_order(order: dict) -> str:
    err = order.get("error") or {}
    return err.get("detail", "")


# ------------------------------------------------------------- lifecycle
async def issue(domains, contact: str = "", staging: bool = False) -> dict:
    """Get a certificate and install it. Returns what was installed."""
    client = AcmeClient(LETSENCRYPT_STAGING if staging else LETSENCRYPT, contact)
    chain, key = await client.obtain(domains)
    info = install(chain, key)
    db.set_setting("tls_domains", ",".join(d.strip() for d in domains))
    db.set_setting("tls_source", "letsencrypt-staging" if staging else "letsencrypt")
    db.set_setting("tls_last_renewal", db.now())
    db.set_setting("tls_last_error", "")
    logger.info("Issued certificate for %s, expires %s",
                info["domains"], info["not_after"])
    return info


async def renew_if_due(force: bool = False) -> Optional[dict]:
    """Renew when the certificate is inside its last 30 days.

    Let's Encrypt certificates last 90 days. Renewing at 30 leaves two clear
    months of retries before anything actually breaks, which is what makes an
    unattended renewal safe.
    """
    if db.get_setting("tls_source", "") not in (
        "letsencrypt",
        "letsencrypt-staging",
    ):
        return None
    info = current()
    if not info:
        return None
    if not force and info["days_left"] > RENEW_WHEN_DAYS_LEFT:
        return None
    domains = [
        d for d in (db.get_setting("tls_domains", "") or "").split(",") if d
    ]
    if not domains:
        domains = info["domains"]
    staging = db.get_setting("tls_source") == "letsencrypt-staging"
    try:
        return await issue(domains, db.get_setting("tls_contact", ""), staging)
    except Exception as exc:  # noqa: BLE001
        db.set_setting("tls_last_error", str(exc)[:400])
        logger.error("Renewal failed: %s", exc)
        return None


async def renewal_loop() -> None:
    """Background task. Checks twice a day; renews inside the last 30."""
    while True:
        try:
            await renew_if_due()
        except Exception as exc:  # noqa: BLE001
            logger.error("Renewal check failed: %s", exc)
        await asyncio.sleep(CHECK_EVERY_HOURS * 3600)
