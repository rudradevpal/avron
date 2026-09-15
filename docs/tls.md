# HTTPS

Without TLS, session cookies, API keys and provider credentials cross the
network in the clear. The console says so until you fix it.

Three ways to get there: Let's Encrypt, your own certificate, or a self-signed
one for a private network.

## Let's Encrypt

Free, trusted, and renews itself. Two things must be true first:

- **The domain resolves to this server.**
- **Port 80 reaches Avron.** The compose file maps `80:8080` for exactly this.
  Let's Encrypt fetches `http://your-domain/.well-known/acme-challenge/…` to
  prove you control the name; there is no way around that on the HTTP-01
  challenge.

**HTTPS → Let's Encrypt**, enter your domains and an email for expiry warnings,
and press *Get a certificate*. Validation usually takes under a minute.

**Do a staging run first.** The real service allows five failures per hour per
domain, and a DNS or firewall mistake burns through that quickly. Staging issues
an untrusted certificate but has generous limits, so it costs one extra minute
and tells you whether the plumbing works.

Once issued, switch **Serve over HTTPS** on. Avron restarts to bind the TLS
socket — a few seconds — then answers on 443.

### Renewal

Automatic. A background task checks twice a day and renews when the certificate
is inside its last 30 days. Let's Encrypt certificates last 90, so there are two
clear months of retries before anything breaks, which is what makes an
unattended renewal safe.

Renewal reuses the same ACME account key and the same HTTP-01 challenge, so port
80 has to stay reachable. If it fails, the error is shown on the HTTPS page and
written to the log; nothing is silently broken.

*Renew now* forces one early.

## Your own certificate

**HTTPS → Upload your own.** Paste the PEM chain and the key.

Checked before anything is written:

- both parse as PEM
- the key is not passphrase-protected
- **the key actually matches the certificate** — a mismatched pair installs
  fine and then fails at handshake time, long after it looked successful
- the certificate has not expired

Include the intermediates. A leaf on its own validates here and then fails in
clients that do not happen to carry the issuer.

## Self-signed

One button, for a private network or a tailnet. It encrypts the connection, and
every browser will warn every time. Do not use it on the internet.

## After turning HTTPS on

Set `COOKIE_SECURE: "true"` in `docker-compose.yml` and restart. Session cookies
then refuse to travel over plain HTTP at all.

Do it *after*, not before: with `COOKIE_SECURE=true` on plain HTTP the browser
silently drops the cookie and the console appears to log you straight back out.

## How it fits together

Uvicorn binds its socket once at start, so switching HTTPS restarts the process.
`run.py` re-executes itself rather than exiting, so the container stays up and
does not depend on a restart policy to come back.

With TLS on, a small plain-HTTP listener runs alongside on 8080. It answers ACME
challenges and redirects everything else to HTTPS. It is deliberately minimal —
it is reachable before any certificate exists, so the less it can do the better.

| Path | Port in container | Purpose |
|---|---|---|
| `80:8080` | 8080 | challenges and redirect, or the whole app when TLS is off |
| `443:8443` | 8443 | the console and API over TLS |

Certificates live in `/data/tls`, inside the volume you already back up. The key
is written `0600`.

## Troubleshooting

**"Let's Encrypt could not reach …"** — the name does not resolve here, or port
80 is blocked. Check from outside: `curl http://your-domain/.well-known/acme-challenge/test`
should reach Avron and return 404, not time out.

**Console logs you out immediately after enabling** — `COOKIE_SECURE=true` while
still on HTTP.

**Browser warns after Let's Encrypt succeeded** — you used staging. Re-issue
without it.

**Rate limited** — five failures per hour per domain, and 50 certificates per
week per registered domain. Wait, and use staging while debugging.
