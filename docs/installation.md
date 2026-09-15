# Installation

## Requirements

- Docker and Docker Compose v2
- ~3 GB disk (the spaCy `en_core_web_lg` model is ~590 MB)
- 2 GB RAM minimum, 4 GB comfortable
- Outbound access to your model provider

## Deploy

Unpack the archive wherever you keep your stacks, then:

**1. Storage.**

```bash
mkdir -p /root/docker-storage/avron/{data,cache}
```

`data` holds the SQLite database; `cache` holds the spaCy model so rebuilds do
not re-download it.

**2. Generate the key.**

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

44 characters ending in `=`. This is the only secret you have to supply.

**3. Edit `docker-compose.yml`.** Replace `REPLACE_WITH_FERNET_KEY` with the key
you just generated, and point `OPENAI_BASE_URL` at whatever model API you use.
That value only seeds the database on first boot; afterwards it is edited in the
console.

Then `chmod 600 docker-compose.yml` — it now holds a secret.

**4. Start.**

```bash
docker compose up -d --build
docker logs avron 2>&1 | grep -A6 "first-run credentials"
```

The `2>&1` matters: the credentials are logged at WARNING level to stderr.

The first build takes several minutes — the spaCy model is downloaded during the
image build and cached to `/root/docker-storage/avron/cache`, so rebuilds after
that are fast.

**5. Sign in.** Open `http://<host>:8080` as `admin` with the printed password.
The console blocks you on the password-change screen until you rotate it. The
password is shown once and is not recoverable from the database.

## Networking

The compose file publishes 8080 on all interfaces and joins no custom network.
If Avron needs to reach a model container you already run, either add it to that
stack's network or use the host address.

Bind the port to localhost or a private address if this machine is exposed:

```yaml
    ports:
      - "127.0.0.1:8080:8080"
```

Docker's port publishing writes its own iptables rules and bypasses UFW, so a
firewall rule alone will not protect a `0.0.0.0` binding.

## What ships

One service on port 8080, serving the console, the proxy and the masking API.
No database server, no queue, no cache. Configuration lives in a single SQLite
file under `/root/docker-storage/avron/data`.

Model providers are configured in the console, not the compose file — point
Avron at OpenAI, a local Ollama, or anything else that speaks the OpenAI wire
format.

## MASTER_KEY

The one setting that must stay in the environment. It encrypts the provider API
keys stored in the database, so it cannot live in the database it protects.

- Generate once. Store it in your password manager or secret store.
- **Lose it** and every stored API key must be re-entered.
- **Change it** and stored keys silently decrypt to empty strings.

It must be a valid Fernet key: 32 random bytes, urlsafe-base64 encoded, 44
characters ending in `=`.

## First-run checklist

1. Change the admin password.
2. **Endpoints** → edit `/v1` → set the provider address and API key.
3. **Detection model** → point it somewhere, or switch it off.
4. **Patterns** → enable the packs for your region.
5. **Scan text** → paste a representative sample and check the results.
6. **Playground** → run a prompt and confirm the placeholder table.

## Upgrading

```bash
cd ~/avron
# replace the avron/ directory contents
docker compose up -d --build avron
```

Migrations run on startup and are idempotent. New packs and settings are added
without touching rows you have edited. Back up the database first — see
[operations.md](operations.md).
