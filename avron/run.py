"""Avron launcher.

Uvicorn binds its TLS socket once, at start, so turning HTTPS on in the console
has to restart the process. This launcher reads the stored certificate, starts
uvicorn with or without TLS, and re-executes itself when the console asks it to.

It also runs a tiny plain-HTTP listener alongside, which does two jobs:
answers Let's Encrypt HTTP-01 challenges, and redirects everything else to
HTTPS. It has to be plain HTTP because that is what the ACME validator speaks.
"""

import asyncio
import logging
import os
import sys
import threading

import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("avron")

APP_PORT = int(os.getenv("PORT", "8080"))
TLS_PORT = int(os.getenv("TLS_PORT", "8443"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))


# ------------------------------------------------- plain HTTP side-car
async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Minimal HTTP/1.1: enough for a challenge and a redirect, nothing more.

    Not a general server on purpose. It is reachable before any certificate
    exists, so the less it can do the better.
    """
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=10)
        parts = line.decode("latin-1").split()
        if len(parts) < 2:
            return
        path = parts[1]

        host = ""
        for _ in range(50):
            header = await asyncio.wait_for(reader.readline(), timeout=10)
            if header in (b"\r\n", b"\n", b""):
                break
            if header.lower().startswith(b"host:"):
                host = header.split(b":", 1)[1].strip().decode("latin-1")

        from tls import CHALLENGES

        if path.startswith("/.well-known/acme-challenge/"):
            token = path.rsplit("/", 1)[-1]
            answer = CHALLENGES.get(token)
            if answer:
                body = answer.encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + body
                )
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
        else:
            target = host.split(":")[0] or "localhost"
            suffix = "" if TLS_PORT == 443 else f":{TLS_PORT}"
            location = f"https://{target}{suffix}{path}".encode()
            writer.write(
                b"HTTP/1.1 301 Moved Permanently\r\nLocation: " + location
                + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        await writer.drain()
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


def _run_http_sidecar(port: int) -> None:
    async def serve():
        server = await asyncio.start_server(_handle, "0.0.0.0", port)
        logger.info("Plain HTTP listener on %d (ACME challenges and redirect)",
                    port)
        async with server:
            await server.serve_forever()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(serve())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Plain HTTP listener could not start on %d: %s", port, exc)


# -------------------------------------------------------------- restart
def restart() -> None:
    """Replace this process so uvicorn re-binds with the new TLS settings.

    exec rather than exit: the container keeps running and does not depend on
    a restart policy to come back.
    """
    logger.warning("Restarting to apply TLS settings")
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)])


def main() -> None:
    # Import after logging is configured so first-boot output is not lost.
    import db
    import tls
    from patterns import ALL_ENTITIES, SEED_PATTERNS

    db.announce_first_run(db.init(SEED_PATTERNS, ALL_ENTITIES))

    cert, key = tls.paths()
    if cert:
        threading.Thread(
            target=_run_http_sidecar, args=(HTTP_PORT,), daemon=True
        ).start()
        info = tls.current() or {}
        logger.info(
            "HTTPS on %d for %s, expires %s (%s days left)",
            TLS_PORT, ", ".join(info.get("domains", [])) or "?",
            info.get("not_after", "?"), info.get("days_left", "?"),
        )
        uvicorn.run(
            "main:app", host="0.0.0.0", port=TLS_PORT,
            ssl_certfile=cert, ssl_keyfile=key, log_level="info",
        )
    else:
        # No certificate: the app itself serves plain HTTP on the app port, and
        # answers ACME challenges from the same process so a first issuance
        # works before any TLS exists.
        logger.info("HTTP on %d. TLS is off.", APP_PORT)
        uvicorn.run("main:app", host="0.0.0.0", port=APP_PORT,
                    log_level="info")


if __name__ == "__main__":
    main()
