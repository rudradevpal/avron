"""Transparent OpenAI-compatible forward proxy, driven by DB routes.

Every route configured in the UI gets its own path prefix, upstream, token,
entity set, mask roles and LLM toggle. Requests are forwarded verbatim; only
bodies whose shape we recognise are rewritten, and only for the configured roles.
"""

import json
import logging
import time
from typing import List

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

import db
import net
import providers
from balancer import pool
from config import config
from vault import StreamRestorer, Vault

logger = logging.getLogger(__name__)
router = APIRouter(tags=["proxy"])

# Hop-by-hop headers must not be forwarded.
STRIP = {
    "host", "content-length", "connection", "keep-alive",
    "transfer-encoding", "accept-encoding", "cookie",
}


async def analyze_text(text: str, entities=None, use_llm=None):
    """Rules + optional LLM pass + overlap dedupe."""
    from main import dedupe

    results = config.analyzer.analyze(
        text=text,
        language="en",
        entities=entities or config.enabled_entities(),
        score_threshold=config.threshold(),
    )
    cfg = config.llm()
    if cfg["enabled"] if use_llm is None else use_llm:
        from llm_pass import analyze_with_llm

        results += await analyze_with_llm(text, cfg)
    return dedupe(results)


# --------------------------------------------------------------- masking
async def _mask(text: str, vault: Vault, route: dict) -> str:
    if not isinstance(text, str) or not text.strip():
        return text
    results = await analyze_text(text, route["entities"], route["use_llm"])
    # Number them in reading order first, then substitute right-to-left so
    # earlier offsets stay valid. Doing both in one pass numbers people
    # backwards, which makes the model's reasoning hard to follow.
    for r in sorted(results, key=lambda x: x.start):
        vault.reserve(text[r.start : r.end], r.entity_type)
    out = text
    for r in sorted(results, key=lambda x: -x.start):
        token = vault.token_for(text[r.start : r.end], r.entity_type)
        out = out[: r.start] + token + out[r.end :]
    return out


async def _mask_content(content, vault, route):
    if isinstance(content, str):
        return await _mask(content, vault, route)
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict) and p.get("type") == "text":
                p = {**p, "text": await _mask(p.get("text", ""), vault, route)}
            # Non-text parts (image_url, audio) pass through unscanned.
            parts.append(p)
        return parts
    return content


async def _mask_messages(messages: List[dict], vault, route) -> List[dict]:
    out = []
    for msg in messages or []:
        if not isinstance(msg, dict) or msg.get("role") not in route["mask_roles"]:
            out.append(msg)
            continue
        new = dict(msg)
        new["content"] = await _mask_content(msg.get("content"), vault, route)
        if msg.get("tool_calls"):
            calls = []
            for c in msg["tool_calls"]:
                c = json.loads(json.dumps(c))
                fn = c.get("function", {})
                if isinstance(fn.get("arguments"), str):
                    fn["arguments"] = await _mask(fn["arguments"], vault, route)
                calls.append(c)
            new["tool_calls"] = calls
        out.append(new)
    return out


async def _mask_body(rest: str, body: dict, vault, route) -> dict:
    if not isinstance(body, dict):
        return body
    body = dict(body)
    if "messages" in body:
        body["messages"] = await _mask_messages(body["messages"], vault, route)
    elif rest.endswith("responses") and "input" in body:
        inp = body["input"]
        body["input"] = (
            await _mask(inp, vault, route)
            if isinstance(inp, str)
            else await _mask_messages(inp, vault, route)
        )
    elif rest.endswith("embeddings") and "input" in body:
        inp = body["input"]
        body["input"] = (
            await _mask(inp, vault, route)
            if isinstance(inp, str)
            else [await _mask(i, vault, route) for i in inp]
        )
    elif "prompt" in body:
        p = body["prompt"]
        body["prompt"] = (
            await _mask(p, vault, route)
            if isinstance(p, str)
            else [await _mask(i, vault, route) for i in p]
        )
    return body


# --------------------------------------------------------------- routing
def _prepare(upstream: dict, rest: str, headers: dict, body):
    """Per-attempt URL, headers and body for one upstream."""
    url = f"{upstream['url'].rstrip('/')}/{rest}"
    head = dict(headers)
    # A token stored on the upstream replaces whatever the client sent, so
    # agents never need to hold any real provider credential. The header name
    # depends on the provider: Azure wants api-key, Anthropic x-api-key.
    if upstream["token"]:
        head.pop("authorization", None)
        head.update(
            providers.auth_headers(
                upstream.get("provider_type", "openai"), upstream["token"]
            )
        )
    if isinstance(body, dict) and upstream["model_override"]:
        body = {**body, "model": upstream["model_override"]}
    return url, head, body


@router.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
async def proxy(full_path: str, request: Request):
    route = config.match_route("/" + full_path)
    if route is None:
        return JSONResponse(status_code=404, content={"error": "No route configured"})

    candidates = pool.order(route["upstreams"], route["strategy"])
    if not candidates:
        return JSONResponse(
            status_code=503,
            content={"error": f"No upstream enabled on {route['prefix']}"},
        )

    rest = route["_rest"]
    headers = {k: v for k, v in request.headers.items() if k.lower() not in STRIP}
    params = dict(request.query_params)
    raw = await request.body()

    body = None
    if raw and "json" in request.headers.get("content-type", ""):
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = None

    # Mask once, not per attempt: the same masked body is reused on retry so a
    # failover cannot produce different placeholders for the same values.
    vault = Vault()
    masked = None
    if body is not None:
        masked = await _mask_body(rest, body, vault, route)
        if vault.size:
            logger.info("Masked %d values on %s", vault.size, route["prefix"])

    attempts = min(len(candidates), max(1, route["retries"] + 1))
    errors = []

    for upstream in candidates[:attempts]:
        url, head, payload = _prepare(upstream, rest, headers, masked)
        started = time.monotonic()
        pool.enter(upstream["id"])
        try:
            if masked is not None and masked.get("stream"):
                # Streaming: the client consumes the generator after we return,
                # so the first byte is the only thing we can retry on.
                client = net.client(route["timeout"], url)
                ctx = client.stream(
                    request.method, url, json=payload, headers=head, params=params
                )
                response = await ctx.__aenter__()
                if response.status_code >= 400:
                    detail = (await response.aread())[:200].decode("utf-8", "replace")
                    await ctx.__aexit__(None, None, None)
                    await client.aclose()
                    raise RuntimeError(f"{response.status_code} {detail}")
                pool.record_success(upstream["id"], time.monotonic() - started)
                db.bump_stats(route["prefix"], masked=vault.size)
                return StreamingResponse(
                    _stream(client, ctx, response, vault, upstream),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                        "X-Upstream": upstream["name"] or str(upstream["id"]),
                    },
                )

            async with net.client(route["timeout"], url) as client:
                if masked is None:
                    r = await client.request(
                        request.method, url, content=raw, headers=head, params=params
                    )
                else:
                    r = await client.request(
                        request.method, url, json=payload, headers=head, params=params
                    )

            # 5xx and 429 are the upstream's problem - fail over. 4xx is the
            # caller's problem and would fail identically everywhere, so it is
            # returned as-is rather than burning the rest of the pool.
            if r.status_code >= 500 or r.status_code == 429:
                raise RuntimeError(f"{r.status_code} {r.text[:160]}")

            elapsed = time.monotonic() - started
            pool.record_success(upstream["id"], elapsed)
            db.bump_stats(
                route["prefix"], masked=vault.size, error=r.status_code >= 400
            )
            usage = {}
            if "json" in r.headers.get("content-type", ""):
                try:
                    usage = r.json().get("usage") or {}
                except Exception:  # noqa: BLE001
                    usage = {}
            db.record_sample(
                upstream["id"], route["prefix"], int(elapsed * 1000),
                r.status_code < 400,
                usage.get("prompt_tokens", 0) or 0,
                usage.get("completion_tokens", 0) or 0,
                vault.size,
                (masked or {}).get("model", "") if isinstance(masked, dict) else "",
            )

            if "json" not in r.headers.get("content-type", ""):
                return Response(
                    content=r.content,
                    status_code=r.status_code,
                    media_type=r.headers.get("content-type"),
                    headers={"X-Upstream": upstream["name"] or str(upstream["id"])},
                )

            data = vault.restore_deep(r.json())
            if isinstance(data, dict) and vault.size:
                data["x_pii_masked"] = vault.size
            return JSONResponse(
                status_code=r.status_code,
                content=data,
                headers={"X-Upstream": upstream["name"] or str(upstream["id"])},
            )

        except Exception as exc:  # noqa: BLE001
            pool.record_failure(upstream["id"], str(exc))
            db.record_sample(
                upstream["id"], route["prefix"],
                int(1000 * (time.monotonic() - started)), False,
            )
            errors.append(f"{upstream['name'] or upstream['url']}: {exc}")
        finally:
            pool.leave(upstream["id"])

    db.bump_stats(route["prefix"], error=True)
    return JSONResponse(
        status_code=502,
        content={"error": "Every upstream attempt failed", "attempts": errors},
    )


async def _stream(client, ctx, response, vault: Vault, upstream: dict):
    """Re-emit SSE, restoring placeholders across chunk boundaries."""
    restorer = StreamRestorer(vault)
    try:
        async for line in response.aiter_lines():
            if not line:
                yield "\n"
                continue
            if not line.startswith("data: "):
                yield line + "\n"
                continue
            payload = line[6:]
            if payload.strip() == "[DONE]":
                tail = restorer.flush()
                if tail:
                    yield "data: " + json.dumps(
                        {"choices": [{"delta": {"content": tail}, "index": 0}]}
                    ) + "\n\n"
                yield "data: [DONE]\n\n"
                continue
            try:
                chunk = json.loads(payload)
            except json.JSONDecodeError:
                yield line + "\n"
                continue
            for choice in chunk.get("choices", []):
                delta = choice.get("delta") or {}
                if isinstance(delta.get("content"), str):
                    delta["content"] = restorer.feed(delta["content"])
                for call in delta.get("tool_calls") or []:
                    fn = call.get("function", {})
                    if isinstance(fn.get("arguments"), str):
                        fn["arguments"] = vault.restore(fn["arguments"])
            yield f"data: {json.dumps(chunk)}\n\n"
    except Exception as exc:  # noqa: BLE001
        logger.error("Stream from %s failed: %s", upstream["id"], exc)
        yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        yield "data: [DONE]\n\n"
    finally:
        await ctx.__aexit__(None, None, None)
        await client.aclose()
