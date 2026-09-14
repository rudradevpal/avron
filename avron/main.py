"""AVRON — PII detection, masking API, admin console and LLM forward proxy."""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig
from pydantic import BaseModel, Field

import db
from patterns import ALL_ENTITIES, SEED_PATTERNS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("avron")

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="AVRON", version="2.0", docs_url=None, redoc_url=None)

anonymizer = AnonymizerEngine()
deanonymizer = DeanonymizeEngine()


def dedupe(results):
    """Highest score wins any overlapping span."""
    ordered = sorted(results, key=lambda r: (-r.score, r.start - r.end))
    kept = []
    for res in ordered:
        if any(res.start < k.end and k.start < res.end for k in kept):
            continue
        kept.append(res)
    return sorted(kept, key=lambda r: r.start)


# ---------------------------------------------------------------- startup
@app.on_event("startup")
def startup():
    password = db.init(SEED_PATTERNS, ALL_ENTITIES)
    from config import config

    config.reload()
    if password:
        logger.warning(
            "\n"
            "==========================================================\n"
            "  AVRON first-run credentials\n"
            "    username: admin\n"
            "    password: %s\n"
            "  Change this immediately at http://<host>:8080/\n"
            "  It is shown once and is not recoverable from the database.\n"
            "==========================================================",
            password,
        )


# ------------------------------------------------------------- masking API
class AnalyzeRequest(BaseModel):
    text: str
    entities: Optional[List[str]] = None
    use_llm: Optional[bool] = None


class AnonymizeRequest(AnalyzeRequest):
    strategy: str = Field("replace", description="replace|mask|hash|encrypt|redact")
    per_entity: Dict[str, str] = Field(default_factory=dict)


def _operators(strategy: str, per_entity: Dict[str, str]):
    key = db.get_secret("crypto_key")

    def build(name: str) -> OperatorConfig:
        if name == "mask":
            return OperatorConfig(
                "mask", {"masking_char": "*", "chars_to_mask": 64, "from_end": False}
            )
        if name == "hash":
            return OperatorConfig("hash", {"hash_type": "sha256"})
        if name == "encrypt":
            return OperatorConfig("encrypt", {"key": key})
        if name == "redact":
            return OperatorConfig("redact", {})
        return OperatorConfig("replace", {})

    ops = {"DEFAULT": build(strategy)}
    for entity, op_name in per_entity.items():
        ops[entity] = build(op_name)
    return ops


@app.get("/health")
def health():
    from config import config

    llm = config.llm()
    return {
        "status": "ok",
        "engine_version": config.version,
        "entities_enabled": config.enabled_entities(),
        "score_threshold": config.threshold(),
        "llm": {"enabled": llm["enabled"], "model": llm["model"],
                "base_url": llm["base_url"]},
        "routes": [
            {"prefix": r["prefix"], "enabled": bool(r["enabled"])}
            for r in config.routes()
        ],
    }


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    from openai_proxy import analyze_text

    results = await analyze_text(req.text, req.entities, req.use_llm)
    return {
        "count": len(results),
        "results": [
            {"entity_type": r.entity_type, "start": r.start, "end": r.end,
             "score": round(r.score, 3), "text": req.text[r.start : r.end]}
            for r in results
        ],
    }


@app.post("/anonymize")
async def anonymize(req: AnonymizeRequest):
    from openai_proxy import analyze_text

    results = await analyze_text(req.text, req.entities, req.use_llm)
    output = anonymizer.anonymize(
        text=req.text,
        analyzer_results=results,
        operators=_operators(req.strategy, req.per_entity),
    )
    return {"anonymized_text": output.text,
            "items": [i.to_dict() for i in output.items]}


class DeanonymizeRequest(BaseModel):
    text: str
    items: List[dict]


@app.post("/deanonymize")
def deanonymize(req: DeanonymizeRequest):
    from presidio_anonymizer.entities import OperatorResult

    out = deanonymizer.deanonymize(
        text=req.text,
        entities=[OperatorResult(**i) for i in req.items],
        operators={"DEFAULT": OperatorConfig(
            "decrypt", {"key": db.get_secret("crypto_key")}
        )},
    )
    return {"text": out.text}


# ------------------------------------------------------------------- UI
from admin_api import router as admin_router  # noqa: E402

app.include_router(admin_router)

if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"error": "Not found"})


# The catch-all proxy must be registered LAST so it never shadows the routes
# above. Anything unmatched falls through to a configured proxy prefix.
from openai_proxy import router as proxy_router  # noqa: E402

app.include_router(proxy_router)
