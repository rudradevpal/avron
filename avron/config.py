"""Live configuration: builds the Presidio engine from the database.

Saving a pattern in the UI rebuilds the whole recognizer registry. The rebuild
happens off to the side and only replaces the live engine once it has been
constructed successfully, so a bad pattern fails at save time and leaves the
running analyzer untouched.
"""

import json
import logging
import threading
from typing import Dict, List, Optional

from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider

import db
from patterns import ALL_ENTITIES, VALIDATORS

logger = logging.getLogger(__name__)


class DbPatternRecognizer(PatternRecognizer):
    """A recognizer assembled from rows in the patterns table."""

    def __init__(self, entity: str, patterns, context, validator: str):
        self._validator = VALIDATORS.get(validator, VALIDATORS["none"])
        self._validator_name = validator
        super().__init__(
            supported_entity=entity,
            patterns=patterns,
            context=context,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str):
        """Checks only ever reject.

        Returning True makes Presidio promote the hit to the maximum score,
        which flattens every validated pattern to 1.0 and makes overlaps
        between them a coin toss. Returning None keeps the pattern's own
        score plus its context boost, so the ranking still means something
        and the more specific pattern wins the overlap.
        """
        if self._validator_name == "none":
            return None
        return None if self._validator(pattern_text) else False


class ConfigManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._analyzer: Optional[AnalyzerEngine] = None
        self._nlp = None
        self.version = 0

    # ------------------------------------------------------------ engine
    def _nlp_engine(self):
        if self._nlp is None:
            self._nlp = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
                }
            ).create_engine()
        return self._nlp

    def build(self) -> AnalyzerEngine:
        """Construct a fresh engine from the DB. Raises on bad config."""
        nlp = self._nlp_engine()
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp, languages=["en"])

        # Presidio's URL recognizer treats any dotted token as a host, so
        # "db.py" and "README.md" come back as URLs. In a codebase that is
        # most of the text. Ours requires a scheme or www, and lives in the
        # network pack where it can be switched off.
        try:
            registry.remove_recognizer("UrlRecognizer")
        except Exception:  # noqa: BLE001
            logger.debug("No UrlRecognizer to remove")

        grouped: Dict[tuple, dict] = {}
        rows = db.db().execute(
            "SELECT * FROM patterns WHERE enabled=1 ORDER BY entity, id"
        ).fetchall()
        for row in rows:
            key = (row["entity"], row["validator"])
            g = grouped.setdefault(
                key, {"patterns": [], "context": set(), "validator": row["validator"]}
            )
            g["patterns"].append(
                Pattern(name=row["name"], regex=row["regex"], score=row["score"])
            )
            g["context"].update(json.loads(row["context"] or "[]"))

        for (entity, validator), g in grouped.items():
            registry.add_recognizer(
                DbPatternRecognizer(
                    entity, g["patterns"], sorted(g["context"]), validator
                )
            )

        engine = AnalyzerEngine(
            registry=registry, nlp_engine=nlp, supported_languages=["en"]
        )
        # Smoke test: a broken registry usually explodes on first analyze,
        # not on construction. Better here than on a live request.
        engine.analyze(text="test 9876543210", language="en")
        return engine

    def reload(self) -> None:
        with self._lock:
            engine = self.build()  # may raise - live engine untouched
            self._analyzer = engine
            self.version += 1
            logger.info("Recognizer registry reloaded (v%d)", self.version)

    @property
    def analyzer(self) -> AnalyzerEngine:
        if self._analyzer is None:
            self.reload()
        return self._analyzer

    # ---------------------------------------------------------- settings
    def enabled_entities(self) -> List[str]:
        rows = db.db().execute(
            "SELECT entity FROM entity_toggles WHERE enabled=1"
        ).fetchall()
        return [r["entity"] for r in rows] or list(ALL_ENTITIES)

    def redaction_map(self) -> dict:
        """entity -> {"mode": tag|surrogate|last4, "shape": str}.

        Read on every request, so a change in the console takes effect on the
        next one without a reload.
        """
        out = {}
        for r in db.db().execute(
            "SELECT entity, redaction, shape FROM entity_toggles"
        ):
            out[r["entity"]] = {
                "mode": r["redaction"] or "tag",
                "shape": r["shape"] or "",
            }
        # A pattern may override its entity. Last one wins, which is fine:
        # several patterns for one entity should agree on the shape.
        for r in db.db().execute(
            "SELECT entity, redaction, shape FROM patterns "
            "WHERE enabled=1 AND redaction != 'tag'"
        ):
            out[r["entity"]] = {
                "mode": r["redaction"],
                "shape": r["shape"] or out.get(r["entity"], {}).get("shape", ""),
            }
        return out

    def threshold(self) -> float:
        try:
            return float(db.get_setting("score_threshold", "0.4"))
        except ValueError:
            return 0.4

    def llm(self) -> dict:
        return {
            "enabled": db.get_setting("llm_enabled", "true") == "true",
            "base_url": db.get_setting("llm_base_url").rstrip("/"),
            "token": db.get_secret("llm_token"),
            "model": db.get_setting("llm_model", ""),
            "timeout": float(db.get_setting("llm_timeout", "90") or 90),
            "score": float(db.get_setting("llm_score", "0.75") or 0.75),
            "entities": json.loads(db.get_setting("llm_entities", "[]") or "[]"),
        }

    # ------------------------------------------------------------ routes
    def packs(self) -> List[dict]:
        from patterns import PACK_INFO

        state = {r["key"]: r["enabled"] for r in db.db().execute("SELECT * FROM packs")}
        counts = {
            r["pack"]: (r["n"], r["active"])
            for r in db.db().execute(
                # "on" is a reserved word in SQLite; the alias must differ.
                "SELECT pack, COUNT(*) n, SUM(enabled) active "
                "FROM patterns GROUP BY pack"
            )
        }
        out = []
        for info in PACK_INFO:
            n, on = counts.get(info["key"], (0, 0))
            out.append({**info, "patterns": n, "active": on or 0,
                        "enabled": bool(state.get(info["key"], 0))})
        custom_n, custom_on = counts.get("custom", (0, 0))
        if custom_n:
            out.append({"key": "custom", "label": "Your own",
                        "description": "Patterns you added.", "patterns": custom_n,
                        "active": custom_on or 0, "enabled": True,
                        "default_on": True})
        return out

    def upstreams(self, route_id: int) -> List[dict]:
        rows = db.db().execute(
            "SELECT * FROM upstreams WHERE route_id=? ORDER BY priority, id",
            (route_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def routes(self) -> List[dict]:
        out = []
        for r in db.db().execute("SELECT * FROM routes ORDER BY length(prefix) DESC"):
            d = dict(r)
            d["mask_roles"] = json.loads(d["mask_roles"] or '["user"]')
            d["entities"] = json.loads(d["entities"] or "[]")
            d["strategy"] = d.get("strategy") or "failover"
            d["retries"] = d.get("retries", 2)
            d["upstreams"] = self.upstreams(d["id"])
            out.append(d)
        return out

    def match_route(self, path: str) -> Optional[dict]:
        """Longest configured prefix wins, so /secure/v1 beats /v1."""
        path = "/" + path.lstrip("/")
        for route in self.routes():  # already ordered longest first
            if not route["enabled"]:
                continue
            prefix = route["prefix"].rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                route = dict(route)
                route["_rest"] = path[len(prefix) :].lstrip("/")
                route["upstreams"] = [
                    {**u, "token": db.decrypt(u["token"])} for u in route["upstreams"]
                ]
                if not route["entities"]:
                    route["entities"] = self.enabled_entities()
                return route
        return None


config = ConfigManager()
