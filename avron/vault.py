"""Placeholder vault + streaming-safe restoration.

Three ways to stand in for a value, chosen per entity:

    tag        <PERSON_1>      the model refers to it, cannot inspect it
    surrogate  QWXYZ8871M     same shape, so the model can examine it
    last4      ••••••3210     enough for a human to recognise the record

Whichever is used, the mapping is one-to-one within the request and restored
on the way out.
"""

import re
from typing import Dict, Optional

from surrogate import STRATEGIES, SurrogateFactory, last_four


class Vault:
    """Per-request bidirectional map: real value <-> indexed placeholder.

    Indexed placeholders are the point. If two people both become <PERSON> the
    model cannot tell them apart and will conflate them. Priya becomes
    <PERSON_1> and stays <PERSON_1> in every message of the request, so the
    model tracks identity without ever seeing a real name.
    """

    def __init__(self, policy: Optional[dict] = None) -> None:
        self.to_token: Dict[str, str] = {}
        self.to_real: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        # entity -> {"mode": ..., "shape": ...}; missing entities use tags.
        self.policy = policy or {}
        self.factory = SurrogateFactory()
        # Real values seen in this text. A surrogate must never equal one of
        # them, or restoration would rewrite something the model was shown
        # legitimately.
        self.reals: set = set()
        self.modes: Dict[str, str] = {}
        self._tag_re = None
        self._lit_re = None
        self._tag_lookup: Dict[str, str] = {}

    def reserve(self, real: str, entity: str) -> str:
        """Allocate a token. Call in document order so <PERSON_1> is the first
        person mentioned - replacement itself runs right-to-left to keep
        offsets valid, which would otherwise number everyone backwards."""
        return self.token_for(real, entity)

    def token_for(self, real: str, entity: str) -> str:
        if real in self.to_token:
            return self.to_token[real]

        rule = self.policy.get(entity) or {}
        mode = rule.get("mode", "tag")
        if mode not in STRATEGIES:
            mode = "tag"

        self.reals.add(real)
        if mode == "surrogate":
            token = self.factory.make(entity, real, rule.get("shape") or None,
                                      avoid=self.reals)
        elif mode == "last4":
            token = last_four(real)
            # Two values ending in the same four characters would produce one
            # token standing for both. Fall back rather than merge them.
            if self.to_real.get(token, real) != real:
                mode = "tag"
                token = None
            elif token == real:
                # Nothing was hidden: the value is four characters or shorter.
                # Silently passing it through would be a masking failure that
                # looks like success.
                mode = "tag"
                token = None
        else:
            token = None

        if token is None or (token in self.to_real and self.to_real[token] != real):
            self.counters[entity] = self.counters.get(entity, 0) + 1
            token = f"<{entity}_{self.counters[entity]}>"
            mode = "tag"

        self.to_token[real] = token
        self.to_real[token] = real
        self.modes[token] = mode
        self._tag_re = None      # matchers are stale now
        self._lit_re = None
        return token

    @property
    def size(self) -> int:
        return len(self.to_real)

    # A tag written by a model rarely comes back exactly as it was sent:
    # markdown strips the brackets, title case creeps in, underscores become
    # spaces or hyphens. Matching strictly leaks the placeholder.
    #
    # Matching too loosely is worse. An entity called ORDER produces ORDER_1,
    # and "please check order 1" is an ordinary sentence — substituting there
    # injects a real value into text that never contained one. So the looser
    # separators are only allowed for entity names unlikely to appear in
    # prose, and an underscore is always required for the rest.
    _DISTINCTIVE_LEN = 8

    def _is_distinctive(self, name: str) -> bool:
        body = name.rsplit("_", 1)[0]          # drop the trailing counter
        return "_" in body or len(body) >= self._DISTINCTIVE_LEN

    def _tag_pattern(self, token: str) -> str:
        bare = token.strip("<>")
        parts = bare.split("_")
        if self._is_distinctive(bare):
            # IN_PAN_1, IN_PHONE_NUMBER_2: no sentence looks like these, so
            # accept "in pan 1", "IN-PAN-1", "INPAN1" as well.
            return r"[\s_\-]?".join(re.escape(x) for x in parts)
        # ORDER_1, PERSON_1: underscore required, which "order 1" is not.
        return r"_".join(re.escape(x) for x in parts)

    def _build(self):
        """Compile the two matchers. Rebuilt whenever a token is added."""
        tags, literals = [], []
        for token in self.to_real:
            if self.modes.get(token, "tag") == "tag":
                tags.append(token)
            else:
                literals.append(token)

        self._tag_re = None
        self._tag_lookup = {}
        if tags:
            # Longest first so PERSON_10 is not eaten by PERSON_1.
            ordered = sorted(tags, key=len, reverse=True)
            alts = []
            for token in ordered:
                group = f"t{len(self._tag_lookup)}"
                self._tag_lookup[group] = self.to_real[token]
                alts.append(f"(?P<{group}>{self._tag_pattern(token)})")
            self._tag_re = re.compile(
                r"[<\[\{`]?(?<![\w])(?:" + "|".join(alts) + r")(?![\w])[>\]\}`]?",
                re.IGNORECASE,
            )

        self._lit_re = None
        if literals:
            # Surrogates and masked tails are matched exactly, and only as
            # whole words. A three-character surrogate is otherwise free to
            # rewrite the middle of an ordinary word.
            ordered = sorted(literals, key=len, reverse=True)
            self._lit_re = re.compile(
                r"(?<!\w)(?:" + "|".join(re.escape(x) for x in ordered) + r")(?!\w)"
            )

    def restore(self, text):
        """Put the real values back."""
        if not isinstance(text, str) or not self.to_real:
            return text
        if self._tag_re is None and self._lit_re is None:
            self._build()

        if self._lit_re is not None:
            text = self._lit_re.sub(lambda m: self.to_real[m.group(0)], text)

        if self._tag_re is not None:
            def swap(m):
                for group, value in self._tag_lookup.items():
                    if m.group(group) is not None:
                        return value
                return m.group(0)

            text = self._tag_re.sub(swap, text)
        return text

    def leftovers(self, text: str) -> list:
        """Tokens still visible after restoring.

        Should always be empty. When it is not, something reached a client
        with a placeholder in it, which is worth a log line rather than
        silence.
        """
        if not isinstance(text, str):
            return []
        return [t for t in self.to_real if t.strip("<>") in text]

    def restore_deep(self, obj):
        """Walk any JSON structure and restore every string in it."""
        if isinstance(obj, str):
            return self.restore(obj)
        if isinstance(obj, list):
            return [self.restore_deep(v) for v in obj]
        if isinstance(obj, dict):
            return {k: self.restore_deep(v) for k, v in obj.items()}
        return obj


class StreamRestorer:
    """Restores placeholders across SSE chunk boundaries.

    A token arrives in pieces: "<PER" + "SON_1>", or "Person" + "_1", or
    "PERSON" + " 1". Emitting the first piece leaks a broken placeholder and
    loses the substitution, so the tail of the buffer is held back for as long
    as it could still be growing into a token.

    "Could still be growing" is decided against the tokens actually issued,
    not against a character class, because the separators a model chooses are
    not predictable.
    """

    MAX_HOLD = 80

    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self.buffer = ""
        self._prefixes = None

    def _norm(self, text: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", text).upper()

    def _known(self):
        """Normalised forms of every token, so a partial tail can be tested
        against them as a prefix."""
        if self._prefixes is None:
            self._prefixes = {self._norm(t) for t in self.vault.to_real}
            self._prefixes.discard("")
        return self._prefixes

    def feed(self, chunk: str) -> str:
        if not self.vault.to_real:
            return chunk
        self.buffer += chunk
        known = self._known()

        hold_at = len(self.buffer)
        start = max(0, len(self.buffer) - self.MAX_HOLD)
        for i in range(start, len(self.buffer)):
            candidate = self._norm(self.buffer[i:])
            if candidate and any(k.startswith(candidate) for k in known):
                hold_at = i
                break

        out, self.buffer = self.buffer[:hold_at], self.buffer[hold_at:]
        return self.vault.restore(out)

    def flush(self) -> str:
        out, self.buffer = self.buffer, ""
        return self.vault.restore(out)
