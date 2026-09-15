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
        else:
            token = None

        if token is None or (token in self.to_real and self.to_real[token] != real):
            self.counters[entity] = self.counters.get(entity, 0) + 1
            token = f"<{entity}_{self.counters[entity]}>"
            mode = "tag"

        self.to_token[real] = token
        self.to_real[token] = real
        self.modes[token] = mode
        return token

    @property
    def size(self) -> int:
        return len(self.to_real)

    def restore(self, text):
        """Put the real values back.

        Models routinely mangle the delimiters - markdown bolding turns
        <PERSON_1> into **PERSON_1**, and some strip the angle brackets
        entirely. Matching the bare token as well means those still restore
        instead of leaking a placeholder into the reply.
        """
        if not isinstance(text, str) or not self.to_real:
            return text
        # Tags are matched with or without their angle brackets, because a
        # model will happily write **PERSON_1**. Surrogates and masked tails
        # are matched literally: stripping characters off them would create
        # false matches against ordinary text.
        bare = {}
        for token, value in self.to_real.items():
            if self.modes.get(token, "tag") == "tag":
                bare[token.strip("<>")] = value
            else:
                bare[token] = value
        if not any(b in text for b in bare):
            return text
        # Longest first so PERSON_10 is not clobbered by PERSON_1.
        alt = "|".join(re.escape(b) for b in sorted(bare, key=len, reverse=True))
        pattern = re.compile(r"<?(?<![\w])(" + alt + r")(?![\w])>?")
        return pattern.sub(lambda m: bare[m.group(1)], text)

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

    A token like <PERSON_1> can arrive split as "<PER" + "SON_1>". Emitting the
    first half would leak a broken placeholder and lose the substitution, so the
    trailing word fragment is held back until a non-word character proves it is
    finished, or it grows too long to be a placeholder.
    """

    MAX_HOLD = 64

    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self.buffer = ""

    _TAIL = re.compile(r"[<>\w\u2022@.\-/]+$")

    def feed(self, chunk: str) -> str:
        if not self.vault.to_real:
            return chunk
        self.buffer += chunk
        # Hold back any trailing run of token-shaped characters. A placeholder
        # can arrive split as "<PER" + "SON_1>", and models often drop the
        # brackets entirely, so holding only on "<" is not enough.
        match = self._TAIL.search(self.buffer)
        if not match or len(self.buffer) - match.start() > self.MAX_HOLD:
            out, self.buffer = self.buffer, ""
        else:
            out, self.buffer = self.buffer[: match.start()], self.buffer[match.start() :]
        return self.vault.restore(out)

    def flush(self) -> str:
        out, self.buffer = self.buffer, ""
        return self.vault.restore(out)
