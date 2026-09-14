"""Placeholder vault + streaming-safe restoration."""

import re
from typing import Dict


class Vault:
    """Per-request bidirectional map: real value <-> indexed placeholder.

    Indexed placeholders are the point. If two people both become <PERSON> the
    model cannot tell them apart and will conflate them. Priya becomes
    <PERSON_1> and stays <PERSON_1> in every message of the request, so the
    model tracks identity without ever seeing a real name.
    """

    def __init__(self) -> None:
        self.to_token: Dict[str, str] = {}
        self.to_real: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}

    def reserve(self, real: str, entity: str) -> str:
        """Allocate a token. Call in document order so <PERSON_1> is the first
        person mentioned - replacement itself runs right-to-left to keep
        offsets valid, which would otherwise number everyone backwards."""
        return self.token_for(real, entity)

    def token_for(self, real: str, entity: str) -> str:
        if real in self.to_token:
            return self.to_token[real]
        self.counters[entity] = self.counters.get(entity, 0) + 1
        token = f"<{entity}_{self.counters[entity]}>"
        self.to_token[real] = token
        self.to_real[token] = real
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
        bare = {t.strip("<>"): v for t, v in self.to_real.items()}
        if not any(b in text for b in bare):
            return text
        # Longest first so PERSON_10 is not clobbered by PERSON_1.
        alt = "|".join(re.escape(b) for b in sorted(bare, key=len, reverse=True))
        pattern = re.compile(r"<?\b(" + alt + r")\b>?")
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

    _TAIL = re.compile(r"[<>\w]+$")

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
