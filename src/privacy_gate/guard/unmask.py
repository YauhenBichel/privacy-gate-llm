# SPDX-License-Identifier: Apache-2.0
"""Unmasking the reply: put the real values back, locally, for the person (design, section 3.3).

Only surrogates this session's vault issued are replaced, and only exactly: ``<EMAIL_k3x9qa>`` written
differently by the model stays as written. A surrogate counts only as a whole word: when the vault issued
``192.0.2.1`` and the model writes ``192.0.2.12`` or ``192.0.2.10``, that is another address and stays as
written, not the real value followed by a digit. The same holds for a letter or digit straight before a
surrogate that starts with one.

Candidates are found by shape (`vault.SURROGATE_SHAPES`) and looked up in the vault, so the cost of a call
does not grow with the number of values the session has masked.

Streaming: a surrogate can be split across chunks. `StreamUnmasker` holds back the longest end of what it has
seen that is the start of some surrogate, or a whole one whose next character is not known yet, and releases
it when the next chunk shows whether it was one. At the
end of a block, `flush` releases everything. Whatever the split, the stream's output equals `unmask` of the
whole text (a property test checks every split point).

Tool calls: arguments arrive as pieces of JSON. `ToolArgsBuffer` collects them and unmasks the JSON text once
it is complete, writing each value JSON-escaped, so a value with a quote or a backslash keeps the JSON valid.

SSE framing (events, ``data:`` lines) is the provider adapters' job, from P3; this module works on text.
"""

from __future__ import annotations

import json
import re

from .vault import SURROGATE_SHAPES, Vault

_WORD = "A-Za-z0-9"


def _pattern(escaped: bool) -> re.Pattern[str]:
    # In JSON text a line break is written \\n: the n is part of an escape, not a letter before the surrogate.
    before = rf"(?:(?<![{_WORD}])|(?<=\\[nrtbf]))" if escaped else rf"(?<![{_WORD}])"
    return re.compile(
        "|".join(
            (before if word_start else "") + shape + (rf"(?![{_WORD}])" if word_end else "")
            for shape, word_start, word_end in SURROGATE_SHAPES
        )
    )


_PLAIN = _pattern(escaped=False)
_JSON = _pattern(escaped=True)
#: Characters of context a match looks back at (the JSON escape is two).
_LOOKBEHIND = 2


def _real(match: re.Match[str], vault: Vault, escape_json: bool) -> str:
    real = vault.value(match.group())
    if real is None:
        return match.group()
    return json.dumps(real, ensure_ascii=False)[1:-1] if escape_json else real


def unmask(text: str, vault: Vault) -> str:
    return _PLAIN.sub(lambda m: _real(m, vault, False), text)


def unmask_json_text(text: str, vault: Vault) -> str:
    """Unmask JSON text (tool arguments), escaping each value for a JSON string."""
    return _JSON.sub(lambda m: _real(m, vault, True), text)


class StreamUnmasker:
    def __init__(self, vault: Vault, escape_json: bool = False) -> None:
        self._vault = vault
        self._escape = escape_json
        self._pattern = _JSON if escape_json else _PLAIN
        self._buffer = ""
        #: The last characters already released, as received: what a surrogate at the start of the buffer
        #: stands after.
        self._before = ""

    def _hold(self, buffer: str) -> int:
        """How much of the end of `buffer` could still turn out to be, or not to be, a surrogate."""
        vault = self._vault
        for size in range(min(vault.longest, len(buffer)), 0, -1):
            end = buffer[-size:]
            if vault.starts_one(end) or (end[-1].isalnum() and vault.issued(end)):
                return size
        return 0

    def _release(self, buffer: str, cut: int) -> str:
        """`buffer[:cut]` unmasked; a surrogate that runs past `cut` waits, with everything after it."""
        text = self._before + buffer
        shift = len(self._before)
        out: list[str] = []
        pos = 0
        for match in self._pattern.finditer(text, shift):
            start, end = match.start() - shift, match.end() - shift
            if end > cut:
                # A whole surrogate that runs into the held part waits with it, so the longer one can win.
                cut = min(cut, start)
                break
            out.append(buffer[pos:start])
            out.append(_real(match, self._vault, self._escape))
            pos = end
        out.append(buffer[pos:cut])
        self._before = (self._before + buffer[:cut])[-_LOOKBEHIND:]
        self._buffer = buffer[cut:]
        return "".join(out)

    def feed(self, chunk: str) -> str:
        buffer = self._buffer + chunk
        return self._release(buffer, len(buffer) - self._hold(buffer))

    def flush(self) -> str:
        out = self._release(self._buffer, len(self._buffer))
        self._before = ""
        return out

    @property
    def held(self) -> int:
        return len(self._buffer)


class ToolArgsBuffer:
    """Collects a tool call's argument pieces and unmasks them once complete."""

    def __init__(self, vault: Vault) -> None:
        self._vault = vault
        self._parts: list[str] = []

    def feed(self, piece: str) -> None:
        self._parts.append(piece)

    def finish(self) -> str:
        text, self._parts = "".join(self._parts), []
        return unmask_json_text(text, self._vault)
