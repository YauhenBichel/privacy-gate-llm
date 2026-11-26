# SPDX-License-Identifier: Apache-2.0
"""What the patterns cannot see in one leaf: a field's name, and a value split over neighbouring leaves.

The patterns read one leaf at a time, as ``key: value``. Two shapes of body got past that:

1. The name of the field says what the value is, and the value alone has no shape: ``{"password": "hunter2"}``
   is too short for the secret rule, ``{"phone": 447700900123}`` has no ``+`` and no spaces. `key_findings`
   reads the name.
2. The value is split: an address ends one message and its domain starts the next, or a form sends
   ``{"label": "NHS number", "value": "9434765919"}``. `joined_findings` reads neighbouring leaves as one text.

A finding from joined leaves cannot be masked (there is no one place to put a surrogate), so the caller holds
the request.

What is left out on purpose: a value made only of digits and separators, with no label, is not put together
from several leaves. Four years in a list (``[2019, 2020, 2021, 2022]``) are sixteen digits, and one such list
in ten passes the card checksum; holding those would make the guard unusable for ordinary tool results. A
card or phone number typed into four separate fields is therefore not found (see SECURITY.md).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from .detect import Finding
from .rules import Rule, Ruleset
from .walker import TextUnit

SECRET_RULE = "PG-SECRET-003"
PHONE_RULE = "PG-PHONE-001"

_SECRET_ENDINGS = (
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "apikey",
    "accesstoken",
    "authtoken",
    "privatekey",
    "clientsecret",
    "secretkey",
)
_SECRET_NAMES = frozenset({"secret", "pwd"})
_PHONE_ENDINGS = ("phone", "phonenumber", "mobile", "mobilenumber", "telephone")
_PHONE_NAMES = frozenset({"tel", "cell", "msisdn", "fax", "whatsapp"})
#: What stands where a secret would be, in documentation, templates and redacted logs.
_PLACEHOLDER = re.compile(
    r"(?i)[*x.\-_#]*|<[^<>]*>|\[[^\[\]]*\]|\$\{[^}]*\}|\{\{[^}]*\}\}|\$[a-z_][a-z0-9_]*|%[a-z_][a-z0-9_]*%"
    r"|redacted|removed|hidden|masked|none|null|nil|undefined|n/a|true|false|string|str|changeme"
    r"|your[ _-]?(?:password|secret|key|token)(?:[ _-]?here)?"
)
_BARE_NUMBER = re.compile(r"\+?[0-9]{10,15}")
#: A leaf longer than twice this is read at its two ends only: a split value sits at the edge of a leaf.
EDGE = 80


def _name(key: str) -> str:
    return "".join(ch for ch in key.lower() if ch.isalnum())


def key_findings(unit: TextUnit, text: str, ruleset: Ruleset, found: list[Finding]) -> list[Finding]:
    """Findings the field's name gives for this leaf, unless the patterns already found the value."""
    if unit.key is None:
        return []
    name = _name(unit.key)
    value = text[unit.value_offset :]
    start = unit.value_offset + len(value) - len(value.lstrip())
    end = unit.value_offset + len(value.rstrip())
    if start >= end:
        return []
    rule_id = None
    if name in _SECRET_NAMES or name.endswith(_SECRET_ENDINGS):
        if unit.is_string and not _PLACEHOLDER.fullmatch(text[start:end]):
            rule_id = SECRET_RULE
    elif (name in _PHONE_NAMES or name.endswith(_PHONE_ENDINGS)) and _BARE_NUMBER.fullmatch(text[start:end]):
        rule_id = PHONE_RULE
    rule = _rule(ruleset, rule_id)
    if rule is None or any(f.start < end and start < f.end for f in found):
        return []
    return [Finding(rule.category, rule.id, rule.aliases, start, end, "L1")]


def _rule(ruleset: Ruleset, rule_id: str | None) -> Rule | None:
    # An overlay or a custom rule file may not have the rule the finding would be reported under.
    return next((r for r in ruleset.rules if r.id == rule_id), None)


@dataclass(frozen=True)
class JoinedFinding:
    rule: Rule
    #: The value, for the allowlist and the audit hash; never logged.
    value: str
    #: Index of the first leaf the match touches.
    leaf: int


@dataclass(frozen=True)
class _Piece:
    leaf: int
    text: str
    #: Where `text` starts in the leaf's value.
    local: int


def _windows(leaves: list[tuple[int, str]]) -> Iterator[list[_Piece]]:
    window: list[_Piece] = []
    for leaf, value in leaves:
        if len(value) <= 2 * EDGE:
            window.append(_Piece(leaf, value, 0))
            continue
        window.append(_Piece(leaf, value[:EDGE], 0))
        yield window
        window = [_Piece(leaf, value[-EDGE:], len(value) - EDGE)]
    yield window


def joined_findings(
    units: list[tuple[TextUnit, str, list[Finding]]], ruleset: Ruleset
) -> list[JoinedFinding]:
    """Findings that exist only when neighbouring leaves are read as one text.

    Leaves are read in document order, and again per field name (so ``content`` of one message is beside
    ``content`` of the next, without ``role`` between them), joined with nothing and with a space.
    """
    values = [(i, text[unit.value_offset :]) for i, (unit, text, _) in enumerate(units)]
    streams = [values]
    by_key: dict[str | None, list[tuple[int, str]]] = {}
    for i, (unit, _, _) in enumerate(units):
        by_key.setdefault(unit.key, []).append(values[i])
    if len(by_key) > 1:
        streams.extend(group for group in by_key.values() if len(group) > 1)
    out: dict[tuple[str, int, str], JoinedFinding] = {}
    for stream in streams:
        for window in _windows(stream):
            if len(window) < 2:
                continue
            for joiner in ("", " "):
                for hit in _scan(window, joiner, units, ruleset):
                    out.setdefault((hit.rule.id, hit.leaf, hit.value), hit)
    return list(out.values())


def _scan(
    window: list[_Piece], joiner: str, units: list[tuple[TextUnit, str, list[Finding]]], ruleset: Ruleset
) -> Iterator[JoinedFinding]:
    text = joiner.join(piece.text for piece in window)
    bounds: list[tuple[int, int]] = []
    pos = 0
    for piece in window:
        bounds.append((pos, pos + len(piece.text)))
        pos += len(piece.text) + len(joiner)
    for rule in ruleset.rules:
        for match_start, match_end, start, end in rule.matches(text):
            touched = [i for i, (lo, hi) in enumerate(bounds) if lo < match_end and match_start < hi]
            if len(touched) < 2:
                continue  # inside one leaf: the leaf's own scan has read it, with its key
            value = text[start:end]
            labelled = (match_start, match_end) != (start, end)
            if not labelled and "@" not in value and not any(ch.isalpha() for ch in value):
                continue  # digits put together from several leaves: see the module text
            if any(_seen(window[i], bounds[i], start, end, rule, units) for i in touched):
                continue
            yield JoinedFinding(rule, value, window[touched[0]].leaf)


def _seen(
    piece: _Piece,
    bound: tuple[int, int],
    start: int,
    end: int,
    rule: Rule,
    units: list[tuple[TextUnit, str, list[Finding]]],
) -> bool:
    """True when the leaf's own scan already found part of this value: then joining only made it longer."""
    lo, hi = max(start, bound[0]), min(end, bound[1])
    if lo >= hi:
        return False
    unit, _, found = units[piece.leaf]
    shift = unit.value_offset + piece.local - bound[0]
    return any(f.category == rule.category and f.start < hi + shift and lo + shift < f.end for f in found)
