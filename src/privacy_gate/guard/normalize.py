# SPDX-License-Identifier: Apache-2.0
"""L0: normalise and decode, so a value cannot slip past the patterns by being written differently.

A view is a rewritten copy of a text plus, for each of its characters, the span of the original it came
from. The patterns run on every view; a finding in a view is mapped back through that table, so the guard
always masks or reports a span of the text the person actually sent.

The base view:
1. undoes URL escapes (``%40``), JSON/JavaScript ``\\uXXXX`` escapes and HTML character references
   (``&#64;``, ``&#x40;``, ``&commat;``); a run of escapes maps to the whole run;
2. per character, applies NFKC (full-width letters, ligatures, superscript digits), then
   - removes what a reader does not see: format characters (zero-width, bidi marks, tag characters),
     combining marks and variation selectors, filler letters and control characters other than tab and
     line breaks;
   - folds every dash and minus to ``-`` and every decimal digit of another script to ``0``-``9``;
   - folds the Cyrillic and Greek letters that look like a Latin letter to that letter.

The original text is always read as well, so a view can only add findings.

Decoded views: a base64 run of 24 or more characters, or a hex run of 32 or more, that decodes to printable
UTF-8 becomes a view of its own, and is normalised and decoded again, to a depth of 2. Every character of a
decoded view maps to the whole encoded run, so a secret inside base64 holds the run it was hidden in.

Not done here: rot13 and other ciphers, digits written as words, and look-alikes outside the table below
(the full Unicode confusables list is 6,000 entries; this one covers the letters used to fake a Latin word).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass

ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e")
DASHES = frozenset("\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d")
#: Letters that render as nothing: Hangul fillers and the Braille blank. A digit run can hide a gap in them.
FILLERS = frozenset("\u115f\u1160\u3164\uffa0\u2800")
#: Unicode categories a reader does not see: format, non-spacing and enclosing marks, controls.
_UNSEEN = frozenset({"Cf", "Mn", "Me", "Cc"})
_KEPT_CONTROLS = frozenset("\t\n\r")
#: Cyrillic and Greek letters drawn like a Latin letter, so ``p\u0430ssword`` reads as ``password``.
CONFUSABLES = dict(
    zip(
        "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u04bb\u0501\u051b\u051d"
        "\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0406\u0408\u0405"
        "\u03bf\u03b1\u03bd\u03c1\u03b9\u03ba"
        "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7",
        "aeopcyxijshdqwABEKMHOPCTXIJSoavpikABEZHIKMNOPTYX",
        strict=True,
    )
)
_ESCAPE = re.compile(
    r"(?:%[0-9A-Fa-f]{2})+|(?:\\u[0-9A-Fa-f]{4})+"
    r"|(?:&#[0-9]{1,7};?|&#[xX][0-9A-Fa-f]{1,6};?|&[A-Za-z][A-Za-z0-9]{1,31};)+"
)
#: Anything the base rewrite could change. Printable ASCII without an escape is returned as it is.
_NEEDS_REWRITE = re.compile(r"[^\t\n\r\x20-\x7e]|%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|&[#A-Za-z]")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX = re.compile(r"(?:[0-9A-Fa-f]{2}){16,}")
MAX_DECODE_DEPTH = 2
#: Decoded views per text. Past this the text is unusual enough that the caller should hold it, not half read it.
MAX_VIEWS = 256


class DecodeLimitError(Exception):
    """Too many encoded runs to decode; the caller holds the text rather than reading part of it."""


@dataclass(frozen=True)
class View:
    text: str
    #: For each character of `text`, the original span it came from. None means the identity.
    starts: tuple[int, ...] | None
    ends: tuple[int, ...] | None
    #: 0 for the base view, 1 or 2 for decoded views.
    depth: int

    def original(self, start: int, end: int) -> tuple[int, int]:
        if self.starts is None or self.ends is None:
            return start, end
        return self.starts[start], self.ends[end - 1]


def _rewrite(text: str) -> tuple[str, list[int], list[int]] | None:
    """The base rewrite of `text` with its offset table, or None when it changes nothing."""
    if _NEEDS_REWRITE.search(text) is None:
        return None
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []

    def emit(chunk: str, start: int, end: int) -> None:
        for ch in chunk:
            if " " <= ch <= "~":
                folded_run = ch
            elif ch in ZERO_WIDTH or ch in FILLERS:
                continue
            else:
                folded_run = unicodedata.normalize("NFKC", ch)
            for folded in folded_run:
                if folded > "~" or folded < " ":
                    if folded in _KEPT_CONTROLS:
                        pass
                    elif folded in DASHES:
                        folded = "-"
                    elif folded in CONFUSABLES:
                        folded = CONFUSABLES[folded]
                    elif folded in FILLERS or unicodedata.category(folded) in _UNSEEN:
                        continue
                    else:
                        digit = unicodedata.decimal(folded, None)
                        if digit is not None:
                            folded = str(digit)
                out.append(folded)
                starts.append(start)
                ends.append(end)

    pos = 0
    for match in _ESCAPE.finditer(text):
        for i in range(pos, match.start()):
            emit(text[i], i, i + 1)
        decoded = _unescape(match.group())
        if decoded is None:
            for i in range(match.start(), match.end()):
                emit(text[i], i, i + 1)
        else:
            emit(decoded, match.start(), match.end())
        pos = match.end()
    for i in range(pos, len(text)):
        emit(text[i], i, i + 1)
    rewritten = "".join(out)
    if rewritten == text:
        return None
    return rewritten, starts, ends


def _unescape(run: str) -> str | None:
    try:
        if run.startswith("&"):
            decoded = html.unescape(run)
            return None if decoded == run else decoded
        if run.startswith("%"):
            return bytes(int(run[i + 1 : i + 3], 16) for i in range(0, len(run), 3)).decode("utf-8")
        units = [int(run[i + 2 : i + 6], 16) for i in range(0, len(run), 6)]
        return "".join(chr(u) for u in units).encode("utf-16", "surrogatepass").decode("utf-16")
    except (UnicodeDecodeError, ValueError):
        return None


def _printable(text: str) -> bool:
    return bool(text) and all(ch.isprintable() or ch in "\t\n\r" for ch in text)


def _decode(run: str, is_hex: bool) -> str | None:
    try:
        if is_hex:
            raw = bytes.fromhex(run)
        else:
            body = run.rstrip("=")
            alphabet_url = "-" in body or "_" in body
            padded = body + "=" * (-len(body) % 4)
            raw = (
                base64.urlsafe_b64decode(padded) if alphabet_url else base64.b64decode(padded, validate=True)
            )
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _printable(text) else None


def views(text: str, max_depth: int = MAX_DECODE_DEPTH) -> list[View]:
    """The views of `text` the patterns should read, apart from `text` itself."""
    out: list[View] = []
    _views(text, None, max_depth, 0, out)
    return out


def _compose(parent: View | None, start: int, end: int) -> tuple[int, int]:
    return parent.original(start, end) if parent is not None else (start, end)


def _views(text: str, parent: View | None, max_depth: int, depth: int, out: list[View]) -> None:
    rewritten = _rewrite(text)
    if rewritten is None:
        base = View(text, None, None, depth) if parent is None else parent
    else:
        new_text, starts, ends = rewritten
        if parent is None:
            base = View(new_text, tuple(starts), tuple(ends), depth)
        else:
            mapped = [_compose(parent, s, e) for s, e in zip(starts, ends, strict=True)]
            base = View(new_text, tuple(m[0] for m in mapped), tuple(m[1] for m in mapped), depth)
        out.append(base)
    if depth >= max_depth:
        return
    source = base.text
    for pattern, is_hex in ((_HEX, True), (_BASE64, False)):
        for match in pattern.finditer(source):
            run = match.group()
            if not is_hex and _HEX.fullmatch(run):
                continue  # decoded as hex already
            decoded = _decode(run, is_hex)
            if decoded is None:
                continue
            if len(out) >= MAX_VIEWS:
                raise DecodeLimitError(f"more than {MAX_VIEWS} encoded runs")
            lo, hi = base.original(match.start(), match.end())
            child = View(decoded, (lo,) * len(decoded), (hi,) * len(decoded), depth + 1)
            out.append(child)
            _views(decoded, child, max_depth, depth + 1, out)
