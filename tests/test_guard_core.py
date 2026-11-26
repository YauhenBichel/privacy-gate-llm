# SPDX-License-Identifier: Apache-2.0
"""The guard core (P1): walker, L0 views, policy, vault, masking, unmasking, audit and the `Guard` facade.

Every value here is fake and low-entropy: addresses at northgate.internal, the Ofcom drama range, documented
or Luhn-valid test card numbers, and EXAMPLE-NOT-A-KEY. No literal credential shapes on purpose: CI greps *.py.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import random
import stat
import tempfile
import time
import unittest
import warnings
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from privacy_gate.guard import (
    AuditWriter,
    Guard,
    Policy,
    PolicyError,
    Ruleset,
    ScanLimitError,
    ScanLimits,
    SessionStore,
    StreamUnmasker,
    ToolArgsBuffer,
    Vault,
    check_local_url,
    detect,
    safe_path,
    scan_units,
    unmask,
    unmask_json_text,
)
from privacy_gate.guard import guard as guard_module
from privacy_gate.guard.detect import Finding, resolve
from privacy_gate.guard.mask import mask_text, residual
from privacy_gate.guard.normalize import MAX_VIEWS, DecodeLimitError, views
from privacy_gate.guard.policy import parse_overrides, strip_markers
from privacy_gate.guard.rules import DEFAULT_RULES_PATH as RULES_PATH
from privacy_gate.guard.vault import SURROGATE, make_surrogate
from privacy_gate.guard.walker import BinaryUnit, TextUnit, binary_kind, js_string

ROOT = Path(__file__).resolve().parent.parent
BODIES = ROOT / "rules" / "conformance.bodies.v2.json"
EMAIL = "ana.duarte@northgate.internal"
OTHER_EMAIL = "j.doe@northgate.internal"
CARD = "4000 1234 5678 9017"
PHONE = "07700 900123"
SECRET = "EXAMPLE-NOT-A-KEY"
RULES = Ruleset.load()


def nested(depth: int) -> list:
    body: list = []
    inner = body
    for _ in range(depth - 1):
        inner.append([])
        inner = inner[0]
    return body


class Walker(unittest.TestCase):
    def test_leaves_are_paired_with_their_key_in_document_order(self) -> None:
        units = list(scan_units({"a": "x", "b": [1, True, None, {"c": "y"}], "d": 1.5}))
        self.assertEqual([u.text for u in units], ["a: x", "b: 1", "b: true", "c: y", "d: 1.5"])
        self.assertEqual(units[3].path, ("b", 3, "c"))
        self.assertTrue(units[0].is_string)
        self.assertFalse(units[1].is_string)
        self.assertEqual(units[0].value_offset, 3)

    def test_a_bare_string_and_unpaired_mode(self) -> None:
        self.assertEqual(list(scan_units("hi")), [TextUnit((), None, "hi", 0, True)])
        self.assertEqual([u.text for u in scan_units({"k": "v", "n": 3}, pair_keys=False)], ["v"])

    def test_js_string_matches_javascript(self) -> None:
        cases = [
            (True, "true"),
            (False, "false"),
            (40219, "40219"),
            (1.0, "1"),
            (1.5, "1.5"),
            (1e-7, "1e-7"),
            (1e21, "1e+21"),
            (float("nan"), "NaN"),
            (float("inf"), "Infinity"),
            (float("-inf"), "-Infinity"),
        ]
        for value, expected in cases:
            self.assertEqual(js_string(value), expected, value)

    def test_binary_kinds(self) -> None:
        self.assertEqual(binary_kind({"type": "image", "source": {"type": "base64"}}), "image")
        self.assertEqual(binary_kind({"type": "image_url", "image_url": {"url": "u"}}), "image")
        self.assertEqual(binary_kind({"type": "input_image"}), "image")
        self.assertEqual(binary_kind({"type": "document", "source": {"type": "base64"}}), "document")
        self.assertIsNone(binary_kind({"type": "document", "source": {"type": "text"}}))
        self.assertIsNone(binary_kind({"type": "document", "source": {"type": "content"}}))
        self.assertEqual(binary_kind({"type": "input_audio"}), "audio")
        self.assertEqual(binary_kind({"type": "file", "file": {}}), "file")
        self.assertIsNone(binary_kind({"type": "file"}))
        self.assertEqual(binary_kind({"type": "container_upload"}), "file")
        self.assertEqual(binary_kind({"type": "search_result", "source": {"type": "url"}}), "search_result")
        self.assertEqual(binary_kind({"source": {"type": "file"}}), "binary")
        self.assertIsNone(binary_kind({"type": "text", "text": "hi"}))
        unit = next(u for u in scan_units({"c": [{"type": "image"}]}) if isinstance(u, BinaryUnit))
        self.assertEqual(unit.path, ("c", 0))

    def test_caps_and_non_json_values_raise(self) -> None:
        with self.assertRaises(ScanLimitError):
            list(scan_units(nested(70)))
        list(scan_units(nested(60)))
        with self.assertRaises(ScanLimitError):
            list(scan_units(["x"] * 20, ScanLimits(max_nodes=10)))
        with self.assertRaises(ScanLimitError):
            list(scan_units(["x" * 50] * 3, ScanLimits(max_chars=100)))
        for bad in ({1: "x"}, {"a": b"x"}, {"a": {1, 2}}):
            with self.assertRaises(ScanLimitError):
                list(scan_units(bad))

    def test_a_cycle_hits_the_depth_cap(self) -> None:
        loop: list = []
        loop.append(loop)
        with self.assertRaises(ScanLimitError):
            list(scan_units(loop))


class Normalise(unittest.TestCase):
    def found(self, text: str) -> list[tuple[str, str]]:
        return [(f.category, text[f.start : f.end]) for f in detect(text, RULES)]

    def test_zero_width_and_escapes_and_full_width(self) -> None:
        for text in (
            "ana.duarte\u200b@northgate.internal",
            "ana.duarte%40northgate.internal",
            "ana.duarte\\u0040northgate.internal",
            "ana.duarte＠northgate.internal",
        ):
            self.assertEqual([c for c, _ in self.found(text)], ["email"], text)
            self.assertEqual(self.found(text)[0][1], text, "the span maps back to the whole original")

    def test_dashes_fold(self) -> None:
        self.assertEqual([c for c, _ in self.found("card 4000–1234–5678–9017")], ["card"])

    def test_base64_and_hex_at_depth_one_and_two(self) -> None:
        once = base64.b64encode(f"mail {EMAIL}".encode()).decode()
        twice = base64.b64encode(once.encode()).decode()
        hexed = f"mail {EMAIL}".encode().hex()
        for text in (once, twice, hexed):
            found = detect(f"see {text} ok", RULES)
            self.assertEqual([f.category for f in found], ["email"], text)
            self.assertTrue(found[0].encoded)
            self.assertEqual((found[0].start, found[0].end), (4, 4 + len(text)), "the whole run")
        thrice = base64.b64encode(twice.encode()).decode()
        self.assertEqual(detect(thrice, RULES), [], "depth is capped at 2")

    def test_clean_text_has_no_views_and_too_many_runs_raise(self) -> None:
        self.assertEqual(views("plain words"), [])
        run = base64.b64encode(b"hello there, friend!").decode()
        with self.assertRaises(DecodeLimitError):
            views(" ".join([run] * (MAX_VIEWS + 1)))

    def test_html_references_and_characters_that_do_not_show(self) -> None:
        for text in (
            "ana.duarte&#64;northgate.internal",
            "ana.duarte&#x40;northgate.internal",
            "ana.duarte&commat;northgate.internal",
            "ana.duarte\u034f@northgate.internal",  # combining grapheme joiner
            "ana.duarte\u3164@northgate.internal",  # Hangul filler
            "ana.duarte\u2800@northgate.internal",  # braille blank
            "ana.duarte\x00@northgate.internal",
            "ana.duarte\u202e@northgate.internal",  # right-to-left override
        ):
            self.assertEqual(self.found(text), [("email", text)], ascii(text))

    def test_look_alike_letters_and_digits_of_other_scripts(self) -> None:
        cyrillic_a = "\u0430"
        text = f"{cyrillic_a}na.duarte@northgate.internal"
        self.assertEqual(self.found(text), [("email", text)])
        arabic_indic = CARD.translate({ord("0") + n: 0x0660 + n for n in range(10)})
        keycaps = "".join(ch + "\ufe0f\u20e3" if ch.isdigit() else ch for ch in CARD)
        self.assertEqual(self.found(arabic_indic), [("card", arabic_indic)])
        self.assertEqual([c for c, _ in self.found(keycaps)], ["card"])
        label = f"p{cyrillic_a}ssword = correct-horse-battery-9"
        self.assertEqual([c for c, _ in self.found(label)], ["secret"])

    def test_ordinary_text_in_other_scripts_is_not_held(self) -> None:
        for text in (
            "Привет, как дела?",
            "Καλημέρα κόσμε",
            "naïve café, 12 items &amp; 3 more",
            "السعر ١٢٣ فقط",
        ):
            self.assertEqual(self.found(text), [], text)


class Resolve(unittest.TestCase):
    """`resolve` is a sweep over sorted findings. It must choose exactly what comparing every pair chose."""

    KINDS = (("card", "PG-CARD-001"), ("secret", "PG-SECRET-003"), ("email", "PG-EMAIL-001"),
             ("phone", "PG-PHONE-001"), ("private_ip", "PG-IP-001"))  # fmt: skip

    @staticmethod
    def pairwise(findings: list[Finding]) -> list[Finding]:
        def is_block(f: Finding) -> bool:
            return RULES.categories[f.category].action == "block"

        unique = {
            (f.category, f.rule_id, f.start, f.end): f
            for f in sorted(findings, key=lambda f: f.layer == "L1")
        }
        blocks = sorted(
            (f for f in unique.values() if is_block(f)), key=lambda f: (f.start, f.end, f.rule_id)
        )
        masks = [
            f
            for f in unique.values()
            if not is_block(f) and not any(b.start < f.end and f.start < b.end for b in blocks)
        ]
        masks.sort(key=lambda f: (-(f.end - f.start), f.start, f.rule_id))
        kept: list[Finding] = []
        for f in masks:
            if not any(k.start < f.end and f.start < k.end for k in kept):
                kept.append(f)
        kept.sort(key=lambda f: f.start)
        return blocks + kept

    def test_same_choice_as_comparing_every_pair(self) -> None:
        rng = random.Random(20261126)
        for _ in range(400):
            width = rng.choice((20, 60, 400))
            findings = []
            for _ in range(rng.randint(0, 40)):
                category, rule_id = rng.choice(self.KINDS)
                start = rng.randrange(width)
                layer = rng.choice(("L0", "L1"))
                findings.append(Finding(category, rule_id, (), start, start + rng.randint(1, 15), layer))
            self.assertEqual(resolve(list(findings), RULES), self.pairwise(findings))

    def test_many_findings_cost_no_more_than_sorting_them(self) -> None:
        # 30,000 findings compared pair by pair is 450 million comparisons: minutes. The sweep takes a moment.
        findings = [Finding("email", "PG-EMAIL-001", (), n * 10, n * 10 + 8, "L1") for n in range(30_000)]
        findings += [Finding("card", "PG-CARD-001", (), n * 10_000, n * 10_000 + 4, "L1") for n in range(30)]
        started = time.perf_counter()
        kept = resolve(findings, RULES)
        self.assertLess(time.perf_counter() - started, 3.0)
        self.assertEqual(len(kept), 30_000, "30 block findings, and each hides one of the mask findings")

    def test_mask_text_with_many_findings_and_with_overlapping_ones(self) -> None:
        vault = Vault(key=b"m" * 32)
        text = " ".join(f"user{n}@northgate.internal" for n in range(2_000))
        masked = mask_text(text, detect(text, RULES), vault, RULES)
        self.assertNotIn("northgate", masked)
        self.assertEqual(unmask(masked, vault), text)
        overlapping = [
            Finding("email", "PG-EMAIL-001", (), 0, 12, "L1"),
            Finding("phone", "PG-PHONE-001", (), 8, 20, "L1"),
        ]
        with self.assertRaises(ValueError):  # the guard turns any error into a block
            mask_text("x" * 30, overlapping, vault, RULES)


class PolicyTests(unittest.TestCase):
    def test_defaults_and_loosening_rules(self) -> None:
        policy = Policy.from_mapping({}, RULES)
        self.assertEqual((policy.profile, policy.mode, policy.on_block), ("lite", "enforce", "refuse"))
        self.assertEqual(policy.action("email", RULES), "mask")
        self.assertEqual(
            Policy.from_mapping({"categories": {"email": "allow"}}, RULES).action("email", RULES), "allow"
        )
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"categories": {"card": "mask"}}, RULES)

    def test_providers_only_tighten(self) -> None:
        policy = Policy.from_mapping({"providers": {"deepseek": {"categories": {"email": "block"}}}}, RULES)
        self.assertEqual(policy.action("email", RULES, "deepseek"), "block")
        self.assertEqual(policy.action("email", RULES, "anthropic"), "mask")
        with self.assertRaises(PolicyError):
            Policy.from_mapping(
                {"categories": {"email": "block"}, "providers": {"x": {"categories": {"email": "mask"}}}},
                RULES,
            )

    def test_bad_policies_are_refused(self) -> None:
        for bad in (
            [],
            {"nope": 1},
            {"version": 2},
            {"extends": "builtin:huge"},
            {"mode": "loud"},
            {"categories": {"nope": "mask"}},
            {"categories": {"email": "maybe"}},
            {"on_block": "local"},
            {"on_block": "drop"},
            {"local": {"url": "ftp://x"}},
            {"shadow_block_categories": "yes"},
            {"allow": {"values_file": "/does/not/exist"}},
            {"overlays": [3]},
            {"providers": {"x": []}},
        ):
            with self.assertRaises(PolicyError, msg=bad):
                Policy.from_mapping(bad, RULES)  # type: ignore[arg-type]

    def test_local_url_must_be_local(self) -> None:
        check_local_url("http://127.0.0.1:11500")
        check_local_url("http://localhost:11434/v1")
        check_local_url("http://[::1]:8080")
        check_local_url("http://192.168.1.20:8080", ("192.168.1.20",))
        check_local_url("http://yserver.lan:8080", ("yserver.lan",))
        for bad, hosts in (
            ("http://192.168.1.20", ()),
            ("http://8.8.8.8", ("8.8.8.8",)),
            ("http://api.example.org", ()),
            ("file:///x", ()),
        ):
            with self.assertRaises(PolicyError, msg=bad):
                check_local_url(bad, hosts)

    def test_files_json_yaml_allowlist_and_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "allow.txt").write_text(f"# team inbox\n{EMAIL}\n")
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"allow": {"values_file": "allow.txt"}}))
            policy = Policy.load(path, RULES)
            self.assertTrue(policy.allowed(EMAIL))
            self.assertFalse(policy.allowed(OTHER_EMAIL))
            self.assertNotIn(EMAIL, repr(policy))
            (Path(tmp) / "bad.json").write_text("{")
            with self.assertRaises(PolicyError):
                Policy.load(Path(tmp) / "bad.json", RULES)
            with self.assertRaises(PolicyError):
                Policy.load(Path(tmp) / "missing.json", RULES)
        self.assertEqual(parse_overrides(" email, phone ,"), {"email", "phone"})
        self.assertEqual(parse_overrides(None), set())
        self.assertEqual(strip_markers("a [[send-as-is:email,phone]] b"), ("a  b", {"email", "phone"}))


class VaultTests(unittest.TestCase):
    def test_shapes(self) -> None:
        mac = bytes(range(32))
        self.assertRegex(
            make_surrogate(mac, "email", "", EMAIL, False) or "", r"^m-[a-z2-7]{6}@masked\.invalid$"
        )
        self.assertRegex(make_surrogate(mac, "phone", "", PHONE, False) or "", r"^\+44 7700 900\d{3}$")
        self.assertRegex(
            make_surrogate(mac, "private_ip", "", "10.42.0.7", False) or "",
            r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$",
        )
        self.assertRegex(make_surrogate(mac, "private_ip", "", "fd00::1", False) or "", r"^2001:db8::")
        self.assertRegex(make_surrogate(mac, "home_path", "", "jdoe", False) or "", r"^u-[a-z2-7]{6}$")
        self.assertRegex(make_surrogate(mac, "tag", "IBAN", "x", False) or "", r"^<IBAN_[a-z2-7]{6}>$")
        self.assertRegex(make_surrogate(mac, "phone", "PHONE", PHONE, True) or "", r"^<PHONE_[a-z2-7]{6}>$")

    def test_same_value_same_surrogate_and_sessions_differ(self) -> None:
        vault = Vault()
        first = vault.surrogate("email", EMAIL, "email", "")
        self.assertEqual(vault.surrogate("email", EMAIL, "email", ""), first)
        self.assertNotEqual(vault.surrogate("email", OTHER_EMAIL, "email", ""), first)
        self.assertEqual(vault.value(first), EMAIL)
        self.assertTrue(vault.issued(first))
        self.assertNotEqual(Vault().surrogate("email", EMAIL, "email", ""), first)
        self.assertNotIn(EMAIL, repr(vault))

    def test_collisions_bump_and_never_reuse_a_surrogate(self) -> None:
        vault = Vault(key=b"k" * 32)
        phones = {vault.surrogate("phone", f"07700 9{n:05d}", "phone", "PHONE") for n in range(1500)}
        self.assertEqual(len(phones), 1500, "1000 drama numbers, then tag surrogates")
        self.assertTrue(any(p.startswith("<PHONE_") for p in phones))

    def test_sessions_are_bound_to_the_caller_and_expire(self) -> None:
        now = [0.0]
        store = SessionStore(idle_seconds=100, clock=lambda: now[0])
        mine = store.vault("caller-a", "s1")
        mine.surrogate("email", EMAIL, "email", "")
        self.assertIs(store.vault("caller-a", "s1"), mine)
        self.assertEqual(store.vault("caller-b", "s1").surrogates(), [], "another caller, same session id")
        now[0] = 50
        self.assertIs(store.vault("caller-a", "s1"), mine)
        now[0] = 500
        self.assertIsNot(store.vault("caller-a", "s1"), mine)
        self.assertEqual(len(store), 1)

    def test_every_surrogate_shape_is_one_the_unmasker_looks_for(self) -> None:
        vault = Vault(key=b"s" * 32)
        made = [
            vault.surrogate("email", EMAIL, "email", ""),
            vault.surrogate("private_ip", "10.42.0.7", "private_ip", ""),
            vault.surrogate("private_ip", "fd00::1", "private_ip", ""),
            vault.surrogate("home_path", "jdoe", "home_path", ""),
            vault.surrogate("iban", "x", "tag", "IBAN"),
            vault.surrogate("nhs-number", "y", "tag", "NHS-NUMBER"),
        ]
        made += [vault.surrogate("phone", f"07700 9{n:05d}", "phone", "PHONE") for n in range(1_100)]
        for surrogate in made:
            self.assertIsNotNone(SURROGATE.fullmatch(surrogate), surrogate)
            self.assertEqual(vault.longest, max(len(m) for m in made))
            self.assertTrue(vault.starts_one(surrogate[:3]))
        self.assertFalse(vault.starts_one("zz"))

    def test_an_idle_vault_is_never_handed_back_and_the_store_is_swept(self) -> None:
        now = [0.0]
        store = SessionStore(idle_seconds=100, clock=lambda: now[0])
        old = [store.vault("caller", f"s{n}") for n in range(50)]
        now[0] = 100.5  # past the idle time, before any sweep is due
        self.assertIsNot(store.vault("caller", "s0"), old[0])
        now[0] = 400
        store.vault("caller", "new")
        self.assertEqual(len(store), 1, "the other 50 are gone")

    def test_a_lookup_does_not_walk_every_session(self) -> None:
        # Sweeping every session on every request made each request cost in proportion to the sessions alive.
        store = SessionStore()
        for n in range(20_000):
            store.vault("caller", f"s{n}")
        started = time.perf_counter()
        for n in range(20_000):
            store.vault("caller", f"s{n}")
        self.assertLess(time.perf_counter() - started, 2.0)


class Unmasking(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = Vault(key=b"u" * 32)
        self.email = self.vault.surrogate("email", EMAIL, "email", "")
        self.tag = self.vault.surrogate("iban", 'GB "quoted" \\ value', "tag", "IBAN")
        self.ip = self.vault.surrogate("private_ip", "10.42.0.7", "private_ip", "")

    def test_only_issued_surrogates_exactly(self) -> None:
        text = f"to {self.email}, from {self.ip}; not <IBAN_zzzzzz> or {self.email.upper()}"
        out = unmask(text, self.vault)
        self.assertIn(EMAIL, out)
        self.assertIn("10.42.0.7", out)
        self.assertIn("<IBAN_zzzzzz>", out)
        self.assertIn(self.email.upper(), out)
        self.assertEqual(unmask("nothing here", Vault()), "nothing here")

    def test_longest_first(self) -> None:
        vault = Vault()
        vault._by_surrogate.update({"192.0.2.1": "a", "192.0.2.12": "b"})
        vault.version += 1
        self.assertEqual(unmask("192.0.2.12 and 192.0.2.1", vault), "b and a")

    def test_stream_equals_whole_text_at_every_split(self) -> None:
        text = f"Dear {self.email}, the host {self.ip} and {self.tag}. Bye {self.email}"
        whole = unmask(text, self.vault)
        for cut in range(len(text) + 1):
            stream = StreamUnmasker(self.vault)
            self.assertEqual(stream.feed(text[:cut]) + stream.feed(text[cut:]) + stream.flush(), whole, cut)
        stream = StreamUnmasker(self.vault)
        self.assertEqual("".join(stream.feed(ch) for ch in text) + stream.flush(), whole)

    def test_holds_back_only_a_possible_surrogate(self) -> None:
        stream = StreamUnmasker(self.vault)
        self.assertEqual(stream.feed("plain text"), "plain text")
        self.assertEqual(stream.feed(" " + self.email[:4]), " ")
        self.assertEqual(stream.held, 4)
        self.assertEqual(stream.feed(self.email[4:] + " end"), EMAIL + " end")
        self.assertEqual(stream.flush(), "")

    def test_json_values_stay_valid_json(self) -> None:
        args = json.dumps({"to": self.email, "ref": self.tag})
        out = json.loads(unmask_json_text(args, self.vault))
        self.assertEqual(out, {"to": EMAIL, "ref": 'GB "quoted" \\ value'})
        buffer = ToolArgsBuffer(self.vault)
        for i in range(0, len(args), 5):
            buffer.feed(args[i : i + 5])
        self.assertEqual(json.loads(buffer.finish())["ref"], 'GB "quoted" \\ value')

    def test_a_surrogate_inside_a_longer_word_or_number_is_left_alone(self) -> None:
        # 192.0.2.16 is issued; the model writes 192.0.2.165. Replacing the first ten characters would put a
        # real address into a string that never held one.
        for text in (f"{self.ip}5", f"1{self.ip}", f"x{self.email}", f"{self.email}s", f"v{self.ip}.5"):
            self.assertEqual(unmask(text, self.vault), text)
            stream = StreamUnmasker(self.vault)
            self.assertEqual("".join(stream.feed(ch) for ch in text) + stream.flush(), text)
        for text, real in (
            (f"({self.ip})", "(10.42.0.7)"),
            (f"{self.ip}.", "10.42.0.7."),
            (f"<{self.email}>", f"<{EMAIL}>"),
        ):
            self.assertEqual(unmask(text, self.vault), real)
        phones = Vault(key=b"p" * 32)
        phone = phones.surrogate("phone", PHONE, "phone", "PHONE")
        self.assertEqual(unmask(f"{phone}7", phones), f"{phone}7")
        self.assertEqual(unmask(f"call {phone}.", phones), f"call {PHONE}.")

    def test_stream_equals_whole_text_when_surrogates_touch_other_characters(self) -> None:
        text = f"{self.ip}5 then {self.ip}, a{self.tag}b {self.email}s ({self.email}) {self.ip}"
        whole = unmask(text, self.vault)
        self.assertIn(f"{self.ip}5", whole)
        self.assertTrue(whole.endswith("10.42.0.7"))
        for cut in range(len(text) + 1):
            stream = StreamUnmasker(self.vault)
            self.assertEqual(stream.feed(text[:cut]) + stream.feed(text[cut:]) + stream.flush(), whole, cut)
        stream = StreamUnmasker(self.vault)
        self.assertEqual("".join(stream.feed(ch) for ch in text) + stream.flush(), whole)

    def test_json_escape_before_a_surrogate(self) -> None:
        # In JSON text a line break is the two characters `\n`; the `n` is not a letter the surrogate is glued to.
        args = json.dumps({"note": f"first line\n{self.ip}\t{self.email}"})
        self.assertEqual(
            json.loads(unmask_json_text(args, self.vault)), {"note": f"first line\n10.42.0.7\t{EMAIL}"}
        )

    def test_cost_does_not_grow_with_the_values_in_the_session(self) -> None:
        # One pattern built from every surrogate, rebuilt whenever the vault changed, made the 6,000th request
        # of a session far slower than the first.
        def per_call(vault: Vault, already: int) -> float:
            for n in range(already):
                vault.surrogate("email", f"user{n}@northgate.internal", "email", "")
            best = float("inf")
            for round_ in range(3):
                started = time.perf_counter()
                for n in range(50):
                    new = vault.surrogate("email", f"new{round_}-{n}@northgate.internal", "email", "")
                    unmask(f"reply to {new} today", vault)
                    residual(f"reply to {new} today", vault, RULES, ("L0", "L1"))
                best = min(best, time.perf_counter() - started)
            return best

        small = per_call(Vault(key=b"a" * 32), 100)
        large = per_call(Vault(key=b"b" * 32), 6_400)
        self.assertLess(large, 8 * small + 0.02, f"{small * 1000:.1f} ms then {large * 1000:.1f} ms")


class Audit(unittest.TestCase):
    def test_files_are_private_hashes_short_and_rotation_keeps_four(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            writer = AuditWriter(Path(tmp) / "audit.jsonl", max_bytes=600, keep=4)
            self.assertEqual(stat.S_IMODE((Path(tmp) / "audit.key").stat().st_mode), 0o600)
            digest = writer.hash_value("email", EMAIL)
            self.assertRegex(digest, r"^[0-9a-f]{8}$")
            self.assertEqual(writer.hash_value("email", EMAIL), digest)
            self.assertEqual(
                AuditWriter(Path(tmp) / "audit.jsonl").hash_value("email", EMAIL),
                digest,
                "the key file is reused",
            )
            guard = Guard.load()
            for _ in range(30):
                writer.write(guard.protect({"q": f"mail {EMAIL}"}, hasher=writer.hash_value).decision)
            files = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(
                files,
                [
                    "audit.jsonl",
                    "audit.jsonl.1",
                    "audit.jsonl.2",
                    "audit.jsonl.3",
                    "audit.jsonl.4",
                    "audit.key",
                ],
            )
            self.assertEqual(stat.S_IMODE((Path(tmp) / "audit.jsonl").stat().st_mode), 0o600)
            record = json.loads((Path(tmp) / "audit.jsonl").read_text().splitlines()[-1])
            self.assertEqual(record["action"], "mask")
            self.assertEqual(record["value_hashes"], [digest])

    def test_a_readable_key_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "audit.key"
            key.write_text("00" * 32)
            os.chmod(key, 0o644)
            with self.assertRaises(PermissionError):
                AuditWriter(Path(tmp) / "audit.jsonl")


class BodyConformance(unittest.TestCase):
    """rules/conformance.bodies.v2.json: whole bodies, as the TypeScript engine and llm-harness will run them."""

    def test_every_case(self) -> None:
        suite = json.loads(BODIES.read_text())
        self.assertEqual(suite["schema"], "privacy-gate-body-conformance/2")
        guard = Guard.load(profile=suite["profile"])
        for case in suite["cases"]:
            with self.subTest(case["name"]):
                body = nested(case["deep"]) if "deep" in case else case["body"]
                if "base64" in case:
                    encoded = base64.b64encode(case["base64"].encode()).decode()
                    body = json.loads(json.dumps(body).replace("{base64}", encoded))
                result = guard.protect(body, provider="anthropic", wire=case.get("wire", "anthropic"))
                expect, decision = case["expect"], result.decision
                self.assertEqual(decision.action, expect["action"], decision.reason)
                if expect["rules"]:
                    self.assertLessEqual(set(expect["rules"]), set(decision.rules), decision.rules)
                else:
                    self.assertEqual(decision.rules, [])
                for key in ("paths", "categories", "refused_override", "shadow_rules", "fail_closed"):
                    if key in expect:
                        self.assertEqual(getattr(decision, key), expect[key], key)
                sent = json.dumps(result.body)
                for gone in expect.get("masked_absent", []):
                    self.assertNotIn(gone, sent)
                for kept in expect.get("masked_present", []):
                    self.assertIn(kept, sent)
                if decision.action == "block":
                    self.assertIsNone(result.body)


class Facade(unittest.TestCase):
    def test_mask_then_unmask_round_trip(self) -> None:
        guard = Guard.load()
        body = {"messages": [{"role": "user", "content": f"mail {EMAIL} from 10.42.0.7 on {PHONE}"}]}
        result = guard.protect(body, caller="c", session="s")
        self.assertEqual(result.decision.action, "mask")
        self.assertEqual(
            body["messages"][0]["content"],
            f"mail {EMAIL} from 10.42.0.7 on {PHONE}",
            "the caller's body is not changed",
        )
        sent = result.body["messages"][0]["content"]
        for value in (EMAIL, "10.42.0.7", PHONE):
            self.assertNotIn(value, sent)
        stream = guard.unmasker("c", "s")
        self.assertEqual(stream.feed(sent) + stream.flush(), body["messages"][0]["content"])
        self.assertEqual(guard.unmasker("other", "s").feed(sent), sent, "another caller cannot unmask")

    def test_overrides_header_and_allowlist(self) -> None:
        guard = Guard.load()
        result = guard.protect({"q": f"mail {EMAIL}"}, overrides="email,card")
        self.assertEqual(result.decision.action, "allow")
        self.assertEqual(result.decision.override, ["email"])
        self.assertEqual(result.decision.refused_override, ["card"])
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "allow.txt").write_text(EMAIL + "\n")
            guard = Guard.load({"allow": {"values_file": str(Path(tmp) / "allow.txt")}})
        result = guard.protect({"q": f"mail {EMAIL} and {OTHER_EMAIL}"})
        self.assertEqual(result.decision.action, "mask")
        self.assertIn(EMAIL, result.body["q"])
        self.assertNotIn(OTHER_EMAIL, result.body["q"])

    def test_shadow_mode_and_r10(self) -> None:
        shadow = Guard.load({"mode": "shadow"})
        masked = shadow.protect({"q": f"mail {EMAIL}"})
        self.assertEqual((masked.decision.action, masked.decision.would_action), ("allow", "mask"))
        self.assertIn("PG-EMAIL-001", masked.decision.shadow_rules)
        self.assertEqual(masked.body, {"q": f"mail {EMAIL}"})
        self.assertEqual(
            shadow.protect({"q": f"card {CARD}"}).decision.action,
            "block",
            "shadow mode does not release a block category",
        )
        loose = Guard.load({"mode": "shadow", "shadow_block_categories": True}).protect({"q": f"card {CARD}"})
        self.assertEqual((loose.decision.action, loose.decision.would_action), ("allow", "block"))

    def test_combination(self) -> None:
        text = f"{EMAIL} {PHONE} 10.42.0.7 /home/jdoe/notes"
        lite = Guard.load().protect({"q": text}).decision
        self.assertEqual((lite.action, lite.shadow_rules), ("mask", ["PG-COMBO-001"]))
        standard = Guard.load(profile="standard", detectors={"L2": lambda text: []}).protect({"q": text})
        self.assertEqual(standard.decision.action, "block")
        self.assertIn("PG-COMBO-001", standard.decision.rules)
        three = Guard.load().protect({"q": f"{EMAIL} {PHONE} 10.42.0.7"}).decision
        self.assertEqual(three.shadow_rules, [])

    def decide(self, body: object) -> tuple[str, list[str]]:
        decision = Guard.load().protect(body, caller="c", session="s").decision
        return decision.action, decision.rules

    def test_a_field_named_as_a_secret_or_a_phone(self) -> None:
        # In JSON the label is the key and the value is a separate string, so no pattern sees both.
        for key in ("password", "db_password", "clientSecret", "api_key", "X-Api-Key", "access_token"):
            action, rules = self.decide({key: "hunter22"})
            self.assertEqual((action, "PG-SECRET-003" in rules), ("block", True), key)
        for body in ({"api_key": "<your key here>"}, {"password": "changeme"}, {"password": ""}):
            self.assertEqual(self.decide(body)[0], "allow", body)
        for body in (
            {"max_tokens": 4096, "token_count": "1234567890", "token": "abcdefgh"},
            {"count": "447700900123"},
        ):
            self.assertEqual(self.decide(body)[0], "allow", body)
        result = Guard.load().protect({"phone": "447700900123"}, caller="c", session="s")
        self.assertEqual((result.decision.action, result.decision.rules), ("mask", ["PG-PHONE-001"]))
        self.assertNotIn("447700900123", json.dumps(result.body))
        self.assertEqual(
            self.decide({"mobile": 447700900123})[0], "block", "a number cannot carry a surrogate"
        )

    def test_a_value_split_across_fields_is_held(self) -> None:
        for body in (
            {"user": "ana.duarte", "at": "@", "domain": "northgate.internal"},
            {"parts": ["ana.duarte@north", "gate.internal"]},
            {"messages": [{"content": "write to ana.duarte"}, {"content": "@northgate.internal please"}]},
            {"label": "card number", "value": CARD},
        ):
            self.assertEqual(self.decide(body)[0], "block", body)

    def test_fields_that_only_look_joined_are_released(self) -> None:
        for body in (
            {"years": ["2019", "2020", "2021", "2022"]},
            {"a": "hello", "b": "world", "n": [4000, 1234, 5678, 9017]},
            {
                "model": "local",
                "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "yes"}],
            },
        ):
            self.assertEqual(self.decide(body)[0], "allow", body)

    def test_a_match_that_stops_at_an_accented_letter_is_held(self) -> None:
        # The patterns are ASCII. `/home/josé/` matched `jos`, and the surrogate went out with the `é` after it.
        for text in ("see /home/jos\u00e9/notes", f"mail {EMAIL}\u00e9", f"\u00fc{EMAIL}"):
            self.assertEqual(self.decide({"q": text})[0], "block", ascii(text))
        self.assertEqual(self.decide({"q": "see /home/jdoe/notes"})[0], "mask")
        self.assertEqual(self.decide({"q": f"mail {EMAIL}。"})[0], "mask", "punctuation is not a letter")

    def test_the_shared_default_vault_warns_once(self) -> None:
        guard_module._shared_vault_warned = False
        guard = Guard.load()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            guard.protect({"q": f"mail {EMAIL}"}, caller="c", session="s")
            guard.protect({"q": "nothing to mask"})
            self.assertEqual(caught, [], "named caller and session, or nothing masked")
            guard.protect({"q": f"mail {EMAIL}"})
            guard.protect({"q": f"mail {OTHER_EMAIL}"})
        self.assertEqual([w.category for w in caught], [RuntimeWarning])
        self.assertIn("session", str(caught[0].message))

    def test_neighbouring_surrogates_do_not_trip_the_residual_check(self) -> None:
        # A phone surrogate then an address surrogate reads as a Luhn-valid card about one session in ten.
        text = f"{EMAIL} {PHONE} 10.42.0.7 /home/jdoe/notes"
        for n in range(200):
            decision = Guard.load().protect({"q": text}, session=str(n)).decision
            self.assertEqual(decision.action, "mask", decision.reason)

    def test_the_residual_check_still_catches_original_text(self) -> None:
        vault = Vault()
        phone = vault.surrogate("phone", PHONE, "phone", "PHONE")
        left = residual(f"call {phone}, card {CARD} today", vault, RULES, ("L0", "L1"))
        self.assertEqual([f.category for f in left], ["card"])
        self.assertEqual(
            [
                f.category
                for f in residual(f"{phone} at 10.42.0.99", vault, RULES, ("L0", "L1"))
                if f.category != "card"
            ],
            ["private_ip"],
            "an address the vault did not issue is kept",
        )
        cleared = 0
        for _ in range(300):
            fresh = Vault()
            text = (
                f"{fresh.surrogate('phone', PHONE, 'phone', 'PHONE')} "
                f"{fresh.surrogate('private_ip', '10.42.0.7', 'private_ip', '')}"
            )
            self.assertEqual(residual(text, fresh, RULES, ("L0", "L1")), [], text)
            cleared += any(f.category == "card" for f in detect(text, RULES))
        self.assertGreater(cleared, 0, "some pairs read as a card, and all of them are cleared")

    def test_on_block_local_and_provider_tightening(self) -> None:
        guard = Guard.load(
            {
                "on_block": "local",
                "local": {"url": "http://127.0.0.1:11500"},
                "providers": {"deepseek": {"categories": {"email": "block"}}},
            }
        )
        result = guard.protect({"q": f"card {CARD}"})
        self.assertEqual((result.decision.action, result.body), ("local", {"q": f"card {CARD}"}))
        self.assertFalse(result.decision.sends)
        self.assertEqual(guard.protect({"q": EMAIL}, provider="deepseek").decision.action, "local")
        self.assertEqual(guard.protect({"q": EMAIL}, provider="anthropic").decision.action, "mask")

    def test_l2_detector_findings_are_used(self) -> None:
        def names(text: str) -> list[tuple[str, int, int]]:
            at = text.find("Ana Duarte")
            return [("person_name", at, at + 10)] if at >= 0 else []

        guard = Guard.load(profile="standard", detectors={"L2": names})
        result = guard.protect({"q": "letter for Ana Duarte today"})
        self.assertEqual(result.decision.action, "mask")
        self.assertRegex(result.body["q"], r"^letter for <PERSON_[a-z2-7]{6}> today$")

    def test_a_maskable_value_in_a_number_or_a_key_is_held(self) -> None:
        def digits(text: str) -> list[tuple[str, int, int]]:
            at = text.find("7700900123")
            return [("phone", at, at + 10)] if at >= 0 else []

        guard = Guard.load(profile="standard", detectors={"L2": digits})
        decision = guard.protect({"meta": {"phone": 7700900123}}).decision
        self.assertEqual((decision.action, decision.paths), ("block", ["meta.phone"]))
        decision = guard.protect({"meta": {"x7700900123": "owner"}}).decision
        self.assertEqual((decision.action, decision.paths), ("block", ["meta.*"]))
        self.assertEqual(guard.protect({"meta": {"phone": "7700900123"}}).decision.action, "mask")

    def test_fail_closed(self) -> None:
        self.assertIn("L2", Guard.load(profile="standard").failure or "")
        for guard in (
            Guard.load({"overlays": ["/does/not/exist.json"]}),
            Guard.load({"mode": "loud"}),
            Guard.load(rules_path="/does/not/exist.json"),
            Guard.load(profile="huge"),
        ):
            decision = guard.protect({"q": "hello"}).decision
            self.assertEqual((decision.action, decision.fail_closed), ("block", True), guard.failure)
        boom = Guard.load(profile="standard", detectors={"L2": lambda text: 1 / 0})
        decision = boom.protect({"q": "hello"}).decision
        self.assertEqual((decision.action, decision.fail_closed), ("block", True))
        self.assertEqual(decision.reason, "engine error (ZeroDivisionError); nothing sent")
        wrong = Guard.load(profile="standard", detectors={"L2": lambda text: [("nope", 0, 1)]})
        self.assertEqual(wrong.protect({"q": "hello"}).decision.action, "block")
        small = Guard.load(limits=ScanLimits(max_chars=50))
        self.assertTrue(small.protect({"q": "x" * 100}).decision.fail_closed)
        self.assertTrue(Guard.load().protect({"q": b"bytes"}).decision.fail_closed)

    def test_overlay_pinning(self) -> None:
        categories = {"secret": json.loads(Path(RULES_PATH).read_text())["categories"]["secret"]}
        overlay = {
            "schema": "privacy-gate-rules/2",
            "id": "org",
            "version": "1",
            "categories": categories,
            "rules": [
                {
                    "id": "PG-ORG-001",
                    "title": "project code",
                    "category": "secret",
                    "patterns": ["\\bPRJ-[0-9]{4}\\b"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "org.json"
            raw = json.dumps(overlay).encode()
            path.write_bytes(raw)
            good = hashlib.sha256(raw).hexdigest()
            guard = Guard.load({"overlays": [{"path": str(path), "sha256": good}]})
            self.assertIsNone(guard.failure)
            self.assertEqual(guard.protect({"q": "see PRJ-1234"}).decision.rules, ["PG-ORG-001"])
            self.assertNotEqual(guard.ruleset.sha256 if guard.ruleset else "", RULES.sha256)
            bad = Guard.load({"overlays": [{"path": str(path), "sha256": "0" * 64}]})
            self.assertIn("pinned", bad.failure or "")

    def test_safe_paths(self) -> None:
        self.assertEqual(safe_path(("messages", 0, "content")), "messages.0.content")
        self.assertEqual(safe_path(("metadata", EMAIL)), "metadata.*")
        self.assertEqual(safe_path(("metadata", "owner"), True), "metadata.*")
        self.assertEqual(safe_path(()), "$")

    def test_no_value_reaches_a_decision_an_audit_line_or_the_console(self) -> None:
        planted = [EMAIL, PHONE, "10.42.0.7", CARD.replace(" ", ""), SECRET, "jdoe"]
        bodies = [
            {"q": f"mail {EMAIL} on {PHONE} from 10.42.0.7 at /home/jdoe/x"},
            {"q": f"card {CARD.replace(' ', '')}"},
            {"tools": [{"input": {"password": SECRET}}]},
            {EMAIL: {"note": f"call {PHONE}"}},
            {"q": f"mail {EMAIL} [[send-as-is:email,card]]"},
        ]
        guards = [
            Guard.load(),
            Guard.load({"mode": "shadow"}),
            Guard.load(profile="standard", detectors={"L2": lambda t: 1 / 0}),
        ]
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(out), redirect_stderr(err):
            writer = AuditWriter(Path(tmp) / "audit.jsonl")
            dumps = []
            for guard in guards:
                for body in bodies:
                    decision = guard.protect(body, hasher=writer.hash_value).decision
                    writer.write(decision)
                    dumps.append(json.dumps(decision.to_dict()))
                    dumps.append(repr(decision))
            dumps.append((Path(tmp) / "audit.jsonl").read_text())
        dumps += [out.getvalue(), err.getvalue()]
        for value in planted:
            for dump in dumps:
                self.assertNotIn(value, dump)


if __name__ == "__main__":
    unittest.main()
