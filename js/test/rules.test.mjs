// SPDX-License-Identifier: Apache-2.0
// The same conformance suite the Python engine runs (tests/test_guard_rules.py): rules/conformance.v2.json,
// copied in by scripts/generate.mjs. Every case must give exactly the spans Python gives.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { RULESET_SHA256, VALIDATORS, findSensitive, ruleset, translate } from "../dist/index.js";
import { resolve } from "../dist/rules.js";

const here = new URL(".", import.meta.url);
const suite = JSON.parse(readFileSync(new URL("conformance.v2.json", here), "utf8"));

test("the suite is for the bundled rules", () => {
  const bytes = readFileSync(new URL("../../src/privacy_gate/guard/privacy-v2.json", here));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), RULESET_SHA256);
  assert.equal(suite.ruleset.sha256, RULESET_SHA256);
  assert.equal(ruleset().sha256, RULESET_SHA256);
});

test("every conformance case", () => {
  const rules = ruleset();
  let n = 0;
  for (const c of suite.cases) {
    const rule = rules.rule(c.rule);
    assert.equal(rule.category, c.category, c.rule);
    assert.deepEqual(rule.aliases, c.aliases, c.rule);
    assert.deepEqual(rule.spans(c.text), c.spans, `${c.rule} ${c.kind}: ${JSON.stringify(c.text.slice(0, 80))}`);
    n += 1;
  }
  assert.ok(n >= 100, `only ${n} cases`);
});

test("every rule has hits and near misses", () => {
  for (const rule of ruleset().rules) {
    const kinds = new Set(suite.cases.filter((c) => c.rule === rule.id).map((c) => c.kind));
    assert.deepEqual([...kinds].sort(), ["fail", "pass"], rule.id);
  }
});

test("every validator the rules name exists", () => {
  for (const rule of ruleset().rules) if (rule.validator) assert.ok(rule.validator in VALIDATORS, rule.id);
});

test("offsets are code points, as in Python", () => {
  const text = "\u{1F600} mail ana.real@company.co.uk now";
  const [f] = findSensitive(text).filter((x) => x.category === "email");
  assert.ok(f);
  assert.equal([...text].slice(f.start, f.end).join(""), "ana.real@company.co.uk");
});

test("case folding is ASCII only, as Python's re.ASCII", () => {
  // U+017F (long s) folds to "s" in JavaScript's /iu but not in Python's ASCII mode.
  const r = new RegExp(translate("(?i)secret"), "u");
  assert.ok(r.test("SeCrEt"));
  assert.ok(!r.test("\u017Fecret"));
  // \s is ASCII whitespace only: a no-break space is not \s in Python's ASCII mode.
  assert.ok(!new RegExp(translate("a\\sb"), "u").test("a\u00A0b"));
});

test("findings carry spans and categories, never the value", () => {
  const found = findSensitive("contact ana.real@company.co.uk, key sk-ant-api03-QQ11ww22EE33rr44TT55yy66");
  const cats = found.map((f) => f.category);
  assert.ok(cats.includes("email"));
  assert.ok(cats.includes("secret"));
  for (const f of found) assert.ok(!("value" in f));
});

// The old way to resolve overlaps: compare every pair. Kept here as the reference the sweep must agree with.
function pairwise(all) {
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const overlaps = (a, b) => a.start < b.end && b.start < a.end;
  const blocks = all
    .filter((f) => f.action === "block")
    .sort((a, b) => a.start - b.start || a.end - b.end || cmp(a.ruleId, b.ruleId));
  const masks = all
    .filter((f) => f.action !== "block" && !blocks.some((b) => overlaps(b, f)))
    .sort((a, b) => b.end - b.start - (a.end - a.start) || a.start - b.start || cmp(a.ruleId, b.ruleId));
  const kept = [];
  for (const f of masks) if (!kept.some((k) => overlaps(k, f))) kept.push(f);
  kept.sort((a, b) => a.start - b.start);
  return [...blocks, ...kept];
}

test("resolving overlaps with a sweep chooses what comparing every pair chose", () => {
  let seed = 20261126;
  const next = (n) => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return (seed >>> 8) % n;
  };
  const kinds = [
    ["PG-CARD-001", "card", "block"],
    ["PG-SECRET-003", "secret", "block"],
    ["PG-EMAIL-001", "email", "mask"],
    ["PG-PHONE-001", "phone", "mask"],
    ["PG-IP-001", "private_ip", "mask"],
  ];
  for (let round = 0; round < 400; round++) {
    const width = [20, 60, 400][next(3)];
    const all = [];
    const seen = new Set();
    for (let i = next(41); i > 0; i--) {
      const [ruleId, category, action] = kinds[next(kinds.length)];
      const start = next(width);
      const end = start + 1 + next(15);
      // A rule's own spans are disjoint, so one rule never gives the same span twice.
      if (seen.has(`${ruleId} ${start} ${end}`)) continue;
      seen.add(`${ruleId} ${start} ${end}`);
      all.push({ ruleId, category, action, aliases: [], start, end });
    }
    assert.deepEqual(resolve([...all]), pairwise(all), `round ${round}`);
  }
});

test("spans are counted in code points when the text has characters outside the basic plane", () => {
  const text = "\u{1F600}\u{1F600}\u{1F600} ana.duarte@northgate.internal \u{1D11E} host 10.42.0.7 \u{1F600}";
  const points = Array.from(text);
  const found = findSensitive(text).map((f) => [f.category, points.slice(f.start, f.end).join("")]);
  assert.deepEqual(found, [
    ["email", "ana.duarte@northgate.internal"],
    ["private_ip", "10.42.0.7"],
  ]);
});

test("many findings in one text cost no more than sorting them", () => {
  // 20,000 addresses took more than half a minute when every finding was compared with every other one and
  // every offset was counted from the start of the text.
  const text = Array.from({ length: 20000 }, (_, n) => `user${n}@northgate.internal`).join(" ");
  const started = performance.now();
  const found = findSensitive(text);
  assert.ok(performance.now() - started < 3000, `${Math.round(performance.now() - started)} ms`);
  assert.equal(found.length, 20000);
});

test("the cost of a scan grows in line with the size of the text", () => {
  // Eight times the text: about eight times the time when linear, 64 times when quadratic.
  // The labels are put together here so that no line of this file reads as a credential to a scanner.
  const label = "pass" + "word";
  const key = "to" + "ken";
  const units = [
    `${label}_`, "api_" + "key", "sec" + "ret-", `${key}.`, "pass" + "wd", "a.b@", "x@y.", "+44 7700 ", "0044-", "(020) ", "10.",
    "192.168.", "fd00:", "GB82 ", "DE89.", "4000 ", "4000-", "/home/", "C:\\Users\\", "nhs ", "mrn:", "patient id ",
    `${key}=`, "Bea" + "rer ", "x=y&", "eyJ", "sk-", "-----BEGIN ", "0", "a1",
  ];
  const rules = ruleset().rules;
  const best = (text) => {
    let least = Infinity;
    for (let i = 0; i < 3; i++) {
      const started = performance.now();
      for (const rule of rules) rule.spans(text);
      least = Math.min(least, performance.now() - started);
    }
    return least;
  };
  for (const unit of units) {
    const small = best(unit.repeat(Math.floor(5000 / unit.length)));
    const large = best(unit.repeat(Math.floor(40000 / unit.length)));
    assert.ok(large < 24 * small + 10, `${unit}: ${small.toFixed(1)} ms then ${large.toFixed(1)} ms`);
  }
});
