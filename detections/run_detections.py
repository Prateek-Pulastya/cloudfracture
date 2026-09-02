"""
run_detections.py — execute each Sigma rule against its fire/no-fire fixtures.

This is the real test the build plan calls for: not `sigma-cli` schema-linting
(which only proves the YAML is well-formed), but actually EVALUATING each rule's
detection logic against a CloudTrail event and asserting the result:
  * <rule>.fire.json    MUST match   (the rule catches the attack)
  * <rule>.nofire.json  MUST NOT match (the rule stays quiet on benign activity)

If pySigma is installed, each rule is additionally parse-validated as legitimate
Sigma. The evaluator supports the Sigma subset these rules use: field equals /
|contains / |startswith / |endswith, list values (OR), multi-field selections
(AND), and conditions with and/or/not and `all of`/`1 of`/`any of <pattern>`.

Exit code is non-zero if any rule fails — wire it straight into CI.
Run:  python detections/run_detections.py
"""

from __future__ import annotations

import fnmatch
import glob
import json
import re
import sys
from pathlib import Path

import yaml

SIGMA_DIR = Path("detections/sigma")
FIX_DIR = Path("detections/fixtures")

try:
    from sigma.collection import SigmaCollection  # pySigma
    HAVE_PYSIGMA = True
except Exception:
    HAVE_PYSIGMA = False


# ---- event flattening + value matching --------------------------------------

def flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}{k}."))
    else:
        out[prefix[:-1]] = obj
    return out


def cmp(actual, expected, mod):
    if actual is None:
        return False
    a, e = str(actual), str(expected)
    if mod == "contains":
        return e in a
    if mod == "startswith":
        return a.startswith(e)
    if mod == "endswith":
        return a.endswith(e)
    return a == e  # default: equals


def field_matches(key, expected, flat):
    field, *mods = key.split("|")
    mod = mods[0] if mods else None
    actual = flat.get(field)
    values = expected if isinstance(expected, list) else [expected]
    return any(cmp(actual, v, mod) for v in values)  # list = OR


def block_matches(block, flat):
    # a selection matches when ALL its field conditions match (AND)
    return all(field_matches(k, v, flat) for k, v in block.items())


# ---- condition expression evaluator -----------------------------------------

def eval_condition(cond, results):
    tokens = re.findall(r"\(|\)|\b\w+\*?\b", cond)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def nxt():
        nonlocal pos
        t = tokens[pos]; pos += 1; return t

    def quant(kind):  # kind in {'all','1','any'}; expects 'of' <pattern>
        nxt()  # consume 'of'
        pat = nxt()
        matched = [v for name, v in results.items()
                   if (pat == "them" or fnmatch.fnmatch(name, pat))]
        return all(matched) if kind == "all" else any(matched)

    def factor():
        t = peek()
        if t == "not":
            nxt(); return not factor()
        if t == "(":
            nxt(); v = expr();
            if peek() == ")": nxt()
            return v
        t = nxt()
        if t in ("all", "1", "any"):
            return quant(t)
        return bool(results.get(t, False))

    def term():
        v = factor()
        while peek() == "and":
            nxt(); v = v and factor()
        return v

    def expr():
        v = term()
        while peek() == "or":
            nxt(); v = v or term()
        return v

    return expr()


def rule_matches(detection, event):
    flat = flatten(event)
    cond = detection.get("condition", "selection")
    results = {name: block_matches(block, flat)
               for name, block in detection.items() if name != "condition"}
    return eval_condition(cond, results)


# ---- runner ------------------------------------------------------------------

def main():
    rule_files = sorted(glob.glob(str(SIGMA_DIR / "*.yml")))
    if not rule_files:
        print("no rules found"); return 1

    rows, failed = [], 0
    for rf in rule_files:
        text = Path(rf).read_text(encoding="utf-8")
        rule = yaml.safe_load(text)
        stem = Path(rf).stem
        det = rule["detection"]

        valid = "n/a"
        if HAVE_PYSIGMA:
            try:
                SigmaCollection.from_yaml(text); valid = "ok"
            except Exception as exc:
                valid = f"INVALID ({type(exc).__name__})"

        fire_f = FIX_DIR / f"{stem}.fire.json"
        nofire_f = FIX_DIR / f"{stem}.nofire.json"
        fire = rule_matches(det, json.loads(fire_f.read_text())) if fire_f.exists() else None
        nofire = rule_matches(det, json.loads(nofire_f.read_text())) if nofire_f.exists() else None

        ok = (fire is True) and (nofire is False)
        if not ok or valid.startswith("INVALID"):
            failed += 1
        rows.append((stem, valid, fire, nofire, ok))

    print(f"pySigma validation: {'enabled' if HAVE_PYSIGMA else 'not installed (skipped)'}\n")
    print(f"{'rule':<38}{'sigma':<8}{'fire':<7}{'nofire':<8}{'result'}")
    print("-" * 74)
    for stem, valid, fire, nofire, ok in rows:
        print(f"{stem:<38}{valid:<8}{str(fire):<7}{str(nofire):<8}{'PASS' if ok else 'FAIL'}")
    print("-" * 74)
    print(f"{len(rows)} rules, {len(rows) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
