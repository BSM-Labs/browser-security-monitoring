"""
BSM Weighted Behavioral Scorer (self-contained Python implementation).

Implements the nine-pattern weighted DFA scoring described in:
  Vadlamani et al., "BSM: A Browser-Resident Framework for Real-Time Detection
  of JavaScript API Abuse and Prompt Injection Attacks," IEEE Access (under
  review), Table 2 (Monitored Detection Vectors with Empirically Derived Weights).

Scoring rules implemented:
  1. Nine regex patterns, each with an integer weight from Table 2.
  2. Per-pattern count cap of 5 (each pattern contributes at most 5 x weight).
  3. Co-occurrence bonus: +20 points if BOTH "eval" pattern AND any encoding
     pattern (hex/octal/unicode) match at least once. (Per Section IV-B and
     ablation results in Table 18.)
  4. Static source analysis mode: applies regex to full file content as text.

The deployment threshold is T = 40.

Usage:
    from bsm_scorer import score_file, score_text
    score = score_file("path/to/file.js")            # int
    score, breakdown = score_file("...", verbose=True)
"""

import re
from pathlib import Path
from typing import Tuple, Dict, Union

# Patterns and weights are copied verbatim from Table 2 of the manuscript.
# Each entry: (pattern_name, compiled_regex, weight)
PATTERNS = [
    ("eval",                re.compile(r"\beval\s*\("),               15),
    ("function_constr",     re.compile(r"Function\s*\(\s*['\"]"),     12),
    ("unescape",            re.compile(r"unescape\s*\("),             10),
    ("fromCharCode",        re.compile(r"String\.fromCharCode"),       8),
    ("bracket_notation",    re.compile(r"\[\s*['\"][a-zA-Z_]"),        3),
    ("variable_aliasing",   re.compile(r"=\s*(window|document)"),      2),
    ("hex_encoding",        re.compile(r"\\x[0-9a-fA-F]{2}"),          1),
    ("octal_encoding",      re.compile(r"\\[0-7]{3}"),                 1),
    ("unicode_encoding",    re.compile(r"\\u[0-9a-fA-F]{4}"),          1),
]

PER_PATTERN_CAP = 5
COOCCURRENCE_BONUS = 20
# The eval+encoding bonus fires when eval co-occurs with ANY deobfuscation
# or payload-encoding primitive. The published Table 2 weights describe
# unescape as "Deobfuscation" and String.fromCharCode as "Payload encoding",
# so both qualify as encoding contributors for the co-occurrence bonus
# (consistent with Section IV-B framing).
ENCODING_PATTERNS = {
    "unescape",
    "fromCharCode",
    "hex_encoding",
    "octal_encoding",
    "unicode_encoding",
}
DEPLOYMENT_THRESHOLD = 40


def score_text(source: str, verbose: bool = False
              ) -> Union[int, Tuple[int, Dict[str, int]]]:
    """
    Score a JavaScript source string using BSM's nine-pattern weighted scorer.

    Args:
        source: full JavaScript source as a string.
        verbose: if True, return (score, breakdown) where breakdown maps
                 pattern name to its contribution to the total.

    Returns:
        Integer threat score, OR (score, breakdown_dict) if verbose=True.
    """
    breakdown: Dict[str, int] = {}
    total = 0
    eval_matched = False
    encoding_matched = False

    for name, regex, weight in PATTERNS:
        match_count = len(regex.findall(source))
        capped = min(match_count, PER_PATTERN_CAP)
        contribution = capped * weight
        breakdown[name] = contribution
        total += contribution

        if name == "eval" and match_count > 0:
            eval_matched = True
        if name in ENCODING_PATTERNS and match_count > 0:
            encoding_matched = True

    if eval_matched and encoding_matched:
        breakdown["eval_plus_encoding_bonus"] = COOCCURRENCE_BONUS
        total += COOCCURRENCE_BONUS
    else:
        breakdown["eval_plus_encoding_bonus"] = 0

    if verbose:
        return total, breakdown
    return total


def score_file(path: Union[str, Path], verbose: bool = False
              ) -> Union[int, Tuple[int, Dict[str, int]]]:
    """
    Score a JavaScript file from disk.

    Args:
        path: filesystem path to .js file.
        verbose: see score_text.

    Returns:
        Integer threat score, OR (score, breakdown_dict) if verbose=True.
    """
    p = Path(path)
    source = p.read_text(encoding="utf-8", errors="ignore")
    return score_text(source, verbose=verbose)


# Quick self-test when run directly.
if __name__ == "__main__":
    import sys

    # Test 1: trivial benign code (should score very low)
    benign = "console.log('hello world'); var x = 1 + 2;"
    s = score_text(benign)
    print(f"Benign trivial: score = {s} (expected: 0)")
    assert s == 0, f"expected 0, got {s}"

    # Test 2: bare eval call (should score 15)
    bare_eval = "eval('console.log(1)');"
    s = score_text(bare_eval)
    print(f"Bare eval:      score = {s} (expected: 15)")
    assert s == 15, f"expected 15, got {s}"

    # Test 3: eval + 3 hex sequences (15 eval + 3*1 hex + 20 bonus = 38)
    eval_hex = r"eval('\x61\x62\x63');"
    s, breakdown = score_text(eval_hex, verbose=True)
    print(f"Eval + hex:     score = {s} (expected: 38)")
    print(f"                breakdown = {breakdown}")
    assert s == 38, f"expected 38, got {s}"

    # Test 4: malicious-like sample (eval + multiple encodings + fromCharCode)
    malicious = (
        r"var x = String.fromCharCode(101,118,97,108);"
        r"eval('\x61\x62\x63\x64\x65');"
        r"var y = unescape('%41%42%43');"
        r"document['cookie'] = 'stolen';"
    )
    s, breakdown = score_text(malicious, verbose=True)
    print(f"Malicious-like: score = {s}")
    print(f"                breakdown = {breakdown}")
    assert s >= DEPLOYMENT_THRESHOLD, f"expected >= 40, got {s}"

    # Test 5: file scoring (write a temp file)
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(malicious)
        tmp_path = f.name
    s = score_file(tmp_path)
    print(f"From file:      score = {s}")

    print("\nAll self-tests passed.")
