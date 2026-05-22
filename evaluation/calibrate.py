"""
Calibration: verify bsm_scorer.py reproduces the paper's existing numbers.

Run this BEFORE running experiment1_whitelist.py or experiment2_adversarial.py.
If calibration passes, the scorer is correctly reproducing paper's
existing harness. If it fails, you need to investigate the discrepancy
before trusting the new experiment numbers.

EXPECTED (from published Tables 13 and 14):
  Benign 48-library corpus:    10/48 flagged  ->  20.8% FPR
  Malicious 1,061-sample set:  632/1,061 flagged at T=40  ->  59.6% TPR

ACCEPTABLE TOLERANCE: +/- 2 absolute percentage points. The static-source
scoring is deterministic, so exact reproduction is the goal; small drift
may indicate a different file encoding handling in the original harness.

If numbers differ by more than 2 points, see the troubleshooting block
at the bottom of this script.
"""

from pathlib import Path

from bsm_scorer import score_file, DEPLOYMENT_THRESHOLD

BENIGN_DIR    = Path("eval_corpus/benign_48")
MALICIOUS_DIR = Path("eval_corpus/malicious_1061")

# Published numbers from Table 13 (tab:extended_threshold) at T=40
EXPECTED_BENIGN_FLAGGED   = 10
EXPECTED_BENIGN_TOTAL     = 48
EXPECTED_MALICIOUS_TPR    = 59.6
EXPECTED_BENIGN_FPR       = 20.8

TOLERANCE_PCT_POINTS = 2.0


def evaluate(directory: Path, label: str):
    # Malicious corpus contains both .js and .html samples (Petrak collection).
    # Benign corpus is libraries only (.js). The directory contents determine
    # what we pick up; including both extensions is safe for either side.
    files = sorted(list(directory.glob("*.js")) + list(directory.glob("*.html")))
    if not files:
        raise SystemExit(f"ERROR: no .js or .html files in {directory}")
    flagged = 0
    score_distribution = {}
    for f in files:
        s = score_file(f)
        score_distribution[s] = score_distribution.get(s, 0) + 1
        if s >= DEPLOYMENT_THRESHOLD:
            flagged += 1
    return {
        "label": label,
        "n": len(files),
        "flagged": flagged,
        "rate_pct": flagged / len(files) * 100,
        "score_distribution": score_distribution,
    }


def main():
    print("Calibrating BSM scorer against published paper numbers...\n")

    # ---- Benign
    if BENIGN_DIR.exists():
        benign = evaluate(BENIGN_DIR, "benign")
        print(f"Benign corpus: {benign['flagged']}/{benign['n']} flagged "
              f"({benign['rate_pct']:.1f}% FPR)")
        print(f"  Expected: {EXPECTED_BENIGN_FLAGGED}/{EXPECTED_BENIGN_TOTAL} "
              f"({EXPECTED_BENIGN_FPR}% FPR)")
        diff = abs(benign["rate_pct"] - EXPECTED_BENIGN_FPR)
        if diff <= TOLERANCE_PCT_POINTS:
            print(f"  PASS (within {TOLERANCE_PCT_POINTS} pp tolerance, "
                  f"actual diff {diff:.2f} pp)\n")
        else:
            print(f"  FAIL: diff {diff:.2f} pp exceeds tolerance "
                  f"{TOLERANCE_PCT_POINTS} pp\n")
            print("  Score distribution (helps diagnose drift):")
            for score in sorted(benign["score_distribution"].keys()):
                print(f"    score {score}: {benign['score_distribution'][score]} files")
            print()
    else:
        print(f"SKIPPED benign calibration: {BENIGN_DIR} does not exist.\n")

    # ---- Malicious
    if MALICIOUS_DIR.exists():
        malicious = evaluate(MALICIOUS_DIR, "malicious")
        print(f"Malicious corpus: {malicious['flagged']}/{malicious['n']} flagged "
              f"({malicious['rate_pct']:.1f}% TPR)")
        print(f"  Expected: ~{int(EXPECTED_MALICIOUS_TPR/100 * malicious['n'])}/"
              f"{malicious['n']} ({EXPECTED_MALICIOUS_TPR}% TPR)")
        diff = abs(malicious["rate_pct"] - EXPECTED_MALICIOUS_TPR)
        if diff <= TOLERANCE_PCT_POINTS:
            print(f"  PASS (within {TOLERANCE_PCT_POINTS} pp tolerance, "
                  f"actual diff {diff:.2f} pp)\n")
        else:
            print(f"  FAIL: diff {diff:.2f} pp exceeds tolerance "
                  f"{TOLERANCE_PCT_POINTS} pp\n")
            print("  Top score bins:")
            sorted_scores = sorted(malicious["score_distribution"].items(),
                                   key=lambda kv: -kv[1])
            for score, count in sorted_scores[:15]:
                print(f"    score {score}: {count} files")
            print()
    else:
        print(f"SKIPPED malicious calibration: {MALICIOUS_DIR} does not exist.\n")

    # ---- Troubleshooting block
    print("=" * 60)
    print("If calibration FAILED, check the following in this order:")
    print("=" * 60)
    print("""
  1. Your original harness may include an additional rule beyond Table 2.
     Compare bsm_scorer.PATTERNS to your harness source. If your harness has
     an extra pattern (e.g., a tenth pattern not in the published table),
     add it to PATTERNS in bsm_scorer.py with the same weight.

  2. Your harness may use a different per-pattern cap. Section IV-B states
     the cap is 5; if your harness uses a different cap, edit
     PER_PATTERN_CAP in bsm_scorer.py.

  3. The eval+encoding bonus may have a different magnitude than 20.
     The paper states +20 (Section IV-B). If your harness uses a different
     value, edit COOCCURRENCE_BONUS in bsm_scorer.py.

  4. File encoding: some malware samples contain non-UTF-8 bytes. The
     scorer uses errors='ignore' which silently drops invalid bytes. If
     your original harness used a different decode strategy (e.g., latin-1
     for everything), edit the read_text call in bsm_scorer.score_file.

  5. Whitespace in regexes: the published patterns use \\s* in places like
     'eval\\s*\\('. If your harness compiled these slightly differently
     (e.g., '\\s+' or no whitespace), regex match counts will differ
     marginally. Check the PATTERNS list against your harness source.

  After making any change, re-run this calibration script. Once it passes,
  proceed to experiment1_whitelist.py and experiment2_adversarial.py.
""")


if __name__ == "__main__":
    main()
