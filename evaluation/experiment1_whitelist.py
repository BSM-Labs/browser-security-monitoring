"""
Experiment 1: BSM Content-Hash Whitelisting Evaluation
For IEEE Access resubmission Access-2026-20421, Reviewer 2 Comment 2.1.

Self-contained. Depends only on bsm_scorer.py from this package.
No imports from the BSM browser-extension repo are required.

WHAT THIS SCRIPT DOES:
  1. Builds a SHA-256 whitelist over your benign library corpus.
  2. Re-scores the benign corpus with the whitelist gate in front.
  3. Re-scores the malicious corpus with the whitelist gate in front.
  4. Runs a bypass adversarial test (malicious files renamed to library names).
  5. Prints every number the paper revisions need, labeled by placeholder name.

WHAT YOU NEED TO PROVIDE:
  - A directory of benign library .js files (48 files per the paper).
  - A directory of malicious .js files (1,061 files per the paper).
  - At minimum, 30 malicious files that score >= 40 by your existing pipeline.

DIRECTORY LAYOUT THIS SCRIPT EXPECTS:
    eval_corpus/
        benign_48/        <-- 48 production library .js files
        malicious_1061/   <-- 1,061 malicious .js files

If your directory layout differs, edit BENIGN_DIR and MALICIOUS_DIR below.

OUTPUT: a file `experiment1_results.json` plus stdout with all the numbers.
"""

import hashlib
import json
import shutil
import time
from pathlib import Path

from bsm_scorer import score_file, DEPLOYMENT_THRESHOLD

# ----------------------------------------------------------------------
# CONFIGURATION: edit these paths to match your corpus layout
# ----------------------------------------------------------------------
BENIGN_DIR    = Path("eval_corpus/benign_48")
MALICIOUS_DIR = Path("eval_corpus/malicious_1061")
OUTPUT_JSON   = Path("experiment1_results.json")
BYPASS_DIR    = Path("eval_corpus/bypass_test")   # auto-created
N_BYPASS      = 30                                # samples for bypass test
# ----------------------------------------------------------------------


def file_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file's bytes."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_whitelist(benign_dir: Path) -> dict:
    """
    Hash every benign library file. Returns {filename: sha256}.
    The whitelist is the SET of these hashes (we keep filenames for audit).
    """
    print(f"Hashing {benign_dir}...")
    wl = {}
    # Benign corpus is production libraries, which are always .js files.
    files = sorted(benign_dir.glob("*.js"))
    if not files:
        raise SystemExit(f"ERROR: no .js files found in {benign_dir}")
    for f in files:
        wl[f.name] = file_sha256(f)
    return wl


def evaluate_corpus(files, whitelist_set: set, label: str) -> dict:
    """
    For each file:
        - hash it
        - if hash is in whitelist, skip scoring (treat as benign)
        - otherwise, run BSM scorer and flag if score >= T

    Returns dict of counts and timing.
    """
    flagged = 0
    skipped = 0
    scores = []
    latencies = []

    for f in files:
        t0 = time.perf_counter()
        h = file_sha256(f)
        if h in whitelist_set:
            skipped += 1
            latencies.append((time.perf_counter() - t0) * 1000)
            scores.append(None)
            continue
        score = score_file(f)
        latencies.append((time.perf_counter() - t0) * 1000)
        scores.append(score)
        if score >= DEPLOYMENT_THRESHOLD:
            flagged += 1

    n = len(files)
    mean_lat = sum(latencies) / len(latencies) if latencies else 0.0
    std_lat = (sum((x - mean_lat) ** 2 for x in latencies) / len(latencies)) ** 0.5 \
              if latencies else 0.0

    return {
        "label": label,
        "n_total": n,
        "n_flagged": flagged,
        "n_skipped_by_whitelist": skipped,
        "n_scored": n - skipped,
        "mean_latency_ms": mean_lat,
        "std_latency_ms": std_lat,
        "scores": scores,
    }


def run_bypass_test(malicious_dir: Path, whitelist_set: set,
                    bypass_dir: Path, n_samples: int) -> dict:
    """
    Pick n_samples malicious files that BSM currently detects (score >= T),
    rename each to look like a popular library, then re-evaluate.
    A correctly designed whitelist must hash by CONTENT, so renamed files
    should still fail the whitelist check and still be flagged.
    """
    library_names = [
        "jquery-3.7.1.min.js", "react-dom.production.min.js",
        "lodash.min.js",       "moment.min.js",
        "axios.min.js",        "p5.min.js",
        "videojs.min.js",      "pixijs.min.js",
        "papaparse.min.js",    "chart.min.js",
    ]

    # Find malicious samples that BSM currently detects.
    # Malicious corpus has both .js and .html files (Petrak collection).
    print(f"\nLocating {n_samples} detected malicious samples for bypass test...")
    detected = []
    malicious_files = sorted(list(malicious_dir.glob("*.js")) +
                             list(malicious_dir.glob("*.html")))
    for f in malicious_files:
        if score_file(f) >= DEPLOYMENT_THRESHOLD:
            detected.append(f)
            if len(detected) == n_samples:
                break

    if len(detected) < n_samples:
        print(f"WARNING: only {len(detected)} detected samples available, "
              f"requested {n_samples}")

    # Stage the renamed copies.
    if bypass_dir.exists():
        shutil.rmtree(bypass_dir)
    bypass_dir.mkdir(parents=True)
    pool = (library_names * ((n_samples // len(library_names)) + 1))[:n_samples]
    for src, libname in zip(detected, pool):
        shutil.copy(src, bypass_dir / f"{src.stem}__as__{libname}")

    bypass_files = sorted(bypass_dir.glob("*.js"))
    result = evaluate_corpus(bypass_files, whitelist_set, "bypass")
    result["originals_detected"] = len(detected)
    return result


def compute_metrics(benign_eval: dict, malicious_eval: dict) -> dict:
    """Compute FPR, specificity, precision, F1 from the evaluation dicts."""
    fp = benign_eval["n_flagged"]
    n_benign = benign_eval["n_total"]
    tp = malicious_eval["n_flagged"]
    n_malicious = malicious_eval["n_total"]

    fpr = fp / n_benign * 100 if n_benign else 0.0
    specificity = (n_benign - fp) / n_benign * 100 if n_benign else 0.0
    tpr = tp / n_malicious * 100 if n_malicious else 0.0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0.0
    recall_frac = tpr / 100
    prec_frac = precision / 100
    f1 = (2 * prec_frac * recall_frac / (prec_frac + recall_frac)
          if (prec_frac + recall_frac) > 0 else 0.0)

    return {
        "fp": fp,
        "tp": tp,
        "fpr_pct": fpr,
        "tpr_pct": tpr,
        "specificity_pct": specificity,
        "precision_pct": precision,
        "f1": f1,
    }


def main():
    if not BENIGN_DIR.exists():
        raise SystemExit(f"ERROR: {BENIGN_DIR} does not exist. "
                         "Edit BENIGN_DIR at top of script.")
    if not MALICIOUS_DIR.exists():
        raise SystemExit(f"ERROR: {MALICIOUS_DIR} does not exist. "
                         "Edit MALICIOUS_DIR at top of script.")

    # ---- Step 1: build whitelist
    wl_dict = build_whitelist(BENIGN_DIR)
    wl_set = set(wl_dict.values())
    print(f"Whitelist contains {len(wl_set)} unique hashes "
          f"({len(wl_dict)} filenames).\n")

    # ---- Step 2: evaluate benign corpus with whitelist
    print("Evaluating benign corpus with whitelist gate...")
    benign_files = sorted(BENIGN_DIR.glob("*.js"))
    benign_eval = evaluate_corpus(benign_files, wl_set, "benign_with_whitelist")
    print(f"  n={benign_eval['n_total']}, "
          f"skipped_by_whitelist={benign_eval['n_skipped_by_whitelist']}, "
          f"flagged={benign_eval['n_flagged']}\n")

    # ---- Step 3: evaluate malicious corpus with whitelist
    # Malicious corpus contains both .js and .html samples (Petrak collection).
    print("Evaluating malicious corpus with whitelist gate...")
    malicious_files = sorted(list(MALICIOUS_DIR.glob("*.js")) +
                             list(MALICIOUS_DIR.glob("*.html")))
    malicious_eval = evaluate_corpus(malicious_files, wl_set,
                                     "malicious_with_whitelist")
    print(f"  n={malicious_eval['n_total']}, "
          f"skipped_by_whitelist={malicious_eval['n_skipped_by_whitelist']}, "
          f"flagged={malicious_eval['n_flagged']}\n")

    metrics = compute_metrics(benign_eval, malicious_eval)

    # ---- Step 4: bypass adversarial test
    bypass_eval = run_bypass_test(MALICIOUS_DIR, wl_set, BYPASS_DIR, N_BYPASS)
    print(f"\nBypass test: {bypass_eval['n_flagged']}/"
          f"{bypass_eval['n_total']} renamed samples still detected "
          f"({bypass_eval['n_skipped_by_whitelist']} incorrectly whitelisted)")

    # ---- Print all placeholder values for the paper
    print("\n" + "=" * 60)
    print("PLACEHOLDER VALUES FOR THE PAPER (Edits 1, 10, 12, 13):")
    print("=" * 60)
    print(f"<<WL_SIZE>>             = {len(wl_set)}")
    print(f"<<WL_LATENCY_MEAN>>     = {benign_eval['mean_latency_ms']:.3f}")
    print(f"<<WL_LATENCY_STD>>      = {benign_eval['std_latency_ms']:.3f}")
    print(f"<<WL_FPR>>              = {metrics['fpr_pct']:.1f}")
    print(f"<<WL_SPEC>> / <<WL_SPECIFICITY>> = {metrics['specificity_pct']:.1f}")
    print(f"<<WL_PREC>>             = {metrics['precision_pct']:.1f}")
    print(f"<<WL_MALICIOUS_TPR>>    = {metrics['tpr_pct']:.1f}")
    print(f"<<WL_F1>>               = {metrics['f1']:.3f}")
    print(f"<<WL_BYPASS_DETECTED>>  = {bypass_eval['n_flagged']}")
    print("=" * 60)
    print("\nNote: <<WL_AUROC>> requires re-running your AUROC computation")
    print("excluding whitelisted samples. Use your existing AUROC code; the")
    print("subset is all malicious files PLUS benign files whose hash is NOT")
    print("in wl_set. Pre-whitelist baseline AUROC reported in the paper: 0.60.\n")

    # ---- Save full results to JSON
    results = {
        "whitelist": {"size": len(wl_set), "entries": wl_dict},
        "benign_eval": {k: v for k, v in benign_eval.items() if k != "scores"},
        "malicious_eval": {k: v for k, v in malicious_eval.items() if k != "scores"},
        "metrics_post_whitelist": metrics,
        "bypass_test": {
            "n_total": bypass_eval["n_total"],
            "n_flagged": bypass_eval["n_flagged"],
            "n_skipped_by_whitelist": bypass_eval["n_skipped_by_whitelist"],
            "originals_detected": bypass_eval["originals_detected"],
        },
    }
    OUTPUT_JSON.write_text(json.dumps(results, indent=2))
    print(f"Full results saved to {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
