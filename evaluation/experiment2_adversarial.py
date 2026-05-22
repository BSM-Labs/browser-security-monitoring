"""
Experiment 2: BSM Adversarial Robustness Evaluation

Self-contained. Depends only on bsm_scorer.py.

WHAT THIS SCRIPT DOES:
  For 30 malicious samples that BSM currently detects, generates five
  transformation variants (A1, A2, A3, B1, B2) and re-scores each variant.
  Reports detection rate per variant family.

  Family A: split-token eval constructions
    A1: window["e"+"v"+"a"+"l"](...)
    A2: window[String.fromCharCode(101,118,97,108)](...)
    A3: (function(){}).constructor(...)()
  Family B: encoding substitution
    B1: hex sequences replaced with base64 + atob()
    B2: hex sequences replaced with ROT13 + inline decoder

  Family C (paraphrase, prompt injection) is already done in the paper at
  Table 12 (0/20 detected). It is not re-run here.

WHAT YOU NEED TO PROVIDE:
  A directory of malicious .js files (the same MALICIOUS_DIR as Experiment 1).
  The script will pick the first 30 that BSM detects at T = 40.

DIRECTORY LAYOUT THIS SCRIPT EXPECTS:
    eval_corpus/
        malicious_1061/   <-- 1,061 malicious .js files

OUTPUT: a file `experiment2_results.json` plus stdout with placeholder values.
"""

import base64
import codecs
import json
import re
import shutil
from pathlib import Path

from bsm_scorer import score_file, score_text, DEPLOYMENT_THRESHOLD

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
MALICIOUS_DIR = Path("eval_corpus/malicious_1061")
VARIANTS_DIR  = Path("eval_corpus/adv_variants")
OUTPUT_JSON   = Path("experiment2_results.json")
N_SAMPLES     = 30
# ----------------------------------------------------------------------


def transform_A1(src: str) -> str:
    """Bracket-indexed eval via string concatenation."""
    return re.sub(r"\beval\s*\(",
                  'window["e"+"v"+"a"+"l"](',
                  src)


def transform_A2(src: str) -> str:
    """String.fromCharCode reconstruction of 'eval'."""
    return re.sub(r"\beval\s*\(",
                  "window[String.fromCharCode(101,118,97,108)](",
                  src)


def transform_A3(src: str) -> str:
    """Function.prototype.constructor route (executes argument as code)."""
    # Replace eval(<expr>) with (function(){}).constructor(<expr>)()
    # We capture the parenthesized argument with a balanced-ish regex.
    # This is approximate but works for the common case of eval('...string...')
    # or eval(variableName).
    pattern = re.compile(r"\beval\s*\(\s*((?:[^()]+|\([^()]*\))*)\s*\)")
    return pattern.sub(r"(function(){}).constructor(\1)()", src)


def _replace_hex_run(src: str, encoder) -> str:
    """
    Find runs of 3+ consecutive \\xHH sequences and replace each run with
    encoder(decoded_bytes). The encoder returns a JS expression that
    decodes back to the same string at runtime.
    """
    def repl(match):
        hex_str = match.group(0)
        # Pull the hex pairs out: e.g. \x61\x62 -> [0x61, 0x62]
        pairs = re.findall(r"\\x([0-9a-fA-F]{2})", hex_str)
        try:
            data = bytes(int(p, 16) for p in pairs)
            return encoder(data)
        except (ValueError, UnicodeDecodeError):
            return hex_str
    return re.sub(r"(?:\\x[0-9a-fA-F]{2}){3,}", repl, src)


def transform_B1(src: str) -> str:
    """Replace runs of hex escapes with base64 + atob()."""
    def encode(data: bytes) -> str:
        b64 = base64.b64encode(data).decode("ascii")
        return f'atob("{b64}")'
    return _replace_hex_run(src, encode)


def transform_B2(src: str) -> str:
    """Replace runs of hex escapes with ROT13 + inline decoder."""
    def encode(data: bytes) -> str:
        try:
            text = data.decode("latin-1")
            rot = codecs.encode(text, "rot_13")
            # JS-side ROT13 decoder, returns the original text.
            return ('(function(s){return s.replace(/[a-zA-Z]/g,function(c){'
                    'var b=c<="Z"?90:122,n=c.charCodeAt(0)+13;'
                    'return String.fromCharCode(n<=b?n:n-26);'
                    f'}})}})("{rot}")')
        except Exception:
            # Fallback: pass through unchanged
            return data.hex()
    return _replace_hex_run(src, encode)


TRANSFORMS = {
    "A1": ("split-token bracket eval",        transform_A1),
    "A2": ("fromCharCode eval",               transform_A2),
    "A3": ("Function.constructor route",      transform_A3),
    "B1": ("base64 + atob",                   transform_B1),
    "B2": ("ROT13 + inline decoder",          transform_B2),
}


def find_detected_samples(malicious_dir: Path, n: int) -> list:
    """Iterate malicious files, return the first n that score >= T."""
    # Malicious corpus contains both .js and .html samples (Petrak collection).
    # Transformations operate via regex substitution on the file text, so they
    # work correctly on .html files containing inline JavaScript.
    detected = []
    files = sorted(list(malicious_dir.glob("*.js")) +
                   list(malicious_dir.glob("*.html")))
    for f in files:
        if score_file(f) >= DEPLOYMENT_THRESHOLD:
            detected.append(f)
            if len(detected) == n:
                break
    return detected


def main():
    if not MALICIOUS_DIR.exists():
        raise SystemExit(f"ERROR: {MALICIOUS_DIR} does not exist. "
                         "Edit MALICIOUS_DIR at top of script.")

    # Clear and recreate variants dir
    if VARIANTS_DIR.exists():
        shutil.rmtree(VARIANTS_DIR)
    VARIANTS_DIR.mkdir(parents=True)

    print(f"Finding {N_SAMPLES} malicious samples detected at T={DEPLOYMENT_THRESHOLD}...")
    samples = find_detected_samples(MALICIOUS_DIR, N_SAMPLES)
    if len(samples) < N_SAMPLES:
        print(f"WARNING: only {len(samples)} samples available, "
              f"requested {N_SAMPLES}. Continuing.")
    print(f"Got {len(samples)} samples.\n")

    # Initialize results
    results = {
        variant: {"label": label, "detected": 0, "total": 0, "scores": []}
        for variant, (label, _) in TRANSFORMS.items()
    }

    for sample in samples:
        try:
            src = sample.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"  skipped {sample.name}: {e}")
            continue

        for variant, (label, tfn) in TRANSFORMS.items():
            try:
                transformed = tfn(src)
            except Exception as e:
                print(f"  transform {variant} failed on {sample.name}: {e}")
                continue
            out_path = VARIANTS_DIR / f"{sample.stem}__{variant}.js"
            out_path.write_text(transformed, encoding="utf-8", errors="ignore")
            score = score_text(transformed)
            results[variant]["total"] += 1
            results[variant]["scores"].append(score)
            if score >= DEPLOYMENT_THRESHOLD:
                results[variant]["detected"] += 1

    # Print summary
    print("=" * 60)
    print("ADVERSARIAL ROBUSTNESS RESULTS")
    print("=" * 60)
    print(f"{'Variant':<8} {'Label':<32} {'Det/Tot':<10} {'Evasion %':<10}")
    print("-" * 60)
    for variant, (label, _) in TRANSFORMS.items():
        r = results[variant]
        det, tot = r["detected"], r["total"]
        evasion = (1 - det / tot) * 100 if tot else 0.0
        print(f"{variant:<8} {label:<32} {det}/{tot:<10} {evasion:<10.1f}")
    print("=" * 60)

    # Print placeholder values for the paper (Edit 11)
    print("\nPLACEHOLDER VALUES FOR THE PAPER (Edit 11):")
    print("=" * 60)
    for variant in ["A1", "A2", "A3", "B1", "B2"]:
        r = results[variant]
        det, tot = r["detected"], r["total"]
        evasion = (1 - det / tot) * 100 if tot else 0.0
        print(f"<<ADV_{variant}>>    = {det}    "
              f"(out of {tot}; <<ADV_{variant}_D>> = {evasion:.1f}% evasion)")
    print("=" * 60)

    # Save full results
    OUTPUT_JSON.write_text(json.dumps({
        "n_samples": len(samples),
        "threshold": DEPLOYMENT_THRESHOLD,
        "results": results,
    }, indent=2))
    print(f"\nFull results saved to {OUTPUT_JSON}")
    print(f"Generated variant files saved to {VARIANTS_DIR}/")


if __name__ == "__main__":
    main()
