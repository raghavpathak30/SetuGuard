"""SetuGuard — seeded 716-sample builder for scorer-v2 measurement.

NOT one of the six frozen PS1 files, not part of batch_baseline.py's suite.
Ad hoc, non-frozen script written 2026-08-12 to build a fixed, reproducible
sample set for the Step 2/4 scorer-pruning measurement, per instruction
("do not score all 3307; seeded sample, seed=42").

Deterministic construction:
  - ALL 16 banking_holdout_16/*.apk (the true holdout, never subsampled)
  - random.Random(42).sample() of 400 from sorted-glob cicmaldroid_banking/*.apk
  - random.Random(42).sample() of 300 from sorted-glob fdroid_benign_apks/*.apk

Sampling from a sorted glob (not os.listdir order, which is filesystem-
dependent) so the same seed reproduces the same 716 files on any machine.
Writes harness/sample_set_716.txt, format: path,label (mirrors
sample_set_86.txt's convention).

Usage:
    python3 build_sample_set_716.py
"""
import random
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = 42
N_MALICIOUS = 400
N_BENIGN = 300

OUT = Path(__file__).parent / "sample_set_716.txt"


def main():
    holdout = sorted((REPO_ROOT / "banking_holdout_16").glob("*.apk"))
    malicious_pool = sorted((REPO_ROOT / "cicmaldroid_banking").glob("*.apk"))
    benign_pool = sorted((REPO_ROOT / "fdroid_benign_apks").glob("*.apk"))

    rng = random.Random(SEED)
    malicious_sample = rng.sample(malicious_pool, N_MALICIOUS)
    rng = random.Random(SEED)  # fresh RNG per corpus so each draw is independent of draw order
    benign_sample = rng.sample(benign_pool, N_BENIGN)

    lines = [
        "# harness/sample_set_716.txt",
        "# Seeded (seed=42) sample set for scorer-v2 measurement (SetuGuard, 2026-08-12).",
        "# ALL 16 banking_holdout_16 + random.Random(42).sample(400) of cicmaldroid_banking",
        "# + random.Random(42).sample(300) of fdroid_benign_apks, both drawn from a sorted",
        "# glob (filesystem-order-independent) with a fresh seeded RNG per corpus.",
        "# Format: path,label",
        "#",
        f"# Pool sizes at build time: banking_holdout_16={len(holdout)}, "
        f"cicmaldroid_banking={len(malicious_pool)}, fdroid_benign_apks={len(benign_pool)}",
        f"# Totals: 16 banking_holdout + {N_BENIGN} benign + {N_MALICIOUS} malicious = "
        f"{16 + N_BENIGN + N_MALICIOUS}",
        "",
    ]
    for p in holdout:
        lines.append(f"{p},banking_holdout")
    for p in sorted(benign_sample):
        lines.append(f"{p},benign")
    for p in sorted(malicious_sample):
        lines.append(f"{p},malicious")

    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT} ({len(holdout) + len(benign_sample) + len(malicious_sample)} entries)")


if __name__ == "__main__":
    main()
