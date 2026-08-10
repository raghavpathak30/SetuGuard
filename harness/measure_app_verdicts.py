"""SetuGuard — D1 after-inversion measurement harness.

NOT one of the six frozen PS1 pipeline files and not part of the PS1 measurement
suite (batch_baseline.py) either — this is an ad hoc, non-frozen script written
2026-08-10 to measure the D1 verdict-path inversion in setuguard_app/backend/app.py.
It never imports or mutates any frozen file; it only POSTs to a locally running
/api/analyze_apk, same as the real frontend would.

Reads harness/sample_set_86.txt (the same explicit, deterministic 86-sample set
used for setuguard_ps1/batch_baseline.py's pinned before-run, so the two runs are
directly comparable) and POSTs each APK to a locally running backend
(setuguard_app/backend/app.py, default http://127.0.0.1:5000).

Records verdict, confidence, verdict_source, narrative_source (the structured
provenance fields added by the D1 inversion) per sample, incrementally
flushed so a killed run can be diagnosed from partial output.

Usage:
    python3 measure_app_verdicts.py [--base-url http://127.0.0.1:5000]
                                     [--sample-list ../harness/sample_set_86.txt]
                                     [--out results_app_path.csv]
"""
import argparse
import csv
import sys
import time
from pathlib import Path

import requests

FIELDNAMES = ["filename", "true_label", "verdict", "confidence",
              "verdict_source", "narrative_source", "elapsed_s"]


def _read_sample_list(path: Path):
    samples = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path_str, label = line.rsplit(",", 1)
        samples.append((Path(path_str), label))
    return samples


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://127.0.0.1:5000")
    p.add_argument("--sample-list", type=Path,
                    default=Path(__file__).parent / "sample_set_86.txt")
    p.add_argument("--out", type=Path,
                    default=Path(__file__).parent / "results_app_path.csv")
    args = p.parse_args()

    samples = _read_sample_list(args.sample_list)
    print(f"Loaded {len(samples)} samples from {args.sample_list}", file=sys.stderr)

    already_done = set()
    if args.out.exists() and args.out.stat().st_size > 0:
        with open(args.out, newline="") as f:
            already_done = {row["filename"] for row in csv.DictReader(f)}
    remaining = [(pth, lbl) for pth, lbl in samples if pth.name not in already_done]
    print(f"{len(already_done)} already done (resume), {len(remaining)} remaining", file=sys.stderr)

    is_new = not args.out.exists() or args.out.stat().st_size == 0
    out_f = open(args.out, "a", newline="")
    writer = csv.DictWriter(out_f, fieldnames=FIELDNAMES)
    if is_new:
        writer.writeheader()
        out_f.flush()

    skipped = []
    for idx, (apk_path, true_label) in enumerate(remaining, start=1):
        t0 = time.perf_counter()
        try:
            with open(apk_path, "rb") as fh:
                resp = requests.post(
                    f"{args.base_url}/api/analyze_apk",
                    files={"apk": (apk_path.name, fh, "application/vnd.android.package-archive")},
                    timeout=300,
                )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            skipped.append((apk_path.name, true_label, repr(e)))
            print(f"  [{idx}/{len(remaining)}] {apk_path.name} SKIPPED: {e}", file=sys.stderr)
            continue

        elapsed = time.perf_counter() - t0
        row = {
            "filename": apk_path.name,
            "true_label": true_label,
            "verdict": data["verdict"],
            "confidence": data["confidence"],
            "verdict_source": data.get("verdict_source"),
            "narrative_source": data.get("narrative_source"),
            "elapsed_s": round(elapsed, 3),
        }
        writer.writerow(row)
        out_f.flush()
        print(f"  [{idx}/{len(remaining)}] {apk_path.name} ({true_label}) -> "
              f"{data['verdict']} ({data['confidence']:.2f}) "
              f"[{data.get('verdict_source')}/{data.get('narrative_source')}] {elapsed:.1f}s",
              file=sys.stderr)

    out_f.close()
    if skipped:
        print(f"\n{len(skipped)} skipped:", file=sys.stderr)
        for name, label, err in skipped:
            print(f"  - {name} ({label}): {err}", file=sys.stderr)


if __name__ == "__main__":
    main()
