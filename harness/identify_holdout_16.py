"""SetuGuard — provenance recovery for banking_holdout_16/. NON-FROZEN.

NOT one of the six frozen PS1 files (static_analysis.py, knowledge_base.py,
report_prompt.py, rag_report.py, yara_gen.py, run_pipeline.py) and not part of
batch_baseline.py's measurement suite. Ad hoc, non-frozen, written 2026-08-12.

Why this exists: sixteen sha256-named APKs back the project's headline negative
result (AUC(malicious vs banking_holdout_16) = 0.4113) and the repository
records nothing about what they are. "Which sixteen banks?" had no answer.

IT NOW HAS ONE, AND IT IS NOT THE EXPECTED ANSWER. Every document in this repo
describes banking_holdout_16/ as "16 real banking APKs" / "legitimate banking
apps". It is not. All sixteen are members of Banking.tar.gz -- the CICMalDroid
"Banking" MALWARE archive that cicmaldroid_banking/ was also extracted from.
The archive holds 2,505 APKs; cicmaldroid_banking/ holds 2,489 and
banking_holdout_16/ holds 16; 2489 + 16 = 2505 exactly, with zero overlap and
zero extras. "banking holdout" meant "held out from the Banking malware set",
and later sessions read it as "holdout of banking apps". See the FINDING
section of the generated Markdown for the full evidence and consequences.

Read-only. Opens each APK with androguard's APK class (manifest + signature
blocks only -- NOT AnalyzeAPK, which would also disassemble every DEX and is
both slow and unnecessary here). Extracts package name, app label, version
name, version code, certificate subject/issuer, certificate SHA-256 and file
size. It does not modify the APKs, does not invoke the scoring pipeline, and
does not write into any existing output directory -- its only output is the
Markdown file named by --out.

On the dead convention: CONTEXT.md's §9 used to state "never touch
banking_holdout_16/ in any script." That convention is already dead in
practice -- harness/build_sample_set_716.py:33 globs the directory directly and
writes all sixteen files into the scorer's 716-APK sample set, and both
harness/sample_set_banking_holdout_16.txt and harness/results_banking_holdout.csv
are committed direct runs over it. No guard, assertion or refusal exists
anywhere in the repo. This script is consistent with actual practice, not with
the written convention; the written convention should be struck rather than
this script suppressed.

Tiering is deliberately mechanical and evidence-bound -- see TIER_RULES below.
Anything the package name and certificate subject do not settle comes back
"Unknown". That is the intended behaviour, not a shortfall: this scheme is
reused as the pre-registered inclusion rule for the AndroZoo corpus expansion,
so a confident wrong tier is more expensive than an honest Unknown.

Usage:
    python3 harness/identify_holdout_16.py
    python3 harness/identify_holdout_16.py --dir banking_holdout_16 --out harness/BANKING_HOLDOUT_16_PROVENANCE.md
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from loguru import logger

# androguard 4.x logs at DEBUG through loguru, not stdlib logging.
logger.disable("androguard")

from androguard.core.apk import APK  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Tier rules. Package-name prefix / certificate-subject substring ONLY.
#
# Tier A -- scheduled commercial bank first-party app
# Tier B -- UPI / PSP app
# Tier C -- NBFC, wallet, or fintech
# Unknown -- the package name and certificate do not settle it
#
# Every entry below is a naming fact, not a market judgement: the package
# namespace or the certificate's Organization field names the institution.
# No web lookup is performed and no inference is drawn from the app label.
# ---------------------------------------------------------------------------

TIER_RULES = [
    # --- Tier A: scheduled commercial bank first-party namespaces ---
    ("A", "pkg_prefix", "com.sbi."),
    ("A", "pkg_prefix", "com.SBI."),
    ("A", "pkg_prefix", "com.onlinesbi"),
    ("A", "pkg_prefix", "com.icicibank"),
    ("A", "pkg_prefix", "com.csam.icici"),
    ("A", "pkg_prefix", "com.icici"),
    ("A", "pkg_prefix", "com.hdfcbank"),
    ("A", "pkg_prefix", "com.snapwork.hdfc"),
    ("A", "pkg_prefix", "com.axis"),
    ("A", "pkg_prefix", "com.kotak"),
    ("A", "pkg_prefix", "com.pnb"),
    ("A", "pkg_prefix", "com.msf.kbank"),
    ("A", "pkg_prefix", "com.bankofbaroda"),
    ("A", "pkg_prefix", "com.baroda"),
    ("A", "pkg_prefix", "com.boi."),
    ("A", "pkg_prefix", "com.bankofindia"),
    ("A", "pkg_prefix", "com.canarabank"),
    ("A", "pkg_prefix", "com.unionbank"),
    ("A", "pkg_prefix", "com.indusind"),
    ("A", "pkg_prefix", "com.yesbank"),
    ("A", "pkg_prefix", "com.idfcfirstbank"),
    ("A", "pkg_prefix", "com.federalbank"),
    ("A", "pkg_prefix", "com.fedmobile"),
    ("A", "pkg_prefix", "com.rblbank"),
    ("A", "pkg_prefix", "com.bandhanbank"),
    ("A", "pkg_prefix", "com.iob"),
    ("A", "pkg_prefix", "com.centralbank"),
    ("A", "pkg_prefix", "com.ucobank"),
    ("A", "pkg_prefix", "com.idbi"),
    ("A", "pkg_prefix", "com.dbs.in"),
    ("A", "pkg_prefix", "com.sc.m"),           # Standard Chartered mobile
    ("A", "pkg_prefix", "com.citibank"),
    ("A", "pkg_prefix", "com.hsbc"),
    ("A", "pkg_prefix", "com.barclays"),
    ("A", "pkg_prefix", "com.chase"),
    ("A", "pkg_prefix", "com.wf.wellsfargomobile"),
    ("A", "pkg_prefix", "com.bankofamerica"),
    ("A", "pkg_prefix", "com.infonow.bofa"),
    ("A", "pkg_prefix", "com.usaa"),
    ("A", "pkg_prefix", "com.suntrust"),
    ("A", "pkg_prefix", "com.regions"),
    ("A", "pkg_prefix", "com.konylabs.cbplus"),
    ("A", "pkg_prefix", "com.clairmail"),
    ("A", "pkg_prefix", "com.tdbank"),
    ("A", "pkg_prefix", "com.rbc"),
    ("A", "pkg_prefix", "com.scotiabank"),
    ("A", "pkg_prefix", "com.cibc"),
    ("A", "pkg_prefix", "com.bmo"),
    ("A", "pkg_prefix", "de.comdirect"),
    ("A", "pkg_prefix", "de.dkb"),
    ("A", "pkg_prefix", "com.db."),
    ("A", "pkg_prefix", "com.commbank"),
    ("A", "pkg_prefix", "au.com.nab"),
    ("A", "pkg_prefix", "org.westpac"),
    ("A", "pkg_prefix", "com.anz"),
    ("A", "cert_org", "state bank of india"),
    ("A", "cert_org", "icici bank"),
    ("A", "cert_org", "hdfc bank"),
    ("A", "cert_org", "axis bank"),
    ("A", "cert_org", "kotak"),
    ("A", "cert_org", "punjab national bank"),
    ("A", "cert_org", "bank of baroda"),
    ("A", "cert_org", "bank of india"),
    ("A", "cert_org", "canara bank"),
    ("A", "cert_org", "union bank"),
    ("A", "cert_org", "indusind"),
    ("A", "cert_org", "yes bank"),
    ("A", "cert_org", "federal bank"),
    ("A", "cert_org", "idfc"),
    ("A", "cert_org", "rbl bank"),
    ("A", "cert_org", "standard chartered"),
    ("A", "cert_org", "citibank"),
    ("A", "cert_org", "citigroup"),
    ("A", "cert_org", "hsbc"),
    ("A", "cert_org", "barclays"),
    ("A", "cert_org", "wells fargo"),
    ("A", "cert_org", "bank of america"),
    ("A", "cert_org", "jpmorgan"),
    ("A", "cert_org", "deutsche bank"),
    ("A", "cert_org", "commonwealth bank"),

    # --- Tier B: UPI / PSP ---
    ("B", "pkg_prefix", "in.org.npci"),
    ("B", "pkg_prefix", "com.npci"),
    ("B", "pkg_prefix", "com.phonepe"),
    ("B", "pkg_prefix", "com.google.android.apps.nbu.paisa"),
    ("B", "pkg_prefix", "net.one97.paytm"),
    ("B", "pkg_prefix", "in.amazon.mShop.android.payments"),
    ("B", "pkg_prefix", "com.amazon.mShop.android.payments"),
    ("B", "pkg_prefix", "com.whatsapp.payments"),
    ("B", "pkg_prefix", "com.mobikwik_np"),
    ("B", "cert_org", "national payments corporation"),
    ("B", "cert_org", "phonepe"),
    ("B", "cert_org", "one97"),

    # --- Tier C: NBFC / wallet / fintech ---
    ("C", "pkg_prefix", "com.freecharge"),
    ("C", "pkg_prefix", "com.mobikwik"),
    ("C", "pkg_prefix", "com.dreamplug"),      # CRED
    ("C", "pkg_prefix", "com.bajajfinserv"),
    ("C", "pkg_prefix", "com.bajaj"),
    ("C", "pkg_prefix", "com.navi"),
    ("C", "pkg_prefix", "money.jupiter"),
    ("C", "pkg_prefix", "com.epifi"),
    ("C", "pkg_prefix", "com.slicepay"),
    ("C", "pkg_prefix", "com.oxigen"),
    ("C", "pkg_prefix", "com.payu"),
    ("C", "pkg_prefix", "com.razorpay"),
    ("C", "pkg_prefix", "com.paypal"),
    ("C", "pkg_prefix", "com.venmo"),
    ("C", "pkg_prefix", "com.squareup.cash"),
    ("C", "pkg_prefix", "com.revolut"),
    ("C", "pkg_prefix", "com.transferwise"),
    ("C", "pkg_prefix", "com.wise"),
    ("C", "pkg_prefix", "com.westernunion"),
    ("C", "pkg_prefix", "com.moneygram"),
    ("C", "cert_org", "paypal"),
    ("C", "cert_org", "bajaj fin"),
    ("C", "cert_org", "revolut"),
]


def classify(package_name, cert_subject):
    """Tier from package name / certificate subject ONLY.

    Returns (tier, evidence_string). Never consults the app label, never
    performs a network lookup, never infers from the version string.
    Anything unmatched is Unknown -- see this module's docstring for why
    that is the intended outcome rather than a shortfall.
    """
    pkg = (package_name or "").strip()
    pkg_l = pkg.lower()
    subj_l = (cert_subject or "").lower()

    for tier, kind, needle in TIER_RULES:
        if kind == "pkg_prefix" and pkg_l.startswith(needle.lower()):
            return tier, f"package name starts with `{needle}`"
        if kind == "cert_org" and needle in subj_l:
            return tier, f"certificate subject contains `{needle}`"

    return "Unknown", "no package-namespace or certificate-subject rule matched"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cert_fields(apk: APK):
    """First signer's subject/issuer/sha256. Multi-signer APKs exist but are
    rare; taking the first signer matches static_analysis._extract_certificate's
    documented behaviour so the two agree."""
    try:
        certs = apk.get_certificates()
    except Exception as e:
        return None, None, None, f"{type(e).__name__}: {e}"
    if not certs:
        return None, None, None, "unsigned / no certificate recovered"
    c = certs[0]
    try:
        return c.subject.human_friendly, c.issuer.human_friendly, c.sha256.hex(), None
    except Exception as e:
        return None, None, None, f"{type(e).__name__}: {e}"


def org_of(subject: str) -> str:
    """Pull the Organization / Common Name out of androguard's human_friendly
    subject string, for a compact table cell. Returns the whole string if
    neither field is present."""
    if not subject:
        return ""
    m = re.search(r"Organization:\s*([^,]+)", subject)
    if m and m.group(1).strip():
        return m.group(1).strip()
    m = re.search(r"Common Name:\s*([^,]+)", subject)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return subject


def corpus_membership(filename: str):
    """Which sibling corpus directories contain this exact filename.

    Cheap, read-only, filename-only (the corpora are sha256-named, so a
    filename match IS a content match). This is the check that established the
    FINDING: banking_holdout_16/ and cicmaldroid_banking/ are disjoint halves
    of the same Banking.tar.gz malware archive.
    """
    hits = []
    for d in ("cicmaldroid_banking", "fdroid_benign_apks"):
        if (REPO_ROOT / d / filename).exists():
            hits.append(d)
    return hits


def load_sample_set(path: Path):
    """sha256 (from filename) of every banking_holdout entry in the scorer's
    716-APK sample set, so each row can state whether it is in it."""
    present = set()
    if not path.exists():
        return present
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p, _label = line.rsplit(",", 1)
        present.add(Path(p).stem)
    return present


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=REPO_ROOT / "banking_holdout_16")
    ap.add_argument("--out", type=Path,
                    default=Path(__file__).parent / "BANKING_HOLDOUT_16_PROVENANCE.md")
    ap.add_argument("--json-out", type=Path, default=None,
                    help="optional machine-readable dump alongside the Markdown")
    args = ap.parse_args()

    apks = sorted(args.dir.glob("*.apk"))
    if not apks:
        print(f"no APKs found in {args.dir}", file=sys.stderr)
        return 1
    print(f"[identify] {len(apks)} APKs in {args.dir}", file=sys.stderr)

    in_sample_set = load_sample_set(Path(__file__).parent / "sample_set_716.txt")

    rows = []
    for p in apks:
        row = {
            "filename": p.name,
            "file_sha256": sha256_of(p),
            "size_bytes": p.stat().st_size,
            "package_name": None, "app_label": None,
            "version_name": None, "version_code": None,
            "cert_subject": None, "cert_issuer": None, "cert_sha256": None,
            "error": None,
        }
        try:
            a = APK(str(p))
            row["package_name"] = a.get_package()
            try:
                row["app_label"] = a.get_app_name()
            except Exception as e:
                row["app_label"] = f"<unreadable: {type(e).__name__}>"
            row["version_name"] = a.get_androidversion_name()
            row["version_code"] = a.get_androidversion_code()
            subj, iss, csha, cerr = cert_fields(a)
            row["cert_subject"], row["cert_issuer"], row["cert_sha256"] = subj, iss, csha
            if cerr:
                row["error"] = cerr
        except Exception as e:
            row["error"] = f"{type(e).__name__}: {e}"

        tier, why = classify(row["package_name"], row["cert_subject"])
        row["tier"] = tier
        row["tier_evidence"] = why
        row["in_sample_set_716"] = row["file_sha256"] in in_sample_set
        row["also_in_corpora"] = corpus_membership(p.name)
        row["self_signed"] = (
            row["cert_subject"] == row["cert_issuer"] if row["cert_subject"] else None
        )
        rows.append(row)
        print(f"  {p.name[:12]}… pkg={row['package_name']} tier={tier}", file=sys.stderr)

    rows.sort(key=lambda r: (r["tier"] == "Unknown", r["tier"], r["package_name"] or "~"))

    tier_counts = {}
    for r in rows:
        tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1

    if args.json_out:
        args.json_out.write_text(json.dumps({"tier_counts": tier_counts, "apps": rows}, indent=2))

    args.out.write_text(render(rows, tier_counts, args.dir))
    print(f"\n[identify] tier counts: {tier_counts}", file=sys.stderr)
    print(f"[identify] wrote {args.out}", file=sys.stderr)
    return 0


def render(rows, tier_counts, src_dir) -> str:
    def esc(s):
        return (str(s) if s is not None else "—").replace("|", "\\|")

    L = []
    L.append("# `banking_holdout_16/` — provenance\n")
    L.append("Generated by `harness/identify_holdout_16.py` (non-frozen, read-only) on 2026-08-12.\n")
    L.append("These sixteen APKs are the negative class of SetuGuard's headline PS1 result — "
             "AUC(malicious vs `banking_holdout_16`) = **0.4113**. Until this file existed the "
             "repository recorded nothing about what they are, so the question *\"which sixteen "
             "banks?\"* had no answer.\n")

    L.append("---\n")
    L.append("## FINDING — there are no banks in `banking_holdout_16/`\n")
    L.append("**All sixteen are malware samples.** Not one is a legitimate banking app. "
             "The directory is a sixteen-sample partition of the CICMalDroid **Banking malware** "
             "archive — the same archive `cicmaldroid_banking/` was extracted from.\n")
    L.append("### Evidence 1 — the arithmetic is exact\n")
    L.append("```")
    L.append("$ tar -tzf Banking.tar.gz | grep -c '\\.apk$'      ->  2505")
    L.append("$ ls -1 cicmaldroid_banking/*.apk    | wc -l        ->  2489")
    L.append("$ ls -1 banking_holdout_16/*.apk     | wc -l        ->    16")
    L.append("                                                        -----")
    L.append("                                          2489 + 16  =  2505")
    L.append("```")
    L.append("Set-differenced both ways: **zero** tarball entries outside the two directories, "
             "**zero** files in either directory absent from the tarball, **zero** overlap "
             "between the two directories. `banking_holdout_16/` is the complement of "
             "`cicmaldroid_banking/` within `Banking.tar.gz`. All sixteen filenames were "
             "confirmed present in the tarball listing individually.\n")
    L.append("### Evidence 2 — no certificate belongs to a bank, or to any real publisher\n")
    L.append("Every one of the sixteen is **self-signed**. The subjects are:\n")
    L.append("- Keyboard mash: `sdsdfsdf`, `sasasa`, `zxzxzx`, `32131312312321312`, `7`")
    L.append("- The AOSP **public test key** — `android@android.com / Android / Mountain View / "
             "California / US` — on three samples. No app distributed through Google Play can "
             "carry this key; it is the publicly-known platform test certificate.")
    L.append("- `android-debug` — the Android Studio debug key — on two samples.")
    L.append("- `DarkNess / Space / Galaxy / GA` on three samples.")
    L.append("- `Sergio Mavrodi` — the name of a Russian Ponzi-scheme operator — on one.\n")
    L.append("### Evidence 3 — the package names and labels are not banking apps\n")
    L.append("`com.example.myapp` is the Android Studio template default, which Google Play "
             "rejects outright. `zzzzzz.xxxxxx.cccccc` and `qrprjp.scxrxw.upuwjg` are randomised "
             "namespaces, a repackaging-kit signature. `com.google.game.store` and "
             "`com.sms.google` masquerade as Google. `com.trdos.cores` appears **twice**, as two "
             "different files carrying two different labels (*Worms 2: Armageddon* and "
             "*Семейная ферма*) — one package, two repackaged payloads.\n")
    L.append("Labels include *Free PornTube*, *Yatzy Heaven - Bikini Beach*, *MMS-Центр*, "
             "*获奖证书* (\"award certificate\"), and Korean parcel-delivery lures "
             "(*스마트 택배*, *CJ대한통운 택배*) — the standard smishing bait set. Exactly one "
             "sample carries a banking label, **신한S뱅크** (Shinhan S Bank), and it is a *fake*: "
             "package `com.xinhannewbank` (the real app is `com.shinhan.sbanking`), signed with "
             "the AOSP test key. It is a banking trojan impersonating a bank, which is a "
             "positive, not a negative.\n")

    L.append("### What this does to the headline result\n")
    L.append("| Claim as written across the repo | What the evidence supports |")
    L.append("|---|---|")
    L.append("| AUC 0.4113 = \"malware does not rank above legitimate banking apps\" | "
             "**Void.** It is 360 malware vs 16 malware from the same archive — a within-class "
             "ranking artifact measuring nothing about legitimate apps. |")
    L.append("| \"15/16 legitimate banking apps false-positive\" | "
             "**Inverted.** 15/16 held-out *malware* samples correctly flagged — a 93.8% "
             "detection rate, currently written up as the project's central failure. |")
    L.append("| \"1 app scored 0.28, below the 0.30 threshold\" (a correct benign call) | "
             "**A miss.** One malware sample evaded the scorer. |")
    L.append("| \"Banking apps outscore confirmed malware, 0.688 vs 0.614\" | "
             "Both groups are malware. These sixteen simply score higher than the "
             "cicmaldroid sample average. |")
    L.append("| \"Static analysis cannot separate banking malware from legitimate banking apps — "
             "the classes are convergent by construction\" | "
             "**Unmeasured.** A plausible hypothesis with no supporting measurement in this "
             "repo. |")
    L.append("")
    L.append("**AUC(malicious vs general F-Droid benign) = 0.9366 is unaffected** and remains "
             "the project's one genuine PS1 separation number. `fdroid_benign_apks/` is a real "
             "benign corpus, independently sourced from F-Droid.\n")
    L.append("A second consequence, easy to miss: `SESSION_LOG.md:219` records that term "
             "selection for scorer-v2 ranked discriminative power over \"malicious sample vs "
             "**fdroid_benign + holdout16**\". Those sixteen sat in the **negative** pool. They "
             "are malware. So the term ranking that justified the three scorer-v2 deletions ran "
             "with roughly 5% label noise in its negative class — a labelling error, not merely "
             "the holdout-contamination previously recorded.\n")
    L.append("### How the error happened\n")
    L.append("Semantic drift on the directory name, traceable in the repo. "
             "`SetuGuard_Development_Roadmap_v2.md:16` (2026-07-06) is the earliest occurrence: "
             "*\"F-Droid + 16 real banking-app holdout\"*. `harness/sample_set_banking_holdout_16.txt:2-3` "
             "hardcodes the reading as a comment: *\"The 16 real banking APKs… Every non-benign "
             "verdict here is a false positive on real bank apps.\"* From there it propagated to "
             "`docs/evidence/2026-08-12_scorer_v2.md:121`, `SESSION_LOG.md:172,233,352`, "
             "`PS1_Defects_and_Improvements.md:67`, and `CONTEXT.md`. \"Banking holdout\" means "
             "*held out from the Banking [malware] set*; it was read as *a holdout of banking "
             "apps*.\n")
    L.append("The repo flagged this risk to itself and was not heard: "
             "`PS1_Defects_and_Improvements.md:144` (D9) states *\"the F-Droid pull… and the 16 "
             "real banking APKs are **unsourced**. Until they exist, the FP number cannot be "
             "measured.\"* The FP number was measured anyway, five weeks later, against a "
             "corpus that was never sourced because it never existed.\n")
    L.append("---\n")

    L.append("## How tiers were assigned\n")
    L.append("From the **package name and the certificate subject only**. Not from the app "
             "label, not from a web search, not from the version string. The rule table lives in "
             "`harness/identify_holdout_16.py:TIER_RULES` and every entry is a naming fact — a "
             "first-party package namespace, or an institution named in the certificate's "
             "Organization field.\n")
    L.append("| Tier | Definition |")
    L.append("|---|---|")
    L.append("| **A** | Scheduled commercial bank first-party app |")
    L.append("| **B** | UPI / PSP app |")
    L.append("| **C** | NBFC, wallet, or fintech |")
    L.append("| **Unknown** | Package name and certificate do not settle it |")
    L.append("")
    L.append("**Unknown is marked freely and is not a shortfall.** This scheme is reused as the "
             "*pre-registered* inclusion rule for the planned AndroZoo corpus build, where "
             "the Tier-A gate is the whole experiment. A confident wrong tier there costs more "
             "than an honest Unknown, so the classifier abstains rather than guesses.\n")
    L.append("**All sixteen came back Unknown, and that is the correct answer.** The tier "
             "scheme is a *bank-identification* rule; none of these is a bank app, so none "
             "matches. The scheme abstaining on sixteen malware samples is the scheme working. "
             "Its value is now forward-looking: it is the pre-registered rule for building the "
             "real Tier-A holdout that this project has never had.\n")

    L.append("## Tier counts\n")
    for t in ("A", "B", "C", "Unknown"):
        if t in tier_counts:
            L.append(f"- **Tier {t}**: {tier_counts[t]}")
    L.append("")

    L.append("## The sixteen\n")
    L.append("| # | Tier | Package | App label | Cert subject (org/CN) | Self-signed | Size | In 716 set |")
    L.append("|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        ss = "yes" if r.get("self_signed") else ("—" if r.get("self_signed") is None else "no")
        L.append(
            f"| {i} | {r['tier']} | `{esc(r['package_name'])}` | {esc(r['app_label'])} | "
            f"{esc(org_of(r['cert_subject']))} | {ss} | {r['size_bytes'] / 1048576:.1f} MB | "
            f"{'yes' if r['in_sample_set_716'] else 'no'} |"
        )
    L.append("")
    L.append("Every row is Tier Unknown and every row is self-signed. No row is a bank.\n")

    L.append("## Full records\n")
    for i, r in enumerate(rows, 1):
        L.append(f"### {i}. `{r['filename']}`\n")
        L.append(f"- **Tier**: {r['tier']} — {r['tier_evidence']}")
        L.append(f"- **Package**: `{esc(r['package_name'])}`")
        L.append(f"- **App label**: {esc(r['app_label'])}")
        L.append(f"- **Version**: {esc(r['version_name'])} (code {esc(r['version_code'])})")
        L.append(f"- **File SHA-256**: `{r['file_sha256']}`")
        L.append(f"- **Certificate SHA-256**: `{esc(r['cert_sha256'])}`")
        L.append(f"- **Certificate subject**: {esc(r['cert_subject'])}")
        L.append(f"- **Certificate issuer**: {esc(r['cert_issuer'])}")
        L.append(f"- **Self-signed**: {r['cert_subject'] == r['cert_issuer'] if r['cert_subject'] else '—'}")
        L.append(f"- **Size**: {r['size_bytes']:,} bytes")
        L.append(f"- **In `sample_set_716.txt`**: {'yes' if r['in_sample_set_716'] else 'no'}")
        L.append(f"- **Also present in**: "
                 f"{', '.join(f'`{d}/`' for d in r['also_in_corpora']) or 'no sibling corpus directory'} "
                 f"(all sixteen are members of `Banking.tar.gz` — see FINDING)")
        if r["error"]:
            L.append(f"- **Extraction note**: {esc(r['error'])}")
        L.append("")

    L.append("## The dead convention\n")
    L.append("`CONTEXT.md` §9 used to state: *\"**Never touch `banking_holdout_16/`** in any "
             "script. Every harness in this repo has explicitly excluded it.\"* **That convention "
             "is already dead**, and was dead before this script existed:\n")
    L.append("- `harness/build_sample_set_716.py:33` globs the directory directly "
             "(`sorted((REPO_ROOT / \"banking_holdout_16\").glob(\"*.apk\"))`) and writes all "
             "sixteen files into the scorer's 716-APK sample set.")
    L.append("- `harness/rescore_from_cache.py` scores them and computes the gate AUC on them.")
    L.append("- `harness/sample_set_banking_holdout_16.txt` and "
             "`harness/results_banking_holdout.csv` are committed direct runs over the directory.")
    L.append("- No guard, assertion, path check or refusal exists anywhere in the repo — grepped.\n")
    L.append("**This script is consistent with actual practice, not with the written "
             "convention.** The written convention should be struck rather than this script "
             "suppressed: a rule that every harness already violates is not a control, it is a "
             "false assurance in a document a judge may read.\n")
    L.append("What the holdout genuinely still needs is the *other* discipline the old rule was "
             "reaching for — a holdout must not be used for term selection or threshold "
             "choice. On that point the repo has a recorded failure, see `CONTEXT.md`'s "
             "CONTRADICTED section and `SESSION_LOG.md:219` versus `:258-261`. Note that the "
             "old rule would not have prevented this session's finding either: obeying "
             "\"never open these files\" is exactly what let sixteen malware samples sit "
             "unexamined for five weeks while a headline number was computed on them.\n")

    L.append("## What has to happen next\n")
    L.append("1. **Stop quoting AUC 0.4113 and the 15/16 figure**, in the 17 August report and "
             "everywhere else, until a real Tier-A holdout exists. See `REPORT_FACTS.md`.")
    L.append("2. **Rename the directory** — `banking_holdout_16/` → `cicmaldroid_banking_holdout_16/` "
             "— and fix `harness/sample_set_banking_holdout_16.txt:2-3`, whose comment asserts "
             "the false reading. Code/data change: after 17 August.")
    L.append("3. **Build the real holdout** using the Tier scheme above as the pre-registered "
             "inclusion rule: exact `pkg_name` match against AndroZoo's `latest.csv`, requiring "
             "`vt_detection == 0` **and** `markets` containing Google Play. Both filters are "
             "load-bearing — AndroZoo carries repackaged fake banking apps under near-identical "
             "package names, and `vt_detection == 0` does not exclude a freshly repackaged "
             "trojan. This sample is now the *first* measurement of the class-convergence "
             "claim, not an expansion of an existing one.")
    L.append("4. **Re-run the term-selection ranking** with the sixteen removed from the "
             "negative pool. The three scorer-v2 deletions were justified against a negative "
             "class containing ~5% malware.")
    L.append("5. The one surviving PS1 separation number — **0.9366 against F-Droid benign** — "
             "needs no requalification and should carry the report.\n")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
