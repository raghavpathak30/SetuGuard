# Corpus provenance

Written 2026-08-13, after `banking_holdout_16/` was found to contain malware rather than banking
apps (`harness/BANKING_HOLDOUT_16_PROVENANCE.md`). That error survived five weeks because no
corpus in this repo had a provenance record — only a directory name. This file exists so that
cannot happen twice.

**Rule going forward: a corpus gets an entry here before any number is computed on it.** A
directory name is not provenance.

---

## 1. `Banking.tar.gz` — source of BOTH malware corpora

The single largest provenance risk in the repo: 3.9 GB, gitignored, and the only surviving record
of where 2,505 of the project's APKs came from. If this file is lost, `cicmaldroid_banking/` and
`banking_holdout_16/` become unattributable.

### Measured facts

| Field | Value |
|---|---|
| **SHA-256** | `353c9d800ad73b0048fe6d7f8649008c30b6d776c68137041c0be9fc1258ffa7` |
| **Size** | 3,890,614,109 bytes (3.62 GiB) |
| **APK entries** | **2,505** |
| **Inner root directory** | `Banking/` |
| **Local mtime** (acquisition, not creation) | 2026-07-07 01:30:17 +0530 |
| **Entry ownership** | every entry `cicdataset/cicdataset` |
| **Entry mtime range** | 1971-11-24 to **2020-07-27** |

Verify with:

```
sha256sum Banking.tar.gz
tar -tzf Banking.tar.gz | grep -c '\.apk$'
tar -tvzf Banking.tar.gz | head -1        # shows the cicdataset owner
```

### Source URL — **NOT RECORDED. Raghav must supply it.**

**No file in this repository records where this archive was downloaded from.** `download_log.txt`
is an `fdroidcl` console log covering the F-Droid pull only; it contains three URLs and none of
them is this archive. There is no wget/curl log, no README, no shell history artifact.

**This field is deliberately left blank rather than filled with a plausible guess.** Writing an
unverified URL here would repeat, in the file created to prevent it, the exact failure it was
created to prevent.

### What the evidence does and does not support

**Supports a CICMalDroid attribution, independently of any directory name:**

- Every archive entry is owned by uid/gid **`cicdataset`** — a packing-machine account name
  baked into the tar headers by whoever produced the archive. This is in-archive evidence and
  cannot have been introduced by anything done in this repo.
- The inner root is `Banking/`, i.e. a *category* directory, consistent with a dataset
  distributed as per-category archives.
- No entry has an mtime later than **2020-07-27**, consistent with a dataset frozen in 2020.

Taken together these are consistent with **CICMalDroid 2020**, published by the Canadian
Institute for Cybersecurity at the University of New Brunswick, whose sample set is distributed
by category and includes a Banking category.

**Does NOT support, and must not be asserted until Raghav confirms:**

- The exact download URL.
- The dataset *version* — "CICMalDroid 2020" is inferred from the 2020-07-27 mtime ceiling, not
  read from any manifest inside the archive.
- The licence and citation requirements. Academic malware datasets typically require a signed
  request form and a specific citation in any publication. **If SetuGuard's report or deck names
  the dataset, the required citation must be included** — confirm before the 17 August submission.
- Any claim about *how* the Banking category was labelled, or by what engine. The project has
  never verified that these 2,505 samples are malicious; it has taken the category name on trust.
  That is the same class of assumption that produced the holdout error, one level up. It is
  currently unfalsified, not verified.

**Do not cite the directory name `cicmaldroid_banking/` as evidence of anything.** That name was
chosen locally. The archive itself is named only `Banking.tar.gz`.

### Extraction mapping — complete and verified

```
Banking.tar.gz  (2,505 APKs)
    ├── 2,489  ->  cicmaldroid_banking/     (the "malicious" corpus)
    └──    16  ->  banking_holdout_16/      (misnamed; see BANKING_HOLDOUT_16_PROVENANCE.md)
                   2,489 + 16 = 2,505, zero overlap, zero unaccounted
```

Per-file mapping with sizes: **`harness/BANKING_ARCHIVE_MANIFEST.tsv`** (2,505 rows,
`size_bytes` / `filename` / `extracted_to`). The manifest is committed so the split can be
audited, and the sixteen identified, **without access to the 3.9 GB archive**.

`cicmaldroid_banking/` additionally contains one non-APK file not present in the archive —
`9cc47edb7378b27858632805a6e992454bc0ced64f3c057933d98053ffe17171.sh`, 272 bytes of ASCII text,
origin unknown. It is excluded from every measurement (`harness/build_sample_set_716.py` globs
`*.apk`), but it should not be in a corpus directory.

### Sampling drawn from this archive

`harness/sample_set_716.txt`, built by `harness/build_sample_set_716.py` (seed 42, sorted glob,
filesystem-order-independent, independently re-derived byte-for-byte):

- all **16** of `banking_holdout_16/`, labelled `banking_holdout` — **the label is wrong**; these
  are malware
- **400** of 2,489 from `cicmaldroid_banking/`, labelled `malicious`
- **300** of 802 from `fdroid_benign_apks/`, labelled `benign`

---

## 2. `fdroid_benign_apks/` — the benign corpus

Provenance is **partial but adequate**, and materially better than the malware side.

| Field | Value |
|---|---|
| APKs on disk | **802** |
| Recorded source URLs | **800** (`fdroid_urls.txt`, all `https://f-droid.org/repo/...`) |
| Index the pull was derived from | `index-v2.json` (51 MB, F-Droid repo index, gitignored) |
| Selection script | `parse_fdroid_index.py` (committed) |
| Console log | `download_log.txt` — `fdroidcl` output, 160 lines, **not** a provenance record |

**Gap: 2 of 802 files have no recorded URL** — `acab.naiveha.subrosa_7.apk` and
`app.olauncher_105.apk`. Both follow the F-Droid `package_versioncode.apk` naming convention and
are almost certainly from the same pull, but they are not in `fdroid_urls.txt`. Every URL in that
file does correspond to a file on disk (zero orphans in the other direction).

This corpus carries the project's one surviving PS1 separation number — AUC **0.9366** — so its
provenance matters more than the malware side's. Unlike `banking_holdout_16/`, its identity is
independently checkable: every file is a real F-Droid package with a resolvable URL, and F-Droid
builds from source, which is a stronger benign guarantee than "no antivirus flagged it."

**Not verified:** that F-Droid apps are representative of the consumer Android population a bank
would actually see. They skew open-source, low-permission and non-commercial. This is stated as a
limitation in `CONTEXT.md` §8, not as a resolved question.

---

## 3. `DataSet.csv` — PS2 account data

| Field | Value |
|---|---|
| Rows × columns | 9,082 × 3,925 (`Unnamed: 0` + `F1`…`F3924`) |
| Positives | 81 (`F3924`), prevalence 0.892% |
| Size | 116,537,521 bytes |
| Data dictionary | `data/Description.xlsx`, sheet `Data_Dicitionary`, 3,924 rows — **committed** |
| Source | Supplied by the organisers (PSB CyberShield 2026). No download record in the repo. |

Best-documented corpus in the project: the dictionary is committed, the 18 bank-finalized
features are re-derivable from its column 4, and `harness/test_leakage_assert.py` proves the
exclusion guard fires. `DataSet.csv` itself is gitignored (117 MB), so the *dictionary* survives a
clone but the data does not.

**Known structural property, recorded because it is a leakage trap:** all 81 fraud rows are
contiguous at the file tail — `Unnamed: 0` 9002–9082, DataFrame positions 9001–9081. Row order
encodes the target. Any positional sampling of this file is label leakage.

---

## 4. Open provenance items

| # | Item | Owner | By |
|---|---|---|---|
| P-1 | Supply the `Banking.tar.gz` download URL, dataset version, and licence/citation requirement | Raghav | **before 16 Aug** if the report names the dataset |
| P-2 | Confirm whether the report/deck must carry a dataset citation | Raghav | before 16 Aug |
| P-3 | Rename `banking_holdout_16/` → `cicmaldroid_banking_holdout_16/` and fix `harness/sample_set_banking_holdout_16.txt:2-3`, whose comment asserts these are real bank apps | — | after 17 Aug (`PLAN.md` item 6) |
| P-4 | Relabel the `banking_holdout` rows in `harness/results_716.csv` before committing it | — | after 17 Aug (`PLAN.md` item 5) |
| P-5 | Account for the 2 unsourced F-Droid APKs, or drop them | — | after 17 Aug |
| P-6 | Remove or explain the stray `.sh` in `cicmaldroid_banking/` | — | after 17 Aug |
| P-7 | Record provenance for the AndroZoo Tier-A corpus **before scoring anything on it** — exact `latest.csv` snapshot date, the `pkg_name` list, and the `vt_detection == 0` + Google-Play-market filter, committed in advance | — | with `PLAN.md` item A |

P-7 is the one that matters. The tier scheme in `harness/identify_holdout_16.py:TIER_RULES` is
already committed and therefore pre-registered; the corpus built with it must be documented here
**before** it produces a number, not after a judge asks.
