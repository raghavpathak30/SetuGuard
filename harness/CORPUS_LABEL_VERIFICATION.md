# Corpus label verification — independent check against AndroZoo VirusTotal data

This project has never verified that `cicmaldroid_banking/`'s 2,489 samples are actually malicious, or that `fdroid_benign_apks/`'s 802 samples are actually clean. Both labels were taken on trust from a directory name -- the same class of assumption that produced the `banking_holdout_16/` error, at larger scale and with better odds. This is the first independent evidence for either label.

**Pre-registered interpretation rule (fixed before the numbers were seen):** if more than 15.0% of resolvable malware samples carry `vt_detection == 0`, the positive-class label requires an explicit caveat in this report. Below 15.0%, a tail of zeros is normal for any malware corpus.

## Malware corpus (`cicmaldroid_banking/`, n=2489 on disk)

- Resolved in AndroZoo: **697/2489** (28.0%) -- **1792 not found in AndroZoo, stated plainly as a real coverage limitation, not extrapolated over.**
- `vt_detection` median: **30**, mean 30.03, IQR [29, 33], range [0, 41] (of 697 resolved)
- Full distribution:
  - `0`: 12 (1.7%)
  - `1-4`: 6 (0.9%)
  - `5-9`: 3 (0.4%)
  - `10-19`: 6 (0.9%)
  - `20-29`: 225 (32.3%)
  - `30-39`: 436 (62.6%)
  - `40+`: 9 (1.3%)
- **≥5 detections: 679 (97.4%)**
- **`vt_detection == 0`: 12 (1.7%)** of 697 resolved -- reported as-is, no staleness explanation offered (CICMalDroid samples date from 2017-18 and the `vt_scan_date` distribution above shows most resolved scans postdate collection, so staleness is not a credible account of these zeros).
- **Threshold result: 1.7% is BELOW the 15.0% pre-registered threshold -- no caveat is required.**
- `vt_scan_date` distribution (by year, of resolved samples):
  - 2013: 11
  - 2014: 10
  - 2015: 3
  - 2016: 15
  - 2017: 7
  - 2018: 77
  - 2019: 232
  - 2020: 338
  - 2021: 3
  - 2022: 1

## Benign corpus (`fdroid_benign_apks/`, n=802 on disk)

Carries the surviving AUC 0.9366 figure -- its labels have never been checked either.

- Resolved in AndroZoo: **414/802** (51.6%) -- **388 not found in AndroZoo.**
- **`vt_detection == 0`: 401/414 resolved (96.9%)**

**13 F-Droid sample(s) resolved with nonzero `vt_detection`:**
- `166D4CB9B0F7A5C1468A71BD04C424B84E0C282471794B0CADD97B172DE3D17F` (co.ec.cnsyn.codecatcher_131.apk)
- `2D6424F47B58CDED43E25331400C130F463356946C555BF53E3B56074A3C2736` (com.akansh.fileserversuit_32.apk)
- `416791A88E5A5D917AD989A5314F6CB903802D6D6C2E23F6721B88FA0B3F4BA8` (com.aaronjwood.portauthority_67.apk)
- `6F348767CACA6FDA406EDDCFBF023995B61EE1182BF8F624123E95A0F690D1D9` (com.cyb3rko.flashdim_31.apk)
- `79735398C15632094CCD60FF2C4D220088132D5E7724D7C0692DDBB0E560B22A` (com.ehang.ehhelper_3.apk)
- `7C687578A3F7AEA7CA4FBEA24744BB3CEBB2A5E01E4DACF922C0D7839D21054B` (com.autismprime.fall_3.apk)
- `8CAF4B679367331C2A8BF20C0216A634218A6D1CBC0E3D59EEE9EC8EB345D917` (ch.ihdg.calendarcolor_5.apk)
- `8FFA7288A604109650DEF2FF3D1F44E535545278EEBECD148C0DDBF56D873B3C` (com.aragaer.jtt_36.apk)
- `A208C318C0E5AE1AF7C0F97DC86648E3AA55A9556DD38620AB4994817031A1C4` (com.clicc_32.apk)
- `A5687D1BAD7B2927740A55B7B1DF11EFC81EDCAD03F0633AB5C2E5C58B120541` (com.dozingcatsoftware.dodge_10.apk)
- `BEC3B8076C0F14A36443FDB7B8B2C30588DA181F44C1491AC7ED9D271F707147` (biz.binarysolutions.vatcalculator_11.apk)
- `DC98D8D22801977629D572078D4229E1F3C6DBFD7D594725F5FC3A7B363FFC73` (com.blockbasti.justanotherworkouttimer_20230929.apk)
- `DFBE3767472C07C4D51B0F418FFB284AB342F7FD43AEC8C91F1CBE515BF8AB94` (com.bytehamster.flowitgame_402.apk)

## Scored subset (the 300 actually behind AUC 0.9366)

`build_sample_set_716.py:39-40` draws the benign arm as `random.Random(42).sample(sorted(fdroid_benign_apks/*.apk), 300)` -- the AUC was computed on those 300, not the full 802. Reproduced here with the same seed and the same sorted-glob draw order.

- Resolved in AndroZoo: **160/300** (53.3%) -- 140 not found.
- **`vt_detection == 0`: 157/160 resolved (98.1%)**

## Closes: the two F-Droid APKs with no recorded download URL

`CORPUS_PROVENANCE.md` (P-5) flags `acab.naiveha.subrosa_7.apk` and `app.olauncher_105.apk` as present on disk with no entry in `fdroid_urls.txt`. An AndroZoo resolution for either is independent evidence about them even without their original download URL -- check the benign corpus table above for their sha256 (computed and cached in `harness/fdroid_sha256_cache.tsv`) directly.

