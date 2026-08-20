/*
 * harness/browser_smoke.js -- NON-FROZEN. Headless-Chromium dashboard smoke
 * test. Not part of the shipped app; nothing here runs in production.
 *
 * Starts the Flask backend fresh, loads setuguard_app/frontend/index.html in
 * headless Chromium (via Playwright), and drives six flows end to end:
 *   1. APK analysis (cert-hash-matching APK, so bridge step 3 has something to match)
 *   2. Dataset analysis (real DataSet.csv)
 *   3. Bridge, expected to MATCH on cert_hash (account 9072)
 *   4. APK analysis (C2-host-matching APK, com.kb -- Day 4, 21 Aug), so bridge
 *      step 5 has something to match on the other join key
 *   5. Bridge, expected to MATCH on c2_host (account 9062, host yessign.net --
 *      a real network string extracted by our own static analysis from this
 *      sample, not independently confirmed as live C2 infrastructure; only
 *      the account association is constructed)
 *   6. APK analysis with a different (non-matching) APK, then Bridge again,
 *      expected to produce ZERO links
 *
 * Both ground-truth linkages that steps 3 and 5 exercise are single
 * hand-constructed entries in bridge/matcher.py's SYNTHETIC_LINKAGE_GROUND_TRUTH
 * -- see REPORT_FACTS.md's QUOTABLE -- Bridge section and demo/DEMO_RUNBOOK.md
 * for the full honest framing. This script demonstrates both keys fire; it is
 * not evidence of a validated real-world linkage rate.
 *
 * Captures every console message, every uncaught page exception, and every
 * failed/non-2xx network request, per step. Screenshots each step's rendered
 * result to harness/browser_evidence/<label>/. Exits non-zero if any
 * console 'error' message or uncaught exception occurred in any step.
 *
 * Usage:
 *   node harness/browser_smoke.js [--label ollama_up] [--skip-second-apk]
 *
 * --skip-second-apk lets Task B re-run just the two match paths (cert-hash
 * and C2-host) without needing the third (non-matching) APK for a
 * degradation check.
 */
const { chromium } = require("playwright");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const http = require("http");

const REPO_ROOT = path.resolve(__dirname, "..");
const BACKEND_DIR = path.join(REPO_ROOT, "setuguard_app", "backend");
const FRONTEND_INDEX = path.join(REPO_ROOT, "setuguard_app", "frontend", "index.html");
const MATCHING_APK = path.join(REPO_ROOT, "cicmaldroid_banking",
  "007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk");
const NONMATCHING_APK = path.join(REPO_ROOT, "cicmaldroid_banking",
  "00049d038a2abc2d5fe3b190d6cf5c1cb1ba63441defdf136be251c7a00727d8.apk");
const C2MATCHING_APK = path.join(REPO_ROOT, "cicmaldroid_banking",
  "30baab7000e14cd4a430c8a4a75ea3cae347a6360e0b75ae68c503b5e576cb52.apk");
const DATASET_CSV = path.join(REPO_ROOT, "DataSet.csv");

// analyze_apk's wall-clock is dominated by Ollama/RAG narrative latency, not file
// size or DEX-analysis cost, and that latency varies widely run to run -- four direct
// timings taken 2026-08-19: 007556ca (492KB) at 162.2s (DEMO_RUNBOOK.md:53) and again
// at 162.74s and 61.47s in two later runs; 00049d03... (94KB, the non-matching APK)
// at 46.47s. The prior 60000ms value was never safely above that range; both
// analyze_apk waits in this script timed out against it (unrelated to any other
// change today -- confirmed by diff). Sized at 250000ms = observed max (163s) +
// ~53% headroom, applied to all APK-analysis waits since all draw on the same
// Ollama call and neither file size predicts which end of the range you get.
// com.kb (30baab70..., 361KB, the C2-matching APK added Day 4) measured 46.45s on
// a warm model -- within the existing budget, no change needed.
const APK_ANALYSIS_WAIT_MS = 250000;

const args = process.argv.slice(2);
const labelIdx = args.indexOf("--label");
const LABEL = labelIdx >= 0 ? args[labelIdx + 1] : "default";
const SKIP_SECOND_APK = args.includes("--skip-second-apk");

const EVIDENCE_DIR = path.join(REPO_ROOT, "harness", "browser_evidence", LABEL);
fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

function waitForHealth(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const req = http.get(url, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry();
      });
      req.on("error", retry);
      req.setTimeout(2000, () => { req.destroy(); retry(); });
    };
    const retry = () => {
      if (Date.now() > deadline) return reject(new Error(`backend did not become healthy within ${timeoutMs}ms`));
      setTimeout(tryOnce, 500);
    };
    tryOnce();
  });
}

async function startBackend() {
  const proc = spawn("python3", ["app.py"], {
    cwd: BACKEND_DIR,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const logPath = path.join(EVIDENCE_DIR, "backend_stdout_stderr.log");
  const logStream = fs.createWriteStream(logPath);
  proc.stdout.pipe(logStream);
  proc.stderr.pipe(logStream);
  await waitForHealth("http://127.0.0.1:5000/", 30000);
  return proc;
}

function stopBackend(proc) {
  return new Promise((resolve) => {
    if (!proc || proc.killed) return resolve();
    proc.once("exit", resolve);
    proc.kill("SIGTERM");
    setTimeout(() => { try { proc.kill("SIGKILL"); } catch (_) {} resolve(); }, 5000);
  });
}

class StepRecorder {
  constructor(page, stepName) {
    this.page = page;
    this.stepName = stepName;
    this.console = [];
    this.pageErrors = [];
    this.failedRequests = [];
    this.badResponses = [];
    this._onConsole = (msg) => this.console.push({ type: msg.type(), text: msg.text() });
    this._onPageError = (err) => this.pageErrors.push(String(err && err.stack ? err.stack : err));
    this._onRequestFailed = (req) => this.failedRequests.push({
      url: req.url(), method: req.method(),
      failure: req.failure() ? req.failure().errorText : "unknown",
    });
    this._onResponse = (res) => {
      if (!res.ok()) this.badResponses.push({ url: res.url(), status: res.status() });
    };
    page.on("console", this._onConsole);
    page.on("pageerror", this._onPageError);
    page.on("requestfailed", this._onRequestFailed);
    page.on("response", this._onResponse);
  }
  detach() {
    this.page.off("console", this._onConsole);
    this.page.off("pageerror", this._onPageError);
    this.page.off("requestfailed", this._onRequestFailed);
    this.page.off("response", this._onResponse);
  }
  hasErrors() {
    return this.console.some((c) => c.type === "error") || this.pageErrors.length > 0;
  }
  summary() {
    return {
      step: this.stepName,
      console: this.console,
      pageErrors: this.pageErrors,
      failedRequests: this.failedRequests,
      badResponses: this.badResponses,
      hasErrors: this.hasErrors(),
    };
  }
}

async function runStep(page, stepName, fn) {
  const rec = new StepRecorder(page, stepName);
  let error = null;
  try {
    await fn();
  } catch (e) {
    error = String(e && e.stack ? e.stack : e);
  }
  const shotPath = path.join(EVIDENCE_DIR, `${stepName}.png`);
  await page.screenshot({ path: shotPath, fullPage: true });
  rec.detach();
  const summary = rec.summary();
  summary.screenshot = shotPath;
  summary.stepThrew = error;
  return summary;
}

async function main() {
  console.log(`[browser_smoke] label=${LABEL} skip_second_apk=${SKIP_SECOND_APK}`);
  console.log(`[browser_smoke] starting backend...`);
  const backendProc = await startBackend();
  console.log(`[browser_smoke] backend healthy, pid=${backendProc.pid}`);

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto("file://" + FRONTEND_INDEX);

  const results = [];

  // ---- Step 1: APK analysis (matching-cert APK) ----
  results.push(await runStep(page, "01_apk_matching", async () => {
    await page.click('.nav-item[data-page="malware"]');
    await page.setInputFiles("#apk-input", MATCHING_APK);
    await page.waitForSelector("#apk-analyze-btn:not([disabled])", { timeout: 10000 });
    await page.click("#apk-analyze-btn");
    await page.waitForSelector("#apk-analyze-btn:not([disabled])", { timeout: APK_ANALYSIS_WAIT_MS });
    await page.waitForFunction(
      () => document.getElementById("apk-results").innerHTML.trim().length > 0
        || document.getElementById("apk-status").classList.contains("error"),
      { timeout: 5000 }
    );
  }));

  // ---- Step 2: Dataset analysis ----
  results.push(await runStep(page, "02_dataset", async () => {
    await page.click('.nav-item[data-page="fraud"]');
    await page.setInputFiles("#csv-input", DATASET_CSV);
    await page.waitForSelector("#csv-analyze-btn:not([disabled])", { timeout: 10000 });
    await page.click("#csv-analyze-btn");
    await page.waitForSelector("#csv-analyze-btn:not([disabled])", { timeout: 30000 });
    await page.waitForFunction(
      () => document.getElementById("csv-results").innerHTML.trim().length > 0
        || document.getElementById("csv-status").classList.contains("error"),
      { timeout: 5000 }
    );
  }));

  // ---- Step 3: Bridge, expect MATCH ----
  results.push(await runStep(page, "03_bridge_match", async () => {
    await page.click('.nav-item[data-page="bridge"]');
    await page.click("#bridge-btn");
    await page.waitForFunction(
      () => document.getElementById("bridge-results").innerHTML.trim().length > 0,
      { timeout: 15000 }
    );
  }));
  const bridgeMatchHtml = await page.$eval("#bridge-results", (el) => el.innerText);
  fs.writeFileSync(path.join(EVIDENCE_DIR, "03_bridge_match.txt"), bridgeMatchHtml);

  // ---- Step 4: APK analysis (C2-host-matching APK, com.kb -- Day 4) ----
  results.push(await runStep(page, "04_apk_c2matching", async () => {
    await page.click('.nav-item[data-page="malware"]');
    await page.setInputFiles("#apk-input", C2MATCHING_APK);
    await page.waitForSelector("#apk-analyze-btn:not([disabled])", { timeout: 10000 });
    await page.click("#apk-analyze-btn");
    await page.waitForSelector("#apk-analyze-btn:not([disabled])", { timeout: APK_ANALYSIS_WAIT_MS });
    await page.waitForFunction(
      () => document.getElementById("apk-results").innerHTML.trim().length > 0
        || document.getElementById("apk-status").classList.contains("error"),
      { timeout: 5000 }
    );
  }));

  // ---- Step 5: Bridge, expect MATCH on c2_host (the other join key) ----
  results.push(await runStep(page, "05_bridge_c2match", async () => {
    await page.click('.nav-item[data-page="bridge"]');
    await page.click("#bridge-btn");
    await page.waitForFunction(
      () => document.getElementById("bridge-results").innerHTML.trim().length > 0,
      { timeout: 15000 }
    );
  }));
  const bridgeC2MatchHtml = await page.$eval("#bridge-results", (el) => el.innerText);
  fs.writeFileSync(path.join(EVIDENCE_DIR, "05_bridge_c2match.txt"), bridgeC2MatchHtml);

  if (!SKIP_SECOND_APK) {
    // ---- Step 6: APK analysis (non-matching APK) ----
    results.push(await runStep(page, "06_apk_nonmatching", async () => {
      await page.click('.nav-item[data-page="malware"]');
      await page.setInputFiles("#apk-input", NONMATCHING_APK);
      await page.waitForSelector("#apk-analyze-btn:not([disabled])", { timeout: 10000 });
      await page.click("#apk-analyze-btn");
      await page.waitForSelector("#apk-analyze-btn:not([disabled])", { timeout: APK_ANALYSIS_WAIT_MS });
      await page.waitForFunction(
        () => document.getElementById("apk-results").innerHTML.trim().length > 0
          || document.getElementById("apk-status").classList.contains("error"),
        { timeout: 5000 }
      );
    }));

    // ---- Step 7: Bridge, expect ZERO links ----
    results.push(await runStep(page, "07_bridge_nomatch", async () => {
      await page.click('.nav-item[data-page="bridge"]');
      await page.click("#bridge-btn");
      await page.waitForFunction(
        () => document.getElementById("bridge-results").innerHTML.trim().length > 0,
        { timeout: 15000 }
      );
    }));
    const bridgeNoMatchHtml = await page.$eval("#bridge-results", (el) => el.innerText);
    fs.writeFileSync(path.join(EVIDENCE_DIR, "07_bridge_nomatch.txt"), bridgeNoMatchHtml);
  }

  await browser.close();
  await stopBackend(backendProc);

  const reportPath = path.join(EVIDENCE_DIR, "console_report.json");
  fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));

  console.log("\n===== FULL CONSOLE / ERROR REPORT =====");
  console.log(JSON.stringify(results, null, 2));
  console.log(`\n[browser_smoke] evidence written to ${EVIDENCE_DIR}`);

  const anyErrors = results.some((r) => r.hasErrors || r.stepThrew);
  if (anyErrors) {
    console.error("[browser_smoke] FAIL -- console error, uncaught exception, or step threw");
    process.exit(1);
  }
  console.log("[browser_smoke] PASS -- zero console errors, zero uncaught exceptions across all steps");
  process.exit(0);
}

main().catch((e) => {
  console.error("[browser_smoke] FATAL", e);
  process.exit(2);
});
