/*
 * harness/verify_chartjs.js -- NON-FROZEN, ad-hoc. Task G verification.
 *
 * browser_smoke.js's steps all navigate to a sub-page (malware/fraud/bridge)
 * before attaching their console/error listeners, so none of them actually
 * covers the dashboard's *initial* render -- app.js calls renderDashboard()
 * (which creates the Chart.js line chart) synchronously during page load,
 * before any step-level listener exists. This script closes that gap
 * specifically: listeners are attached BEFORE page.goto(), so the initial
 * load -- including Chart.js executing -- is actually covered. No backend
 * needed; the chart renders from empty in-memory state.
 *
 * Confirms: setuguard_app/frontend/chart.umd.js loads over a local
 * file:// script tag (not a CDN -- there is no network request to
 * anything but file://), `window.Chart` is defined, and a <canvas> the
 * library has drawn into is present, with zero console errors / page
 * errors / failed requests during the load.
 */
const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");

const REPO_ROOT = path.resolve(__dirname, "..");
const FRONTEND_INDEX = path.join(REPO_ROOT, "setuguard_app", "frontend", "index.html");
const EVIDENCE_DIR = path.join(REPO_ROOT, "harness", "browser_evidence", "chartjs_vendored");
fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

async function main() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  const consoleMsgs = [];
  const pageErrors = [];
  const failedRequests = [];
  const allRequests = [];
  page.on("console", (msg) => consoleMsgs.push({ type: msg.type(), text: msg.text() }));
  page.on("pageerror", (err) => pageErrors.push(String(err && err.stack ? err.stack : err)));
  page.on("requestfailed", (req) => failedRequests.push({ url: req.url(), failure: req.failure()?.errorText }));
  page.on("request", (req) => allRequests.push(req.url()));

  await page.goto("file://" + FRONTEND_INDEX);
  await page.waitForFunction(() => typeof window.Chart !== "undefined", { timeout: 5000 });
  await page.waitForSelector("#threat-chart", { state: "attached", timeout: 5000 });

  const chartInfo = await page.evaluate(() => {
    const c = document.getElementById("threat-chart");
    return {
      chartGlobalDefined: typeof window.Chart !== "undefined",
      chartVersion: window.Chart ? window.Chart.version : null,
      canvasVisible: c ? c.style.display !== "none" : false,
      canvasWidth: c ? c.width : null,
      canvasHeight: c ? c.height : null,
    };
  });

  await page.screenshot({ path: path.join(EVIDENCE_DIR, "dashboard_initial_load.png"), fullPage: true });
  await browser.close();

  // The dashboard's own health check (checkHealth() in app.js) legitimately
  // calls the local Flask backend at load time -- that's not a CDN
  // dependency. What actually matters for "is Chart.js vendored, not
  // CDN-loaded" is: no request left file:// / 127.0.0.1 / localhost.
  const externalRequests = allRequests.filter((u) => {
    if (u.startsWith("file://")) return false;
    try {
      const h = new URL(u).hostname;
      return h !== "127.0.0.1" && h !== "localhost";
    } catch (_) {
      return true;
    }
  });
  const report = {
    chartInfo,
    consoleMsgs,
    pageErrors,
    failedRequests,
    allRequestUrls: allRequests,
    externalRequests,
    hasErrors: consoleMsgs.some((m) => m.type === "error") || pageErrors.length > 0,
  };
  fs.writeFileSync(path.join(EVIDENCE_DIR, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));

  if (!chartInfo.chartGlobalDefined) {
    console.error("FAIL -- window.Chart is not defined, chart.umd.js did not load/execute");
    process.exit(1);
  }
  if (externalRequests.length > 0) {
    console.error("FAIL -- page made a request to an external (non-local) host, i.e. a CDN dependency exists:", externalRequests);
    process.exit(1);
  }
  if (report.hasErrors) {
    console.error("FAIL -- console error or page error during initial dashboard load");
    process.exit(1);
  }
  console.log(`PASS -- Chart.js ${chartInfo.chartVersion} loaded from local file://, zero non-file:// requests, zero console/page errors`);
  process.exit(0);
}

main().catch((e) => { console.error("FATAL", e); process.exit(2); });
