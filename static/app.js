/* CyberShield — app.js */

const GAUGE_TOTAL = 157; // arc length for the SVG semicircle

let currentType = "url";

// ── DOM refs ──────────────────────────────────────────────
const tabs        = document.querySelectorAll(".tab");
const textarea    = document.getElementById("target");
const labelEl     = document.getElementById("label");
const scanBtn     = document.getElementById("scan-btn");
const btnText     = document.getElementById("btn-text");
const btnArrow    = document.getElementById("btn-arrow");
const btnSpinner  = document.getElementById("btn-spinner");
const resultCard  = document.getElementById("result");
const resultIcon  = document.getElementById("result-icon");
const resultVerdict = document.getElementById("result-verdict");
const scoreNum    = document.getElementById("score-num");
const gaugeArc    = document.getElementById("gauge-arc");
const reasonsList = document.getElementById("reasons-list");
const recentList  = document.getElementById("recent-list");
const refreshBtn  = document.getElementById("refresh-btn");

// ── Tab switching ─────────────────────────────────────────
tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    currentType = tab.dataset.type;

    if (currentType === "url") {
      labelEl.textContent = "Enter a URL to analyze";
      textarea.placeholder = "https://example.com/login?verify=account";
    } else {
      labelEl.textContent = "Paste a suspicious email, SMS, or chat message";
      textarea.placeholder =
        "Your account will be suspended. Verify your password immediately: https://scam-bank.xyz/secure/login";
    }
    hideResult();
  });
});

// ── Scan ─────────────────────────────────────────────────
scanBtn.addEventListener("click", async () => {
  const value = textarea.value.trim();
  if (!value) {
    textarea.style.borderColor = "var(--malicious)";
    textarea.focus();
    setTimeout(() => (textarea.style.borderColor = ""), 1200);
    return;
  }

  setLoading(true);
  hideResult();

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: currentType, target: value }),
    });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    showResult(data);
    loadStats();
  } catch (e) {
    alert("Network error — make sure the Flask server is running.");
  } finally {
    setLoading(false);
  }
});

// ── Keyboard shortcut (Ctrl/Cmd + Enter) ──────────────────
textarea.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") scanBtn.click();
});

// ── Show result ───────────────────────────────────────────
function showResult(data) {
  const { verdict, score, reasons } = data;

  // Verdict icon
  const icons = { SAFE: "🟢", SUSPICIOUS: "🟡", MALICIOUS: "🔴" };
  resultIcon.textContent    = icons[verdict] ?? "⚠️";
  resultVerdict.textContent = verdict;

  // Card color class
  resultCard.className = "result-card " + verdict;
  resultCard.classList.remove("hidden");

  // Animate gauge
  animateGauge(score, verdict);

  // Reasons
  reasonsList.innerHTML = reasons
    .map(r => `<li>${escapeHtml(r)}</li>`)
    .join("");

  // Scroll into view smoothly
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideResult() {
  resultCard.className = "result-card hidden";
}

// ── Gauge animation ───────────────────────────────────────
function animateGauge(score, verdict) {
  const colors = {
    SAFE:       "#00c97b",
    SUSPICIOUS: "#f5c842",
    MALICIOUS:  "#ff4a4a",
  };
  const offset = GAUGE_TOTAL - (score / 100) * GAUGE_TOTAL;
  gaugeArc.style.strokeDashoffset = GAUGE_TOTAL; // reset
  gaugeArc.style.stroke = colors[verdict] ?? "#00ff9d";

  // Animate number
  let start = 0;
  const duration = 900;
  const startTime = performance.now();

  requestAnimationFrame(function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    scoreNum.textContent = Math.round(ease * score);
    gaugeArc.style.strokeDashoffset = GAUGE_TOTAL - ease * (score / 100) * GAUGE_TOTAL;
    if (progress < 1) requestAnimationFrame(step);
  });
}

// ── Loading state ─────────────────────────────────────────
function setLoading(on) {
  scanBtn.disabled = on;
  btnText.textContent = on ? "SCANNING…" : "SCAN FOR THREATS";
  btnArrow.classList.toggle("hidden", on);
  btnSpinner.classList.toggle("hidden", !on);
}

// ── Stats & recent scans ──────────────────────────────────
async function loadStats() {
  try {
    const data = await fetch("/api/stats").then(r => r.json());
    const { counts, recent } = data;

    document.getElementById("safe").textContent       = counts.SAFE       ?? 0;
    document.getElementById("suspicious").textContent = counts.SUSPICIOUS ?? 0;
    document.getElementById("malicious").textContent  = counts.MALICIOUS  ?? 0;
    document.getElementById("total").textContent      =
      (counts.SAFE ?? 0) + (counts.SUSPICIOUS ?? 0) + (counts.MALICIOUS ?? 0);

    if (!recent || recent.length === 0) {
      recentList.innerHTML = '<div class="no-scans">No scans yet. Analyze a URL or message above to get started.</div>';
      return;
    }

    recentList.innerHTML = recent.map(item => `
      <div class="scan-row">
        <span class="scan-type">${escapeHtml(item.type.toUpperCase())}</span>
        <span class="scan-target" title="${escapeHtml(item.target)}">${escapeHtml(item.target.slice(0, 80))}</span>
        <span class="scan-verdict ${item.verdict}">${item.verdict}</span>
        <span class="scan-score">${item.score}</span>
        <span class="scan-time">${escapeHtml(item.time)}</span>
      </div>
    `).join("");
  } catch (e) {
    // silently ignore stats fetch errors
  }
}

// ── Refresh button ────────────────────────────────────────
refreshBtn.addEventListener("click", () => {
  refreshBtn.textContent = "↻ Refreshing…";
  loadStats().finally(() => (refreshBtn.textContent = "↻ Refresh"));
});

// ── Utility ──────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Init ─────────────────────────────────────────────────
loadStats();
