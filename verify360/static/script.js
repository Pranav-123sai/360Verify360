/* ================================================================
   VERIFY360 — Home Page Script
   script.js
   ================================================================ */

// Flask serves this page, so API calls go to the same origin.
const BASE_URL = "";

let selectedType = "Phone";

const PLACEHOLDERS = {
  Phone:     "Enter phone number  (e.g. 9876543210)",
  WhatsApp:  "Enter number or wa.me link",
  Website:   "Enter website URL  (e.g. https://example.com)",
  Instagram: "Enter username  (e.g. @username or instagram.com/username)",
};

/* ================================================================
   TAB SELECTION
   ================================================================ */
function selectTab(el, type) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  selectedType = type;
  document.getElementById("inputData").placeholder = PLACEHOLDERS[type];

  // Clear the previous result when the user switches tabs
  const result = document.getElementById("result");
  result.className = "hidden";
  result.innerHTML = "";
}

/* ================================================================
   SCAN
   ================================================================ */
async function scanData() {
  const input  = document.getElementById("inputData").value.trim();
  const result = document.getElementById("result");
  const btn    = document.getElementById("scanBtn");

  if (!input) {
    showToast("Please enter something to scan!");
    return;
  }

  // Show loading state
  result.className = "scanning";
  result.innerHTML = `<div style="padding:10px 0">⏳ Scanning <strong>${escHtml(input)}</strong>…</div>`;
  btn.disabled    = true;
  btn.textContent = "Scanning…";

  try {
    const res = await fetch(`${BASE_URL}/api/scan`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ input, type: selectedType }),
    });

    if (!res.ok) throw new Error(`Server returned ${res.status}`);

    const data = await res.json();
    renderResult(data);
    loadLiveFeed(); // Refresh the live feed after each scan

  } catch (err) {
    result.className = "danger";
    result.innerHTML = `
      <div class="result-title">⚠️ Connection Error</div>
      <p style="color:#ff8888; font-size:13px">
        Could not reach the VERIFY360 server.<br>
        Make sure <code style="color:#ff8888">python app.py</code> is running.<br><br>
        <small>${escHtml(err.message)}</small>
      </p>
    `;
  }

  btn.disabled    = false;
  btn.textContent = "⚡ EXECUTE SCAN";
}

/* ================================================================
   RENDER SCAN RESULT
   ================================================================ */
function renderResult(data) {
  const result = document.getElementById("result");
  const level  = data.risk_level; // "HIGH" | "MEDIUM" | "LOW"

  const cssClass  = level === "HIGH" ? "danger" : level === "MEDIUM" ? "medium" : "safe";
  const icon      = data.threat ? (level === "HIGH" ? "⛔" : "⚠️") : "✅";
  const title     = data.threat
    ? (level === "HIGH" ? "THREAT DETECTED" : "POSSIBLE THREAT")
    : "NO THREAT FOUND";

  const barColour = { HIGH: "#ff4d4d", MEDIUM: "#ffaa00", LOW: "#00ff99" }[level];

  const reasonsHtml = (data.reasons && data.reasons.length)
    ? `<p class="reasons-title">Why it was flagged</p>
       <ul class="reasons-list">
         ${data.reasons.map(r => `<li>${escHtml(r)}</li>`).join("")}
       </ul>`
    : `<p style="color:#888; font-size:13px">No specific red flags detected.</p>`;

  const recommendation = data.threat
    ? (level === "HIGH" ? "🚫 DO NOT ENGAGE — High probability of scam"
                        : "⚠️ Proceed with caution")
    : "✅ Appears safe — always stay alert";

  result.className = cssClass;
  result.innerHTML = `
    <div class="result-title">${icon} ${title}</div>

    <div class="result-grid">
      <span class="lbl">Type</span>
      <span class="val">${escHtml(data.type)}</span>

      <span class="lbl">Risk Level</span>
      <span class="val" style="color:${barColour}">${level}</span>

      <span class="lbl">Score</span>
      <span class="val">${data.score} / 100</span>
    </div>

    <div class="score-bar-wrap">
      <div class="score-bar" style="width:${data.score}%; background:${barColour}"></div>
    </div>

    ${reasonsHtml}

    <div class="recommendation">${recommendation}</div>
  `;
}

/* ================================================================
   STATS BAR
   ================================================================ */
async function loadStats() {
  try {
    const res  = await fetch(`${BASE_URL}/api/stats`);
    const data = await res.json();

    document.getElementById("statScans").textContent   = data.total.toLocaleString();
    document.getElementById("statThreats").textContent = data.threats.toLocaleString();
    document.getElementById("statDB").textContent      = data.db_entries.toLocaleString();
    document.getElementById("statReports").textContent = data.reports.toLocaleString();
  } catch {
    // Silent fail — stats are non-critical
  }
}

/* ================================================================
   LIVE FEED
   ================================================================ */
async function loadLiveFeed() {
  const container = document.getElementById("liveFeed");

  try {
    const res  = await fetch(`${BASE_URL}/api/live-feed`);
    const feed = await res.json();

    if (!feed.length) {
      container.innerHTML = `<p id="feedEmpty">No scans yet — be the first to scan!</p>`;
      return;
    }

    container.innerHTML = feed.map(item => {
      const rowClass  = item.risk_level === "HIGH"   ? "feed-danger"
                      : item.risk_level === "MEDIUM" ? "feed-medium"
                      :                                "feed-safe";
      const badgeClass = `badge-${item.type.toLowerCase()}`;

      return `
        <div class="feed-item ${rowClass}">
          <span>${item.threat ? "⚠️" : "✅"}</span>
          <span class="feed-badge ${badgeClass}">${item.type}</span>
          <span class="feed-input">${escHtml(item.input)}</span>
          <span class="feed-risk">${item.risk_level}</span>
          <span class="feed-time">${timeAgo(item.scanned_at)}</span>
        </div>
      `;
    }).join("");

  } catch {
    container.innerHTML = `<p id="feedEmpty">Live feed unavailable.</p>`;
  }
}

/* ================================================================
   REPORT MODAL
   ================================================================ */
async function openModal() {
  // Check if the user is logged in before showing the report modal
  try {
    const res  = await fetch("/api/auth/status");
    const data = await res.json();

    if (!data.logged_in) {
      // Not logged in — send them to the login page, with ?next=report
      // so after login they come back and the modal auto-opens
      window.location.href = "/login?next=report";
      return;
    }
  } catch {
    // If auth check fails, still let them try (server will reject if needed)
  }

  // Logged in — open the report modal
  const currentInput = document.getElementById("inputData").value.trim();
  document.getElementById("reportInput").value = currentInput;
  document.getElementById("reportType").value  = selectedType;
  document.getElementById("reportDesc").value  = "";
  document.getElementById("modalBg").classList.add("open");
}

function closeModal() {
  document.getElementById("modalBg").classList.remove("open");
}

async function submitReport() {
  const input = document.getElementById("reportInput").value.trim();
  const type  = document.getElementById("reportType").value;
  const desc  = document.getElementById("reportDesc").value.trim();

  if (!input) {
    showToast("Please enter the scam number / URL / username.");
    return;
  }

  try {
    const res  = await fetch(`${BASE_URL}/api/report`, {
      method:      "POST",
      credentials: "same-origin",
      headers:     { "Content-Type": "application/json" },
      body:        JSON.stringify({ input, type, description: desc }),
    });

    // Session expired mid-session — redirect to login
    if (res.status === 401) {
      closeModal();
      window.location.href = "/login?next=report";
      return;
    }

    const data = await res.json();
    closeModal();
    showToast(data.message || "Report submitted — thank you!");
    loadStats();
  } catch {
    showToast("Could not submit report. Is the server running?");
  }
}

/* ================================================================
   UTILITY FUNCTIONS
   ================================================================ */

/**
 * Escape HTML special characters to prevent XSS.
 */
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Convert a UTC datetime string to a human-readable "X ago" string.
 */
function timeAgo(dateStr) {
  const seconds = Math.floor((Date.now() - new Date(dateStr + "Z")) / 1000);
  if (seconds < 60)   return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

/**
 * Show a brief toast notification at the bottom-right of the screen.
 */
function showToast(msg) {
  const toast = document.getElementById("toast");
  toast.textContent  = msg;
  toast.style.display = "block";
  setTimeout(() => { toast.style.display = "none"; }, 3500);
}

/* ================================================================
   EVENT LISTENERS & BOOT
   ================================================================ */

// Enter key triggers scan
document.addEventListener("keydown", e => {
  if (e.key === "Enter" && document.activeElement.id === "inputData") scanData();
  if (e.key === "Escape") closeModal();
});

// Close modal when clicking the dark overlay
document.getElementById("modalBg").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeModal();
});

// Initial data load on page ready
loadStats();
loadLiveFeed();

// If redirected back from login with ?report=1, auto-open the report modal
const _params = new URLSearchParams(window.location.search);
if (_params.get("report") === "1") {
  // Small delay so the page finishes rendering first
  setTimeout(() => openModal(), 300);
  // Clean the URL so refreshing does not re-trigger it
  history.replaceState({}, "", "/");
}

// Auto-refresh every 15 seconds
setInterval(() => {
  loadLiveFeed();
  loadStats();
}, 15000);
