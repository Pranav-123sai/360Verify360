/* ================================================================
   VERIFY360 — Admin Panel Script
   admin.js
   ================================================================ */

const TYPES = ["Phone", "WhatsApp", "Website", "Instagram"];
let rowCount = 0;

/* ================================================================
   PASTE GRID — building rows
   ================================================================ */

/**
 * Generate <option> elements for the Type dropdown.
 * @param {string} selected - The type to pre-select.
 */
function makeTypeOptions(selected = "Phone") {
  return TYPES.map(t =>
    `<option value="${t}" ${t === selected ? "selected" : ""}>${t}</option>`
  ).join("");
}

/**
 * Append a new editable row to the paste grid.
 */
function addGridRow(value = "", type = "Phone", desc = "", source = "") {
  rowCount++;
  const n  = rowCount;
  const tr = document.createElement("tr");
  tr.id = `gr-${n}`;

  tr.innerHTML = `
    <td class="row-num">${n}</td>
    <td><input type="text" placeholder="e.g. 9999999999 / scam.tk / @fake_acc" value="${esc(value)}"></td>
    <td><select>${makeTypeOptions(type)}</select></td>
    <td><input type="text" placeholder="optional note" value="${esc(desc)}"></td>
    <td><input type="text" placeholder="e.g. manual / cybercell" value="${esc(source)}"></td>
    <td class="del-cell"><button onclick="removeGridRow('gr-${n}')">✕</button></td>
  `;

  document.getElementById("gridBody").appendChild(tr);

  // Tab from the last input in a row automatically creates a new row
  const focusableEls = tr.querySelectorAll("input, select");
  focusableEls.forEach((el, i, all) => {
    el.addEventListener("keydown", e => {
      if (e.key === "Tab" && i === all.length - 1) {
        e.preventDefault();
        addGridRow();
      }
    });
  });
}

/**
 * Add multiple empty rows at once.
 */
function addGridRows(n) {
  for (let i = 0; i < n; i++) addGridRow();
}

/**
 * Remove a single row by its element id.
 */
function removeGridRow(id) {
  document.getElementById(id)?.remove();
}

/**
 * Clear all rows and reset counter.
 */
function clearGrid() {
  document.getElementById("gridBody").innerHTML = "";
  rowCount = 0;
}

/**
 * Escape a value for use inside an HTML attribute string.
 */
function esc(s) {
  return (s || "").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/* ================================================================
   PASTE FROM CLIPBOARD
   Intercepts Ctrl+V while focus is inside the paste grid and
   converts tab-separated Excel rows into editable grid rows.
   ================================================================ */
document.addEventListener("paste", e => {
  const active = document.activeElement;
  const inGrid = active && active.closest("#pasteGrid");
  if (!inGrid) return;

  e.preventDefault();

  const text  = (e.clipboardData || window.clipboardData).getData("text");
  const lines = text.trim().split(/\r?\n/);

  lines.forEach(line => {
    const cells = line.split("\t");
    addGridRow(
      cells[0] || "",
      TYPES.includes((cells[1] || "").trim()) ? cells[1].trim() : "Phone",
      cells[2] || "",
      cells[3] || ""
    );
  });

  toast(`Pasted ${lines.length} row(s) — review and click Save`);
});

/* ================================================================
   SAVE TO DATABASE
   Reads every row from the grid and posts them to /admin/add-bulk.
   ================================================================ */
async function saveToDatabase() {
  const rows = [];

  document.querySelectorAll("#gridBody tr").forEach(tr => {
    const inputs  = tr.querySelectorAll("input");
    const selects = tr.querySelectorAll("select");
    const value   = inputs[0]?.value.trim();
    const type_   = selects[0]?.value;
    const desc    = inputs[1]?.value.trim();
    const source  = inputs[2]?.value.trim();
    if (value) rows.push({ value, type: type_, description: desc, source });
  });

  if (!rows.length) {
    showStatus("No data to save.", false);
    return;
  }

  const btn = document.querySelector(".btn-success");
  btn.textContent = "Saving…";
  btn.disabled    = true;

  try {
    const res  = await fetch("/admin/add-bulk", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ rows }),
    });
    const data = await res.json();
    const msg  = `✅ Saved ${data.added} entries. Skipped: ${data.skipped}.`;

    showStatus(msg, true);
    toast(msg);

    if (data.added > 0) setTimeout(() => location.reload(), 1200);
    if (data.errors.length) console.warn("Row errors:", data.errors);

  } catch (err) {
    showStatus("❌ Error: " + err.message, false);
  }

  btn.textContent = "💾 Save to Database";
  btn.disabled    = false;
}

/**
 * Show a status message below the grid.
 */
function showStatus(msg, ok) {
  const el = document.getElementById("importStatus");
  el.textContent   = msg;
  el.className     = ok ? "status-ok" : "status-err";
  el.style.display = "block";
}

/* ================================================================
   EDIT MODAL
   ================================================================ */

/**
 * Open the edit modal pre-filled with the row's current data.
 */
function openEdit(id, value, type, desc) {
  document.getElementById("editForm").action = `/admin/edit/${id}`;
  document.getElementById("editValue").value = value;
  document.getElementById("editType").value  = type;
  document.getElementById("editDesc").value  = desc;
  document.getElementById("editModal").classList.add("open");
}

function closeEdit() {
  document.getElementById("editModal").classList.remove("open");
}

// Close modal when clicking the dark overlay
document.getElementById("editModal").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeEdit();
});

/* ================================================================
   TOAST NOTIFICATION
   ================================================================ */
function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent   = msg;
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 3500);
}

/* ================================================================
   BOOT — initialise 10 empty rows on page load
   ================================================================ */
addGridRows(10);
