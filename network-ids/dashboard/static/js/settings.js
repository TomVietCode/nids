// ---------------------------------------------------------------------------
// Settings page — fetch, render, save, and reset NIDS config variables
// ---------------------------------------------------------------------------

const configForm = document.getElementById("configForm");
const saveBtn = document.getElementById("saveBtn");
const resetBtn = document.getElementById("resetBtn");
const toast = document.getElementById("toast");

// Track original values for dirty-checking
let originalValues = {};

// ---------------------------------------------------------------------------
// Toast notification
// ---------------------------------------------------------------------------
function showToast(message, type = "success") {
  toast.textContent = message;
  toast.className = `toast toast-${type} show`;
  setTimeout(() => toast.classList.remove("show"), 3500);
}

// ---------------------------------------------------------------------------
// Render config form dynamically
// ---------------------------------------------------------------------------
function createField(item) {
  const wrapper = document.createElement("div");
  wrapper.className = "config-field";

  const label = document.createElement("label");
  label.setAttribute("for", `cfg-${item.name}`);
  label.textContent = item.name;
  wrapper.appendChild(label);

  // Description from inline comment
  if (item.comment) {
    const desc = document.createElement("span");
    desc.className = "field-desc";
    desc.textContent = item.comment;
    wrapper.appendChild(desc);
  }

  let input;

  if (item.type === "bool") {
    // Checkbox toggle
    input = document.createElement("input");
    input.type = "checkbox";
    input.id = `cfg-${item.name}`;
    input.checked = !!item.value;
    input.dataset.cfgName = item.name;
    input.dataset.cfgType = "bool";
    input.className = "toggle-checkbox";
  } else if (item.type === "int" || item.type === "float") {
    input = document.createElement("input");
    input.type = "number";
    input.id = `cfg-${item.name}`;
    input.value = item.value;
    input.dataset.cfgName = item.name;
    input.dataset.cfgType = item.type;
    if (item.type === "int") input.step = "1";
    if (item.type === "float") input.step = "0.1";
  } else if (item.type === "list" || item.type === "set") {
    // Render as a text area with comma-separated values
    input = document.createElement("textarea");
    input.id = `cfg-${item.name}`;
    const vals = Array.isArray(item.value) ? item.value : Array.from(item.value);
    input.value = vals.join(", ");
    input.dataset.cfgName = item.name;
    input.dataset.cfgType = "list";
    input.rows = Math.max(2, Math.min(vals.length, 4));
  } else {
    // String input
    input = document.createElement("input");
    input.type = "text";
    input.id = `cfg-${item.name}`;
    input.value = item.value ?? "";
    input.dataset.cfgName = item.name;
    input.dataset.cfgType = "str";
  }

  wrapper.appendChild(input);
  return wrapper;
}

async function loadConfig() {
  try {
    const r = await fetch("/api/config");
    const data = await r.json();
    configForm.innerHTML = "";
    originalValues = {};

    const sections = data.sections || {};
    for (const [sectionName, items] of Object.entries(sections)) {
      const section = document.createElement("div");
      section.className = "config-section card";

      const heading = document.createElement("h3");
      heading.textContent = sectionName;
      section.appendChild(heading);

      const fields = document.createElement("div");
      fields.className = "config-fields";

      for (const item of items) {
        fields.appendChild(createField(item));
        // Store original for comparison
        originalValues[item.name] = item.value;
      }
      section.appendChild(fields);
      configForm.appendChild(section);
    }
  } catch (e) {
    configForm.innerHTML =
      '<p class="error-text">Failed to load configuration. Is the server running?</p>';
    console.error("loadConfig", e);
  }
}

// ---------------------------------------------------------------------------
// Collect form values
// ---------------------------------------------------------------------------
function collectValues() {
  const values = {};
  const inputs = configForm.querySelectorAll("[data-cfg-name]");
  for (const el of inputs) {
    const name = el.dataset.cfgName;
    const type = el.dataset.cfgType;

    if (type === "bool") {
      values[name] = el.checked;
    } else if (type === "int") {
      const v = parseInt(el.value, 10);
      if (isNaN(v)) {
        showToast(`${name}: must be an integer`, "error");
        el.focus();
        return null;
      }
      values[name] = v;
    } else if (type === "float") {
      const v = parseFloat(el.value);
      if (isNaN(v)) {
        showToast(`${name}: must be a number`, "error");
        el.focus();
        return null;
      }
      values[name] = v;
    } else if (type === "list") {
      // Parse comma-separated into array
      const raw = el.value.trim();
      if (!raw) {
        values[name] = [];
      } else {
        values[name] = raw.split(",").map((s) => {
          const trimmed = s.trim();
          // Try to parse as number if it looks like one
          const num = Number(trimmed);
          return isNaN(num) ? trimmed : num;
        });
      }
    } else {
      values[name] = el.value;
    }
  }
  return values;
}

// ---------------------------------------------------------------------------
// Save and Reset handlers
// ---------------------------------------------------------------------------
saveBtn.addEventListener("click", async () => {
  const values = collectValues();
  if (!values) return; // validation failed

  saveBtn.disabled = true;
  saveBtn.textContent = "Saving…";
  try {
    const r = await fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ values }),
    });
    const data = await r.json();
    if (r.ok) {
      showToast(`Saved ${data.updated.length} setting(s) successfully`);
      // Reload to reflect server-side state
      await loadConfig();
    } else {
      const details = data.details ? data.details.join("; ") : data.error;
      showToast(`Error: ${details}`, "error");
    }
  } catch (e) {
    showToast("Network error — could not save", "error");
    console.error("saveConfig", e);
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = "Save Changes";
  }
});

resetBtn.addEventListener("click", async () => {
  if (!confirm("Reset all settings to factory defaults? This cannot be undone.")) {
    return;
  }
  resetBtn.disabled = true;
  resetBtn.textContent = "Resetting…";
  try {
    const r = await fetch("/api/config/reset", { method: "POST" });
    const data = await r.json();
    if (r.ok) {
      showToast("All settings restored to defaults");
      await loadConfig();
    } else {
      showToast(`Error: ${data.error}`, "error");
    }
  } catch (e) {
    showToast("Network error — could not reset", "error");
    console.error("resetConfig", e);
  } finally {
    resetBtn.disabled = false;
    resetBtn.textContent = "Reset to Defaults";
  }
});

// Initial load
loadConfig();
