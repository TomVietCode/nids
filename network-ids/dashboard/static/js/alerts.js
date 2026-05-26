// ---------------------------------------------------------------------------
// DSH-02  Alert feed (initial REST load + live SocketIO append)
// ---------------------------------------------------------------------------
const alertList = document.getElementById("alertFeed")

function renderAlert(a) {
  const li = document.createElement("li")
  const sev = (a.severity || "LOW").toLowerCase()
  li.innerHTML = `
    <span class="badge badge-${sev}">${a.severity}</span>
    <strong>${a.threat_type}</strong>
    <span>${a.src_ip}</span>
    <span class="ts">${new Date(a.timestamp).toLocaleTimeString()}</span>
    <span style="color: var(--muted); margin-left: auto;">${a.details ?? ""}</span>
  `
  alertList.prepend(li)
  while (alertList.children.length > 100) alertList.removeChild(alertList.lastChild)
}

async function loadInitialAlerts() {
  try {
    const r = await fetch("/api/alerts?limit=50")
    const items = await r.json()
    for (const a of items.reverse()) renderAlert(a)
  } catch (e) {
    console.error("loadInitialAlerts", e)
  }
}
loadInitialAlerts()
socket.on("new_alert", renderAlert)

// ---------------------------------------------------------------------------
// RES-03  IP list management
// ---------------------------------------------------------------------------
const ipForm = document.getElementById("iplistForm")
const ipTableBody = document.querySelector("#iplistTable tbody")

async function refreshIPList() {
  const r = await fetch("/api/iplist")
  const items = await r.json()
  ipTableBody.innerHTML = ""
  for (const x of items) {
    const tr = document.createElement("tr")
    tr.innerHTML = `
      <td>${x.ip_address}</td>
      <td>${x.list_type}</td>
      <td>${new Date(x.added_at).toLocaleString()}</td>
      <td>${x.reason ?? ""}</td>
      <td><button data-ip="${x.ip_address}" class="del">Remove</button></td>
    `
    ipTableBody.appendChild(tr)
  }
}
ipForm.addEventListener("submit", async (e) => {
  e.preventDefault()
  const fd = new FormData(ipForm)
  await fetch("/api/iplist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ip: fd.get("ip"),
      type: fd.get("type"),
      reason: fd.get("reason") || null,
    }),
  })
  ipForm.reset()
  refreshIPList()
})
ipTableBody.addEventListener("click", async (e) => {
  if (!e.target.matches(".del")) return
  await fetch(`/api/iplist/${e.target.dataset.ip}`, { method: "DELETE" })
  refreshIPList()
})
refreshIPList()

// ---------------------------------------------------------------------------
// DSH-05  Packet log viewer with pagination + CSV export link
// ---------------------------------------------------------------------------
const logForm = document.getElementById("logFilters")
const logBody = document.querySelector("#logTable tbody")
const pageInfo = document.getElementById("pageInfo")
const csvLink = document.getElementById("csvExport")
const logState = { page: 1, ip: "", proto: "" }

function logQueryString() {
  const p = new URLSearchParams()
  p.set("page", logState.page)
  if (logState.ip) p.set("ip", logState.ip)
  if (logState.proto) p.set("proto", logState.proto)
  return p.toString()
}

async function refreshLogs() {
  try {
    const r = await fetch("/api/logs?" + logQueryString())
    const data = await r.json()
    logBody.innerHTML = ""
    for (const row of data.items) {
      const tr = document.createElement("tr")
      tr.innerHTML = `
        <td>${new Date(row.timestamp).toLocaleTimeString()}</td>
        <td>${row.src_ip}</td>
        <td>${row.dst_ip}</td>
        <td>${row.protocol}</td>
        <td>${row.src_port ?? ""}</td>
        <td>${row.dst_port ?? ""}</td>
        <td>${row.payload_size ?? ""}</td>
      `
      logBody.appendChild(tr)
    }
    const totalPages = Math.max(1, Math.ceil(data.total / data.per_page))
    pageInfo.textContent = `Page ${data.page} / ${totalPages} (${data.total} rows)`
    csvLink.href = "/api/logs/export.csv?" + logQueryString()
  } catch (e) {
    console.error("refreshLogs", e)
  }
}

logForm.addEventListener("submit", (e) => {
  e.preventDefault()
  const fd = new FormData(logForm)
  logState.page = 1
  logState.ip = fd.get("ip") || ""
  logState.proto = fd.get("proto") || ""
  refreshLogs()
})
document.getElementById("prevPage").addEventListener("click", () => {
  logState.page = Math.max(1, logState.page - 1)
  refreshLogs()
})
document.getElementById("nextPage").addEventListener("click", () => {
  logState.page += 1
  refreshLogs()
})

refreshLogs()
setInterval(refreshLogs, 5000)
