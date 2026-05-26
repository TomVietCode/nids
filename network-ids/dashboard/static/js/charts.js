// Single SocketIO client, reused by alerts.js (loaded after this file).
const socket = io();
const statusDot = document.getElementById('status');
socket.on('connect',    () => statusDot.classList.add('live'));
socket.on('disconnect', () => statusDot.classList.remove('live'));

// ---------------------------------------------------------------------------
// DSH-01  Traffic chart (line, 60s rolling window, fed by 'traffic_update')
// ---------------------------------------------------------------------------
const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'pkts/sec',
      data: [],
      borderColor: '#4f8ef7',
      backgroundColor: 'rgba(79, 142, 247, 0.15)',
      tension: 0.25,
      fill: true,
      pointRadius: 0,
    }],
  },
  options: {
    animation: false,
    scales: { y: { beginAtZero: true } },
    plugins: { legend: { display: false } },
  },
});
socket.on('traffic_update', (windowPoints) => {
  trafficChart.data.labels = windowPoints.map(p => {
    const d = new Date(p.t);
    return isNaN(d.getTime()) ? p.t : d.toLocaleTimeString();
  });
  trafficChart.data.datasets[0].data = windowPoints.map(p => p.pps);
  trafficChart.update('none');
});

// ---------------------------------------------------------------------------
// DSH-04  Protocol distribution (doughnut, polled every 5s)
// ---------------------------------------------------------------------------
const protocolCtx = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(protocolCtx, {
  type: 'doughnut',
  data: {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: ['#4f8ef7', '#4caf50', '#ff9800', '#d50000', '#8b94a7'],
    }],
  },
  options: { plugins: { legend: { position: 'right' } } },
});
async function refreshProtocol() {
  try {
    const r = await fetch('/api/stats/protocol');
    const data = await r.json();
    protocolChart.data.labels = Object.keys(data);
    protocolChart.data.datasets[0].data = Object.values(data);
    protocolChart.update();
  } catch (e) { console.error('refreshProtocol', e); }
}
refreshProtocol();
setInterval(refreshProtocol, 5000);

// ---------------------------------------------------------------------------
// DSH-03  Threat heatmap (CSS grid, 7 rows x 24 cols, polled every 30s)
// ---------------------------------------------------------------------------
async function refreshHeatmap() {
  try {
    const r = await fetch('/api/stats/heatmap');
    const { grid } = await r.json();
    const root = document.getElementById('heatmap');
    root.innerHTML = '';
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    let max = 0;
    for (const row of grid) for (const v of row) if (v > max) max = v;

    // header row: empty corner + 0..23
    root.appendChild(document.createElement('div'));
    for (let h = 0; h < 24; h++) {
      const el = document.createElement('div');
      el.className = 'lbl';
      el.textContent = h;
      root.appendChild(el);
    }

    for (let d = 0; d < 7; d++) {
      const lbl = document.createElement('div');
      lbl.className = 'lbl';
      lbl.textContent = days[d];
      root.appendChild(lbl);
      for (let h = 0; h < 24; h++) {
        const v = grid[d][h];
        const intensity = max ? v / max : 0;
        const cell = document.createElement('div');
        cell.className = 'cell';
        cell.title = `${days[d]} ${h}:00 — ${v} alerts`;
        cell.style.background = `rgba(255, 87, 34, ${0.12 + intensity * 0.85})`;
        root.appendChild(cell);
      }
    }
  } catch (e) { console.error('refreshHeatmap', e); }
}
refreshHeatmap();
setInterval(refreshHeatmap, 30000);