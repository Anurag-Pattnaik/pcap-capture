const DETECTION_SOURCES = [
  {
    id: "ML-*",
    name: "ML model classification",
    category: "model",
  },
  {
    id: "META-1001",
    name: "Sustained packet-rate anomaly",
    category: "metadata",
  },
  {
    id: "META-1002",
    name: "Encrypted service metadata",
    category: "metadata",
  },
  {
    id: "META-0000",
    name: "Metadata baseline",
    category: "baseline",
  },
  {
    id: "RESPONSE",
    name: "Manual blocklist response",
    category: "response",
  },
];

const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const state = {
  logs: [],
  metrics: {
    packets: 0,
    alerts: 0,
    encrypted: 0,
    blocked: 0,
  },
  filters: {
    search: "",
    severity: "all",
    action: "all",
  },
  view: "overview",
  health: null,
};

const elements = {
  apiStatus: document.querySelector("#api-status"),
  captureStatus: document.querySelector("#capture-status"),
  modelStatus: document.querySelector("#model-status"),
  deviceStatus: document.querySelector("#device-status"),
  socketStatus: document.querySelector("#socket-status"),
  interfaceInput: document.querySelector("#interface-input"),
  interfaceOptions: document.querySelector("#interface-options"),
  filterInput: document.querySelector("#filter-input"),
  startCapture: document.querySelector("#start-capture"),
  stopCapture: document.querySelector("#stop-capture"),
  manualIp: document.querySelector("#manual-ip"),
  manualBlock: document.querySelector("#manual-block"),
  blocklist: document.querySelector("#blocklist"),
  pcapInput: document.querySelector("#pcap-input"),
  analyzePcap: document.querySelector("#analyze-pcap"),
  pcapResult: document.querySelector("#pcap-result"),
  exportLogs: document.querySelector("#export-logs"),
  exportResult: document.querySelector("#export-result"),
  logTable: document.querySelector("#log-table"),
  details: document.querySelector("#event-details"),
  selectedSeverity: document.querySelector("#selected-severity"),
  deviceDetails: document.querySelector("#device-details"),
  modelContract: document.querySelector("#model-contract"),
  metricPackets: document.querySelector("#metric-packets"),
  metricAlerts: document.querySelector("#metric-alerts"),
  metricEncrypted: document.querySelector("#metric-encrypted"),
  metricBlocked: document.querySelector("#metric-blocked"),
  metricCritical: document.querySelector("#metric-critical"),
  metricTopTalker: document.querySelector("#metric-top-talker"),
  alertQueue: document.querySelector("#alert-queue"),
  alertTimeline: document.querySelector("#alert-timeline"),
  timelineTotal: document.querySelector("#timeline-total"),
  topSources: document.querySelector("#top-sources"),
  topTargets: document.querySelector("#top-targets"),
  entityTotal: document.querySelector("#entity-total"),
  trafficMix: document.querySelector("#traffic-mix"),
  mixTotal: document.querySelector("#mix-total"),
  ruleSummary: document.querySelector("#rule-summary"),
  ruleList: document.querySelector("#rule-list"),
  modelType: document.querySelector("#model-type"),
  modelHealth: document.querySelector("#model-health"),
  searchInput: document.querySelector("#search-input"),
  severityFilter: document.querySelector("#severity-filter"),
  actionFilter: document.querySelector("#action-filter"),
  viewTabs: document.querySelectorAll("[data-view-target]"),
  viewSections: document.querySelectorAll("[data-view]"),
  logCount: document.querySelector("#log-count"),
  chartTraffic: document.querySelector("#chartTraffic"),
  chartAttacks: document.querySelector("#chartAttacks"),
  chartPorts: document.querySelector("#chartPorts"),
  chartSourceIPs: document.querySelector("#chartSourceIPs"),
  chartProtocols: document.querySelector("#chartProtocols"),
};

const charts = {
  traffic: null,
  attacks: null,
  ports: null,
  sources: null,
  protocols: null,
};

function setPill(element, text, className) {
  element.textContent = text;
  const baseClass = element.classList.contains("status-pill") ? "status-pill" : "pill";
  element.className = `${baseClass} ${className}`;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `Request failed: ${response.status}`);
  }
  return payload;
}

async function refreshHealth() {
  try {
    const health = await requestJson("/health");
    setPill(elements.apiStatus, "API online", "ok");
    setPill(
      elements.captureStatus,
      health.capture.running ? "Capture running" : "Capture stopped",
      health.capture.running ? "ok" : "neutral",
    );
    setPill(
      elements.modelStatus,
      health.model_loaded ? "Model loaded" : "Metadata mode",
      health.model_loaded ? "ok" : "warn",
    );
    renderBlocklist(health.capture.blocked_ips || []);
    renderModelContract(health);
    renderDevice(health.device);
    state.health = health;
    if (health.metrics) {
      state.metrics = { ...state.metrics, ...health.metrics };
      renderAll();
    }
  } catch (error) {
    setPill(elements.apiStatus, "API offline", "danger");
    elements.modelContract.textContent = error.message;
  }
}

function renderModelContract(health) {
  if (!health.model_loaded) {
    elements.modelContract.textContent =
      "No trained pipeline was found. The console is running metadata rules and response workflows.";
    return;
  }

  const count = health.expected_features ? health.expected_features.length : 0;
  elements.modelContract.textContent = `${count} expected model features from ${health.model_path}`;
}

function renderDevice(device) {
  if (!device) return;
  setPill(elements.deviceStatus, device.hostname || "Sensor online", "ok");
  const rows = [
    ["Device ID", device.device_id],
    ["Hostname", device.hostname],
    ["Platform", device.platform],
  ];
  replaceDefinitionList(elements.deviceDetails, rows);
}

function renderBlocklist(blockedIps) {
  elements.blocklist.replaceChildren();
  if (!blockedIps.length) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.className = "muted";
    label.textContent = "No blocked IPs";
    item.append(label);
    elements.blocklist.append(item);
    return;
  }

  for (const ip of blockedIps) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    const button = document.createElement("button");
    label.textContent = ip;
    button.textContent = "Unblock";
    button.addEventListener("click", () => unblockIp(ip));
    item.append(label, button);
    elements.blocklist.append(item);
  }
}

function addLog(log) {
  state.logs.unshift(log);
  state.logs = state.logs.slice(0, 300);
  state.metrics.packets += 1;
  if (log.encrypted_likely) state.metrics.encrypted += 1;
  if (log.action === "blocked") state.metrics.blocked += 1;
  if (isAlert(log)) state.metrics.alerts += 1;
  renderAll();
}

function renderAll() {
  renderMetrics();
  renderRuleSummary();
  renderAlertQueue();
  renderAlertTimeline();
  renderTopEntities();
  renderTrafficMix();
  renderModelHealth();
  renderCharts();
  renderLogs();
  renderView();
}

function renderMetrics() {
  const enriched = state.logs.map(enrichLog);
  const criticalCount = enriched.filter((log) => log.severity === "critical").length;
  const topTalker = topValue(state.logs.map((log) => log.source_ip).filter(Boolean));

  elements.metricPackets.textContent = state.metrics.packets;
  elements.metricAlerts.textContent = state.metrics.alerts;
  elements.metricEncrypted.textContent = state.metrics.encrypted;
  elements.metricBlocked.textContent = state.metrics.blocked;
  elements.metricCritical.textContent = criticalCount;
  elements.metricTopTalker.textContent = topTalker || "-";
}

function renderRuleSummary() {
  const rows = [
    ["Sources", DETECTION_SOURCES.length],
    ["Backend", "owned"],
    ["ML-backed", DETECTION_SOURCES.filter((source) => source.category === "model").length],
  ];

  elements.ruleSummary.replaceChildren(
    ...rows.map(([label, value]) => {
      const item = document.createElement("div");
      const valueElement = document.createElement("strong");
      const labelElement = document.createElement("span");
      valueElement.textContent = value;
      labelElement.textContent = label;
      item.append(valueElement, labelElement);
      return item;
    }),
  );

  elements.ruleList.replaceChildren(
    ...DETECTION_SOURCES.map((source) => {
      const item = document.createElement("article");
      const title = document.createElement("strong");
      const meta = document.createElement("span");
      title.textContent = source.id;
      meta.textContent = `${source.name} / ${source.category}`;
      item.append(title, meta);
      return item;
    }),
  );
}

function renderAlertQueue() {
  const alerts = deduplicatedAlerts(
    state.logs
    .map(enrichLog)
    .filter((log) => log.severity !== "info" && (isAlert(log) || log.action === "blocked"))
  )
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count)
    .slice(0, 8);

  elements.alertQueue.replaceChildren();
  if (!alerts.length) {
    const empty = document.createElement("p");
    empty.className = "muted empty-state";
    empty.textContent = "No active alerts in the current window.";
    elements.alertQueue.append(empty);
    return;
  }

  for (const alert of alerts) {
    const item = document.createElement("button");
    const title = document.createElement("strong");
    const meta = document.createElement("span");
    item.className = "alert-card";
    title.textContent = alert.signature;
    meta.textContent = `${alert.severity.toUpperCase()} / ${alert.count}x / ${formatEndpoint(alert.source_ip, alert.source_port)} -> ${formatEndpoint(
      alert.destination_ip,
      alert.destination_port,
    )}`;
    item.append(title, meta);
    item.addEventListener("click", () => renderDetails(alert));
    elements.alertQueue.append(item);
  }
}

function renderAlertTimeline() {
  const alerts = state.logs.map(enrichLog).filter(isAlert);
  const buckets = countBy(alerts, (log) => {
    const date = new Date(log.timestamp);
    if (Number.isNaN(date.getTime())) return "unknown";
    date.setSeconds(0, 0);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  });
  const entries = Object.entries(buckets).slice(-10);
  elements.timelineTotal.textContent = `${alerts.length} alerts`;
  elements.alertTimeline.replaceChildren();

  if (!entries.length) {
    elements.alertTimeline.append(emptyState("No alert timeline yet."));
    return;
  }

  const maxCount = Math.max(...entries.map(([, count]) => count), 1);
  for (const [label, count] of entries) {
    const row = document.createElement("div");
    const time = document.createElement("span");
    const track = document.createElement("div");
    const fill = document.createElement("i");
    const value = document.createElement("strong");
    time.textContent = label;
    fill.style.width = `${Math.max((count / maxCount) * 100, 5)}%`;
    value.textContent = count;
    track.append(fill);
    row.append(time, track, value);
    elements.alertTimeline.append(row);
  }
}

function renderTopEntities() {
  const sources = state.logs.map((log) => log.source_ip).filter(Boolean);
  const targets = state.logs.map((log) => log.destination_ip).filter(Boolean);
  renderRankList(elements.topSources, sources);
  renderRankList(elements.topTargets, targets);
  elements.entityTotal.textContent = `${new Set([...sources, ...targets]).size} entities`;
}

function renderRankList(container, values) {
  const entries = Object.entries(countBy(values, (value) => value))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
  container.replaceChildren();

  if (!entries.length) {
    container.append(emptyState("No entities observed."));
    return;
  }

  for (const [label, count] of entries) {
    const row = document.createElement("div");
    const name = document.createElement("span");
    const value = document.createElement("strong");
    name.textContent = label;
    value.textContent = count;
    row.append(name, value);
    container.append(row);
  }
}

function renderTrafficMix() {
  const protocols = countBy(state.logs, (log) => log.protocol || "UNKNOWN");
  const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const total = state.logs.length || 0;
  elements.mixTotal.textContent = `${total} events`;
  elements.trafficMix.replaceChildren();

  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "muted empty-state";
    empty.textContent = "Traffic mix appears after live events arrive.";
    elements.trafficMix.append(empty);
    return;
  }

  for (const [protocol, count] of entries) {
    const row = document.createElement("div");
    const label = document.createElement("span");
    const track = document.createElement("div");
    const fill = document.createElement("i");
    const value = document.createElement("strong");
    const percentage = total ? Math.round((count / total) * 100) : 0;
    label.textContent = protocol;
    fill.style.width = `${Math.max(percentage, 4)}%`;
    value.textContent = `${count}`;
    track.append(fill);
    row.append(label, track, value);
    elements.trafficMix.append(row);
  }
}

function renderModelHealth() {
  if (!elements.modelHealth) return;
  const health = state.health;
  const modelInfo = health?.model_info;
  elements.modelType.textContent = modelInfo?.type || (health?.model_loaded ? "loaded" : "metadata mode");

  if (!health?.model_loaded || !modelInfo) {
    elements.modelHealth.replaceChildren(emptyState("No ML model is loaded."));
    return;
  }

  const rows = [
    ["Model type", modelInfo.type],
    ["Binary model", modelInfo.binary_model_path || modelInfo.model_path],
    ["Attack model", modelInfo.attack_model_path],
    ["Decision gate", modelInfo.attack_threshold ? confidenceBand(modelInfo.attack_threshold) : "-"],
    ["Feature columns", modelInfo.expected_features ? modelInfo.expected_features.length : 0],
    ["Flow gate", `${health.capture.ml_min_packets} packets / ${health.capture.ml_min_duration}s`],
    ["Active flows", health.capture.flow_count],
  ];

  const list = document.createElement("dl");
  list.className = "details model-details";
  replaceDefinitionList(list, rows);

  const featureBox = document.createElement("div");
  featureBox.className = "feature-cloud";
  for (const feature of modelInfo.expected_features || []) {
    const tag = document.createElement("span");
    tag.textContent = feature;
    featureBox.append(tag);
  }

  elements.modelHealth.replaceChildren(list, featureBox);
}

function renderLogs() {
  elements.logTable.replaceChildren();
  if (elements.logCount) elements.logCount.textContent = `${filteredLogs().length} entries`;

  for (const log of filteredLogs().slice(0, 140)) {
    const enriched = enrichLog(log);
    const row = document.createElement("tr");
    row.classList.add(`severity-${enriched.severity}`);
    if (log.action === "blocked") row.classList.add("blocked-row");
    if (isAlert(log)) row.classList.add("alert-row");

    appendCell(row, formatTime(log.timestamp), "mono");
    appendCell(row, formatEndpoint(log.source_ip, log.source_port));
    appendCell(row, log.destination_port || "-", "mono");
    appendTagCell(row, verdictLabel(enriched), verdictClass(enriched));
    appendCell(row, attackLabel(enriched));
    appendTagCell(row, enriched.severity, enriched.severity);

    const actionCell = document.createElement("td");
    const inspectButton = document.createElement("button");
    inspectButton.className = "detail-link";
    inspectButton.innerHTML = '<i class="fa-solid fa-ellipsis"></i>';
    inspectButton.addEventListener("click", () => renderDetails(enriched));
    actionCell.append(inspectButton);
    row.append(actionCell);

    row.addEventListener("dblclick", () => renderDetails(enriched));
    elements.logTable.append(row);
  }
}

function filteredLogs() {
  return state.logs.filter((log) => {
    const enriched = enrichLog(log);
    const haystack = [
      log.source_ip,
      log.destination_ip,
      log.protocol,
      log.prediction,
      log.reason,
      enriched.signature,
      enriched.rule_id,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    if (state.filters.search && !haystack.includes(state.filters.search)) return false;
    if (state.filters.severity !== "all" && enriched.severity !== state.filters.severity) return false;
    if (state.filters.action !== "all" && log.action !== state.filters.action) return false;
    return true;
  });
}

function appendCell(row, value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value ?? "-";
  row.append(cell);
}

function appendTagCell(row, value, className = "") {
  const cell = document.createElement("td");
  const tag = document.createElement("span");
  tag.className = `tag ${className}`;
  tag.textContent = value ?? "-";
  cell.append(tag);
  row.append(cell);
}

function renderDetails(log) {
  const enriched = enrichLog(log);
  elements.selectedSeverity.textContent = enriched.severity;
  elements.selectedSeverity.className = `tag ${enriched.severity}`;

  const rows = [
    ["Event ID", log.id],
    ["Time", formatDateTime(log.timestamp)],
    ["Signature", enriched.signature],
    ["Rule ID", enriched.rule_id],
    ["Severity", enriched.severity],
    ["Source", formatEndpoint(log.source_ip, log.source_port)],
    ["Destination", formatEndpoint(log.destination_ip, log.destination_port)],
    ["Protocol", log.protocol],
    ["Flow ID", log.flow_id],
    ["Flow packets", log.flow_packet_count],
    ["Flow bytes", log.flow_byte_count],
    ["Flow duration", formatSeconds(log.flow_duration)],
    ["Length", log.length],
    ["Time diff", log.time_diff],
    ["Packet rate", log.packet_rate],
    ["Average size", log.avg_length],
    ["Encrypted", log.encrypted_likely ? "Likely" : "No"],
    ["Prediction", log.prediction],
    ["Model certainty", confidenceBand(log.ml_confidence)],
    ["Binary label", log.binary_label],
    ["Attack label", log.attack_label],
    ["Action", log.action],
    ["Reason", log.reason],
  ];

  replaceDefinitionList(elements.details, rows);

  if (log.source_ip) {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    const button = document.createElement("button");
    dt.textContent = "Response";
    button.textContent = "Block source IP";
    button.className = "danger";
    button.addEventListener("click", () => blockIp(log.source_ip, `Blocked from event ${log.id}`));
    dd.append(button);
    elements.details.append(dt, dd);
  }
}

function verdictLabel(log) {
  return isAlert(log) ? "MALICIOUS" : "SAFE";
}

function verdictClass(log) {
  return isAlert(log) ? "mal" : "safe";
}

function attackLabel(log) {
  if (!isAlert(log)) return "-";
  return log.attack_label || log.prediction || log.signature || "-";
}

function replaceDefinitionList(list, rows) {
  list.replaceChildren(
    ...rows.flatMap(([key, value]) => {
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = key;
      dd.textContent = value ?? "-";
      return [dt, dd];
    }),
  );
}

function enrichLog(log) {
  const severity = normalizeSeverity(log.severity || fallbackSeverity(log));
  return {
    ...log,
    severity,
    rule_id: log.rule_id || "LEGACY-0000",
    signature: log.signature || log.prediction || "Metadata baseline",
  };
}

function deduplicatedAlerts(alerts) {
  const groups = new Map();
  for (const alert of alerts) {
    const key = [alert.signature, alert.source_ip, alert.destination_ip, alert.severity].join("|");
    const current = groups.get(key);
    if (!current) {
      groups.set(key, { ...alert, count: 1 });
      continue;
    }

    current.count += 1;
    if (Number(new Date(alert.timestamp)) > Number(new Date(current.timestamp))) {
      Object.assign(current, alert, { count: current.count });
    }
  }
  return [...groups.values()];
}

function isAlert(log) {
  return normalizeSeverity(log.severity || fallbackSeverity(log)) !== "info";
}

function normalizeSeverity(value) {
  const normalized = String(value || "info").toLowerCase();
  return Object.hasOwn(SEVERITY_RANK, normalized) ? normalized : "info";
}

function fallbackSeverity(log) {
  const prediction = String(log.prediction || "").toLowerCase();
  if (["normal", "benign"].includes(prediction)) return "info";
  if (log.reason === "high_packet_rate") return "critical";
  return "medium";
}

function countBy(items, getKey) {
  return items.reduce((counts, item) => {
    const key = getKey(item);
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function topValue(values) {
  const counts = countBy(values, (value) => value);
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0];
}

function formatEndpoint(ip, port) {
  if (!ip) return "-";
  return port ? `${ip}:${port}` : ip;
}

function formatTime(value) {
  try {
    return new Date(value).toLocaleTimeString();
  } catch {
    return value;
  }
}

function formatDateTime(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function confidenceBand(value) {
  if (value === null || value === undefined || value === "") return "-";
  const numericValue = Number(value);
  if (Number.isNaN(numericValue)) return value;
  if (numericValue >= 90) return "Very high";
  if (numericValue >= 80) return "High";
  if (numericValue >= 65) return "Moderate";
  return "Low";
}

function initCharts() {
  if (!window.Chart) return;
  Chart.defaults.font.family = "'Inter', 'Segoe UI', sans-serif";
  Chart.defaults.color = "#94a3b8";
  Chart.defaults.borderColor = "rgba(255,255,255,0.05)";

  if (elements.chartTraffic && !charts.traffic) {
    charts.traffic = new Chart(elements.chartTraffic, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Safe",
            data: [],
            borderColor: "#22d3ee",
            backgroundColor: "rgba(34,211,238,0.08)",
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 0,
          },
          {
            label: "Threat",
            data: [],
            borderColor: "#fb7185",
            backgroundColor: "rgba(251,113,133,0.08)",
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 0,
          },
        ],
      },
      options: chartOptions(),
    });
  }

  if (elements.chartAttacks && !charts.attacks) {
    charts.attacks = new Chart(elements.chartAttacks, {
      type: "doughnut",
      data: {
        labels: [],
        datasets: [{ data: [], backgroundColor: ["#fb7185", "#fbbf24", "#6366f1", "#a78bfa", "#22d3ee"], borderWidth: 0 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: { legend: { position: "bottom", labels: { usePointStyle: true, pointStyleWidth: 8 } } },
      },
    });
  }

  if (elements.chartPorts && !charts.ports) {
    charts.ports = new Chart(elements.chartPorts, {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#38bdf8", borderRadius: 6 }] },
      options: barOptions(),
    });
  }

  if (elements.chartSourceIPs && !charts.sources) {
    charts.sources = new Chart(elements.chartSourceIPs, {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#22d3ee", borderRadius: 4 }] },
      options: { ...barOptions(), indexAxis: "y" },
    });
  }

  if (elements.chartProtocols && !charts.protocols) {
    charts.protocols = new Chart(elements.chartProtocols, {
      type: "pie",
      data: { labels: [], datasets: [{ data: [], backgroundColor: ["#22d3ee", "#6366f1", "#fbbf24", "#fb7185"], borderWidth: 0 }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { usePointStyle: true, pointStyleWidth: 8 } } },
      },
    });
  }
}

function renderCharts() {
  if (!window.Chart) return;
  initCharts();
  const logs = state.logs.map(enrichLog);
  const buckets = timeBuckets(logs, 12);
  updateChart(charts.traffic, buckets.labels, [buckets.safe, buckets.threat]);

  const attacks = Object.entries(countBy(logs.filter(isAlert), attackLabel)).sort((a, b) => b[1] - a[1]).slice(0, 6);
  updateChart(charts.attacks, attacks.map(([label]) => label), [attacks.map(([, count]) => count)]);

  const ports = Object.entries(countBy(logs.map((log) => log.destination_port || "Other"), (value) => String(value)))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);
  updateChart(charts.ports, ports.map(([label]) => label), [ports.map(([, count]) => count)]);

  const sources = Object.entries(countBy(logs.map((log) => log.source_ip || "-"), (value) => value))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
  updateChart(charts.sources, sources.map(([label]) => label), [sources.map(([, count]) => count)]);

  const protocols = Object.entries(countBy(logs, (log) => log.protocol || "Other")).sort((a, b) => b[1] - a[1]).slice(0, 5);
  updateChart(charts.protocols, protocols.map(([label]) => label), [protocols.map(([, count]) => count)]);
}

function updateChart(chart, labels, datasets) {
  if (!chart) return;
  chart.data.labels = labels;
  datasets.forEach((data, index) => {
    if (chart.data.datasets[index]) chart.data.datasets[index].data = data;
  });
  chart.update();
}

function timeBuckets(logs, count) {
  const buckets = [];
  const now = new Date();
  for (let index = count - 1; index >= 0; index -= 1) {
    const date = new Date(now);
    date.setMinutes(now.getMinutes() - index * 5, 0, 0);
    buckets.push({ date, safe: 0, threat: 0 });
  }

  for (const log of logs) {
    const date = new Date(log.timestamp);
    if (Number.isNaN(date.getTime())) continue;
    const bucket = buckets.reduce((closest, candidate) => (
      Math.abs(candidate.date - date) < Math.abs(closest.date - date) ? candidate : closest
    ), buckets[0]);
    if (isAlert(log)) bucket.threat += 1;
    else bucket.safe += 1;
  }

  return {
    labels: buckets.map((bucket) => bucket.date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })),
    safe: buckets.map((bucket) => bucket.safe),
    threat: buckets.map((bucket) => bucket.threat),
  };
}

function chartOptions() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: { legend: { position: "top", labels: { usePointStyle: true, pointStyleWidth: 8 } } },
    scales: {
      y: { beginAtZero: true, grid: { color: "rgba(255,255,255,0.04)" } },
      x: { grid: { display: false } },
    },
  };
}

function barOptions() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      y: { beginAtZero: true, grid: { color: "rgba(255,255,255,0.04)" } },
      x: { grid: { display: false } },
    },
  };
}

function formatSeconds(value) {
  const numericValue = Number(value);
  if (Number.isNaN(numericValue)) return value ?? "-";
  return `${numericValue.toFixed(2)}s`;
}

function emptyState(text) {
  const empty = document.createElement("p");
  empty.className = "muted empty-state";
  empty.textContent = text;
  return empty;
}

function setView(view) {
  state.view = view;
  renderView();
}

function renderView() {
  for (const tab of elements.viewTabs) {
    tab.classList.toggle("active", tab.dataset.viewTarget === state.view);
  }
  for (const section of elements.viewSections) {
    const views = section.dataset.view.split(" ");
    section.hidden = !views.includes(state.view);
  }
}

async function startCapture() {
  const payload = {
    interface: elements.interfaceInput.value.trim() || null,
    packet_filter: elements.filterInput.value.trim() || null,
  };
  await requestJson("/capture/start", { method: "POST", body: JSON.stringify(payload) });
  await refreshHealth();
}

async function loadInterfaces() {
  try {
    const result = await requestJson("/capture/interfaces");
    elements.interfaceOptions.replaceChildren(
      ...result.interfaces.map((name) => {
        const option = document.createElement("option");
        option.value = name;
        return option;
      }),
    );
  } catch (error) {
    elements.socketStatus.textContent = error.message;
  }
}

async function stopCapture() {
  await requestJson("/capture/stop", { method: "POST" });
  await refreshHealth();
}

async function blockIp(ip, reason = "Manual block from IDS dashboard") {
  await requestJson("/blocklist", {
    method: "POST",
    body: JSON.stringify({ ip, reason }),
  });
  await refreshHealth();
}

async function unblockIp(ip) {
  await requestJson(`/blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" });
  await refreshHealth();
}

async function exportLogs() {
  const result = await requestJson("/logs/export", { method: "POST" });
  elements.exportResult.textContent = `Exported to ${result.path}`;
}

async function analyzePcap() {
  const file = elements.pcapInput.files[0];
  if (!file) {
    elements.pcapResult.textContent = "Choose a PCAP file first.";
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  elements.analyzePcap.disabled = true;
  elements.pcapResult.textContent = "Analyzing capture...";

  try {
    const response = await fetch("/pcap/analyze", {
      method: "POST",
      body: formData,
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(result.detail || `Upload failed: ${response.status}`);
    }

    elements.pcapResult.textContent =
      `${result.processed_packets} packets analyzed / ${result.alert_count} alerts added`;
    await loadLogs();
    await refreshHealth();
  } finally {
    elements.analyzePcap.disabled = false;
  }
}

async function loadLogs() {
  const result = await requestJson("/logs?limit=300");
  state.logs = result.logs.reverse();
  if (result.metrics) {
    state.metrics = { ...state.metrics, ...result.metrics };
  }
  renderAll();
}

function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws/logs`);

  socket.addEventListener("open", () => {
    elements.socketStatus.textContent = "Live stream connected";
  });

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "snapshot") {
      state.logs = message.data.reverse();
      state.metrics.packets = state.logs.length;
      state.metrics.alerts = state.logs.filter(isAlert).length;
      state.metrics.encrypted = state.logs.filter((log) => log.encrypted_likely).length;
      state.metrics.blocked = state.logs.filter((log) => log.action === "blocked").length;
      renderAll();
    }
    if (message.type === "packet_log") addLog(message.data);
    if (message.type === "blocklist") refreshHealth();
  });

  socket.addEventListener("close", () => {
    elements.socketStatus.textContent = "Live stream reconnecting";
    window.setTimeout(connectWebSocket, 1500);
  });
}

elements.startCapture.addEventListener("click", () => startCapture().catch(alert));
elements.stopCapture.addEventListener("click", () => stopCapture().catch(alert));
elements.manualBlock.addEventListener("click", () => {
  const ip = elements.manualIp.value.trim();
  if (ip) blockIp(ip).catch(alert);
});
elements.exportLogs.addEventListener("click", () => exportLogs().catch(alert));
elements.analyzePcap.addEventListener("click", () => analyzePcap().catch((error) => {
  elements.pcapResult.textContent = error.message;
}));
elements.searchInput.addEventListener("input", (event) => {
  state.filters.search = event.target.value.trim().toLowerCase();
  renderLogs();
});
elements.severityFilter.addEventListener("change", (event) => {
  state.filters.severity = event.target.value;
  renderLogs();
});
elements.actionFilter.addEventListener("change", (event) => {
  state.filters.action = event.target.value;
  renderLogs();
});
for (const tab of elements.viewTabs) {
  tab.addEventListener("click", () => setView(tab.dataset.viewTarget));
}

renderRuleSummary();
initCharts();
renderAll();
loadInterfaces();
refreshHealth();
connectWebSocket();
window.setInterval(refreshHealth, 5000);
