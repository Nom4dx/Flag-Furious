import {
  renderData,
  renderTable,
  renderStructured,
  technicalView,
} from "./presentation.js?v=20260914-2";
import {
  renderGraph,
  renderVisualization,
  download,
  applyPalette,
} from "./visualizations.js";
import {
  initWorkflowWorkspace,
  openWorkflowWorkspace,
  restoreWorkflowRoute,
} from "./workflows.js";
const $ = (id) => document.getElementById(id);
const state = {
  case: null,
  assets: [],
  plugins: [],
  job: null,
  graph: { nodes: [], edges: [] },
  results: [],
  jobData: null,
  timer: null,
  signature: "",
  graphSignature: "",
  issueSignature: "",
  analysisOpened: false,
  activePlugin: "",
  activeGroup: "all",
  activeTab: "summary",
  progress: -1,
  summarySignature: "",
  flagsSignature: "",
  navigationSignature: "",
  transitionDepth: 0,
};
const text = (tag, value, cls) => {
  const n = document.createElement(tag);
  n.textContent = String(value ?? "");
  if (cls) n.className = cls;
  return n;
};
async function api(path, options = {}) {
  const response = await fetch("/api" + path, options);
  const body = await response.json();
  if (!response.ok)
    throw new Error(
      typeof body.detail === "string"
        ? body.detail
        : JSON.stringify(body.detail || body),
    );
  return body;
}
const post = (path, body) =>
  api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
function notice(message, moveFocus = false) {
  $("notice").hidden = !message;
  $("notice").textContent = message;
  if (message && moveFocus) {
    $("notice").tabIndex = -1;
    $("notice").focus({ preventScroll: false });
  }
}
async function busy(button, fn) {
  button.disabled = true;
  button.classList.add("is-busy");
  button.setAttribute("aria-busy", "true");
  try {
    await fn();
  } catch (e) {
    notice(e.message, true);
  } finally {
    button.disabled = false;
    button.classList.remove("is-busy");
    button.removeAttribute("aria-busy");
  }
}
/** Animate intentional console/page changes without affecting polling updates. */
async function transitionView(_label, fn) {
  const loader = $("view-loader");
  state.transitionDepth += 1;
  loader.hidden = false;
  loader.classList.remove("is-leaving");
  document.body.classList.add("view-changing");
  let closed = false;
  const closeLoader = () => {
    if (closed) return;
    closed = true;
    loader.classList.add("is-leaving");
    setTimeout(() => {
      loader.hidden = true;
      loader.classList.remove("is-leaving");
      document.body.classList.remove("view-changing");
    }, 40);
  };
  await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  try {
    return await fn();
  } finally {
    state.transitionDepth -= 1;
    if (!state.transitionDepth) closeLoader();
  }
}
function dialog(title, node) {
  $("dialog-title").textContent = title;
  $("dialog-content").replaceChildren(node);
  $("detail-dialog").showModal();
}
function json(value) {
  if (value?.presentation) {
    const host = document.createElement("div");
    renderMappedSections(host, value);
    host.append(technicalView({ ...value, presentation: undefined }));
    return host;
  }
  return renderStructured(value);
}
function empty(container, message) {
  container.replaceChildren(text("p", message, "empty"));
}
function table(data, fields = null) {
  return renderTable(data, fields || []);
}
function action(label, fn) {
  const b = text("button", label, "plain");
  b.type = "button";
  b.onclick = () => Promise.resolve(fn()).catch((e) => notice(e.message));
  return b;
}
function renderSection(parent, section, result) {
  const node = document.createElement("section");
  node.className = "output-section";
  node.dataset.sectionId = section.id || "";
  const palette = applyPalette(node, result.presentation?.style || result.presentation?.palette);
  node.style.setProperty("--section-accent", palette[section.tone || "primary"] || palette.primary);
  const heading = text("div", undefined, "mapped-section-heading");
  heading.append(text("h3", section.title || section.id || "Output"));
  const sectionStatus = {
    partial: "Copertura parziale",
    failed: "Sezione non disponibile",
    skipped: "Non analizzata",
    cancelled: "Interrotta",
  }[section.status];
  if (sectionStatus) {
    const status = text("span", sectionStatus, "section-status section-status-" + section.status);
    status.style.setProperty("--section-status-color", {
      partial: palette.secondary,
      failed: palette.critical,
      skipped: palette.muted,
      cancelled: palette.muted,
    }[section.status]);
    status.setAttribute("role", "status");
    heading.append(status);
  }
  if (Array.isArray(section.data))
    heading.append(
      text("span", section.data.length + " elementi", "section-count"),
    );
  node.append(heading);
  if (section.description)
    node.append(text("p", section.description, "section-description"));
  const data = section.data ?? section.content ?? [];
  switch (section.type) {
    case "table":
      node.append(table(data, section.fields || section.columns));
      break;
    case "timeline":
      renderVisualization(node, {
        type: "timeline",
        title: section.title,
        data: Array.isArray(data) ? data : [],
        palette: result.presentation?.palette,
        style: result.presentation?.style,
      });
      node.append(table(data));
      break;
    case "terminal":
    case "text":
    case "commands":
    case "logs":
      node.append(
        renderData(data, {
          type:
            section.type === "terminal" && typeof data === "string"
              ? "terminal"
              : "auto",
          fields: section.fields || [],
        }),
      );
      break;
    case "visualization":
      renderVisualization(node, {
        ...data,
        palette: data?.palette || result.presentation?.palette,
        style: data?.style || result.presentation?.style,
      });
      break;
    case "visualization_list":
      for (const chart of Array.isArray(data)
        ? data
        : result.visualizations || [])
        renderVisualization(node, {
          ...chart,
          palette: chart?.palette || result.presentation?.palette,
          style: chart?.style || result.presentation?.style,
        });
      break;
    case "artifact_list":
      for (const a of Array.isArray(data) ? data : result.artifacts || [])
        node.append(artifactRow(a));
      break;
    default:
      node.append(
        renderData(data, {
          type: section.type === "json" ? "auto" : section.type,
          fields: section.fields || section.columns || [],
        }),
      );
  }
  for (const descriptor of section.actions || []) {
    if (descriptor.type !== "plugin_endpoint") continue;
    node.append(
      action(descriptor.label || "Apri azione", async () => {
        const plugin = await api(
          "/plugins/" + encodeURIComponent(result.plugin_id),
        );
        const endpoint = plugin.manifest.endpoints.find(
          (e) =>
            e.path === descriptor.path &&
            (e.method || "GET").toUpperCase() ===
              (descriptor.method || "GET").toUpperCase(),
        );
        if (!endpoint) throw new Error("Endpoint non dichiarato nel manifest");
        const path =
          "/plugins/" + encodeURIComponent(result.plugin_id) + endpoint.path;
        const value =
          (endpoint.method || "GET").toUpperCase() === "GET"
            ? await api(path)
            : await post(path, {
                ...descriptor.payload,
                asset_id: result.asset_id,
              });
        dialog(descriptor.label || "Risultato azione", json(value));
      }),
    );
  }
  if (section.collapsed) {
    const disclosure = document.createElement("details");
    disclosure.className = "mapped-disclosure";
    disclosure.append(text("summary", section.title), node);
    parent.append(disclosure);
  } else parent.append(node);
}
function renderMappedSections(host, result) {
  const sections = result.presentation?.sections || result.sections || [];
  const groups = result.presentation?.groups || [
    { id: "overview", title: "Panoramica" },
  ];
  const active = groups.filter((group) =>
    sections.some((s) => (s.group || "overview") === group.id),
  );
  const navigation = text("nav", undefined, "output-groups");
  navigation.setAttribute("aria-label", "Sezioni del plugin");
  const panels = [];
  const select = (id) => {
    for (const panel of panels)
      panel.hidden = id !== "all" && panel.dataset.group !== id;
    for (const button of navigation.querySelectorAll("button"))
      button.setAttribute("aria-pressed", String(button.dataset.group === id));
  };
  for (const group of [{ id: "all", title: "Tutte le sezioni" }, ...active]) {
    const b = action(group.title, () => select(group.id));
    b.dataset.group = group.id;
    b.setAttribute("aria-pressed", String(group.id === "all"));
    navigation.append(b);
  }
  if (active.length > 1) host.append(navigation);
  for (const [index, group] of active.entries()) {
    const panel = text("div", undefined, "mapped-group");
    panel.dataset.group = group.id;
    const heading = text("div", undefined, "mapped-group-heading");
    heading.append(
      text("span", String(index + 1).padStart(2, "0"), "mono"),
      text("h3", group.title),
    );
    panel.append(heading);
    if (group.description)
      panel.append(text("p", group.description, "section-description"));
    for (const section of sections.filter(
      (s) => (s.group || "overview") === group.id,
    ))
      renderSection(panel, section, result);
    panels.push(panel);
    host.append(panel);
  }
}
const utilityPattern = /additional|diagnostic|log|error|warning|metric|execution|utilit/i;
const emptyValue = (value) =>
  value === null ||
  value === undefined ||
  value === "" ||
  (Array.isArray(value) && value.length === 0) ||
  (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0);
const sectionsOf = (result) => result.presentation?.sections || result.sections || [];
const groupsOf = (result) => result.presentation?.groups || [];
const isUtilityGroup = (group) => utilityPattern.test(`${group.id} ${group.title || ""}`);
const evidenceSections = (result) =>
  sectionsOf(result).filter(
    (section) =>
      !emptyValue(section.data ?? section.content) &&
      !isUtilityGroup({ id: section.group || "", title: section.title || "" }) &&
      !/^(file|input|result-metrics)$/i.test(section.id || ""),
  );
const resultHasEvidence = (result) =>
  ["findings", "flags", "artifacts", "derived_assets", "timeline", "visualizations"].some(
    (key) => result[key]?.length,
  ) || evidenceSections(result).length > 0;
const pluginHasEvidence = (results) => results.some(resultHasEvidence);
const assetName = (id) => state.assets.find((asset) => asset.id === id)?.name || id || "Asset";
const confidencePercent = (value) => {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  return Math.round(Math.max(0, Math.min(100, numeric <= 1 ? numeric * 100 : numeric)));
};
const findingSeverityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
function compareFindings(a, b) {
  return (findingSeverityOrder[String(b.severity || "").toLowerCase()] || 0) -
      (findingSeverityOrder[String(a.severity || "").toLowerCase()] || 0) ||
    (confidencePercent(b.confidence) ?? -1) - (confidencePercent(a.confidence) ?? -1);
}

function pluginStatus(results) {
  const rank = { failed: 7, partial: 6, running: 5, queued: 4, cancelled: 3, completed: 2, skipped: 1 };
  return results.map((result) => result.status).filter(Boolean).sort(
    (a, b) => (rank[b] || 0) - (rank[a] || 0),
  )[0] || "queued";
}

function groupCatalog(results) {
  const groups = new Map();
  for (const result of results)
    for (const group of groupsOf(result))
      if (sectionsOf(result).some((section) => (section.group || "overview") === group.id))
        groups.set(group.id, group);
  return [...groups.values()].sort((a, b) => {
    const utility = Number(isUtilityGroup(a)) - Number(isUtilityGroup(b));
    return utility || (a.order || 0) - (b.order || 0);
  });
}

function aggregateCounts(results) {
  return results.reduce(
    (total, result) => {
      for (const key of ["findings", "artifacts", "flags", "warnings", "errors"])
        total[key] += result[key]?.length || 0;
      return total;
    },
    { findings: 0, artifacts: 0, flags: 0, warnings: 0, errors: 0 },
  );
}

function dashboardHeader(host, pluginId, results, hasEvidence) {
  const counts = aggregateCounts(results);
  const status = pluginStatus(results);
  const header = text("header", undefined, "plugin-dashboard-header");
  const title = text("div");
  title.append(text("span", "DASHBOARD PLUGIN", "mono"), text("h2", pluginId));
  header.append(title, text("span", status, "dashboard-status"));
  host.append(header);
  if (!hasEvidence) {
    const none = text("section", undefined, "dashboard-empty");
    none.append(
      text("strong", "Nessun riscontro"),
      text("p", status === "failed"
        ? "Il plugin non ha prodotto dati utili e ha segnalato un errore. Il dettaglio tecnico è disponibile in Problemi e Log."
        : status === "partial"
          ? "Il plugin ha completato soltanto una parte dell’analisi e non ha prodotto dati utili. Il dettaglio è disponibile in Problemi e Log."
          : status === "cancelled"
            ? "L’analisi è stata interrotta. I risultati raccolti prima dell’annullamento restano consultabili."
            : "Il plugin ha completato l’analisi senza produrre finding, flag, artefatti o dati utili per questo caso."),
    );
    host.append(none);
    return counts;
  }
  const metrics = text("dl", undefined, "dashboard-metrics");
  for (const [label, value] of [
    ["Finding", counts.findings],
    ["Flag", counts.flags],
    ["Artefatti", counts.artifacts],
    ["Asset con riscontri", results.filter(resultHasEvidence).length],
  ]) {
    const metric = text("div");
    metric.append(text("dt", label), text("dd", value));
    metrics.append(metric);
  }
  host.append(metrics);
  return counts;
}

function compactFinding(item, pluginId) {
  const row = text("div", undefined, "dashboard-finding");
  const severity = String(item.severity || "").toLowerCase();
  if (severity) row.dataset.severity = severity;
  const confidence = confidencePercent(item.confidence);
  const sourceId = item.source_asset_id || item.asset_id || item.artifact_id || item.parent_asset_id;
  const source = sourceId ? assetName(sourceId) : item.source || item.artifact || item.path;
  const showOffset = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? `0x${value.toString(16)}`
    : String(value);
  const offset = item.offset ?? item.byte_offset ?? item.absolute_offset;
  const scope = {
    input: "offset input",
    artifact: "offset artefatto",
    decoded_payload: "offset payload decodificato",
    disk: "offset disco",
    absolute: "offset assoluto",
  }[item.offset_scope] || "offset";
  const locations = [];
  if (item.decoded_offset !== undefined && item.decoded_offset !== null)
    locations.push(`offset payload decodificato ${showOffset(item.decoded_offset)}`);
  else if (offset !== undefined && offset !== null)
    locations.push(`${scope} ${showOffset(offset)}`);
  if (item.source_offset !== undefined && item.source_offset !== null)
    locations.push(`${item.source_offset_scope === "encoded_candidate" ? "candidato codificato" : "offset sorgente"} ${showOffset(item.source_offset)}`);
  const location = locations.length ? ` · ${locations.join(" · ")}` :
    item.line !== undefined && item.line !== null ? ` · riga ${item.line}` : "";
  if (severity) row.append(text("span", severity, `finding-severity severity-${severity}`));
  row.append(
    text("strong", item.title || item.type || "Riscontro"),
    text("p", item.description || item.value || item.summary || ""),
    text("small", `${pluginId}${confidence != null ? ` · affidabilità ${confidence}%` : ""}${source ? ` · origine ${source}` : ""}${location}`),
  );
  return row;
}

function renderPluginOverview(host, pluginId, results) {
  const findings = results.flatMap((result) => result.findings || []).sort(compareFindings);
  const flags = results.flatMap((result) => result.flags || []).sort((a, b) =>
    (confidencePercent(b.confidence) ?? -1) - (confidencePercent(a.confidence) ?? -1));
  const artifacts = results.flatMap((result) => result.artifacts || []);
  const section = text("section", undefined, "dashboard-block");
  section.append(text("h3", "Riscontri principali"));
  if (!findings.length && !flags.length && !artifacts.length)
    section.append(text("p", "Le informazioni rilevate sono disponibili nelle sezioni del plugin.", "dashboard-note"));
  for (const finding of findings.slice(0, 20)) section.append(compactFinding(finding, pluginId));
  for (const flag of flags.slice(0, 10)) section.append(compactFinding({ title: flag.value, description: flag.method, confidence: flag.confidence }, pluginId));
  for (const artifact of artifacts.slice(0, 10)) section.append(artifactRow(artifact));
  host.append(section);
  const available = groupCatalog(results).filter((group) => !isUtilityGroup(group));
  if (available.length) {
    const navigation = text("section", undefined, "dashboard-block");
    navigation.append(text("h3", "Sezioni disponibili"));
    const list = text("div", undefined, "dashboard-section-index");
    for (const group of available) {
      const button = action(group.title || group.id, () => selectPluginOutput(pluginId, group.id));
      button.append(text("span", "→"));
      list.append(button);
    }
    navigation.append(list);
    host.append(navigation);
  }
}

function fillAssetResult(details, result, groupId) {
  if (details.dataset.loaded) return;
  details.dataset.loaded = "true";
  const body = text("div", undefined, "asset-result-body");
  const sections = sectionsOf(result).filter((section) =>
    groupId === "utilities"
      ? isUtilityGroup({ id: section.group || "", title: section.title || "" })
      : (section.group || "overview") === groupId,
  );
  for (const section of sections) renderSection(body, section, result);
  if (groupId === "utilities") {
    if (result.warnings?.length)
      body.append(text("pre", result.warnings.join("\n"), "json-output"));
    if (result.errors?.length)
      body.append(text("pre", result.errors.join("\n"), "terminal"));
    body.append(technicalView({ ...result, presentation: undefined }, "Dati tecnici · JSON originale"));
  }
  if (!body.childElementCount) body.append(text("p", "Nessun dato in questa sezione.", "data-empty"));
  details.append(body);
}

function renderPluginGroup(host, pluginId, results, groupId) {
  const catalog = groupCatalog(results);
  const group = groupId === "utilities"
    ? { id: "utilities", title: "Diagnostica e utility senza riscontri" }
    : catalog.find((item) => item.id === groupId);
  const block = text("section", undefined, "dashboard-block dashboard-results");
  block.append(
    text("h3", group?.title || groupId),
    text(
      "p",
      groupId === "utilities"
        ? "Informazioni tecniche, warning, errori e strumenti che non hanno prodotto riscontri sono raccolti alla fine della dashboard."
        : "Risultati organizzati per asset. Apri un asset per consultare i dati prodotti dal plugin.",
      "dashboard-note",
    ),
  );
  const relevant = results.filter((result) =>
    groupId === "utilities"
      ? sectionsOf(result).some((section) => isUtilityGroup({ id: section.group || "", title: section.title || "" })) || result.warnings?.length || result.errors?.length
      : sectionsOf(result).some((section) => (section.group || "overview") === groupId),
  );
  for (const [index, result] of relevant.entries()) {
    const details = document.createElement("details");
    details.className = "asset-result";
    details.dataset.assetId = result.asset_id || "";
    const summary = text("summary");
    const identity = text("span");
    identity.append(text("strong", assetName(result.asset_id)), text("small", result.summary || ""));
    summary.append(identity, text("span", result.status, "asset-result-status"));
    details.append(summary);
    details.addEventListener("toggle", () => details.open && fillAssetResult(details, result, groupId));
    if (index === 0) {
      details.open = true;
      fillAssetResult(details, result, groupId);
    }
    block.append(details);
  }
  if (!relevant.length) block.append(text("p", "Nessun dato disponibile per questa sezione.", "data-empty"));
  host.append(block);
}

function renderOutputs(results = state.results) {
  state.results = results;
  const host = $("outputs");
  const scrollTop = host.scrollTop;
  host.replaceChildren();
  if (!results.length) {
    empty(host, "I risultati compariranno durante l’esecuzione.");
    host.scrollTop = scrollTop;
    return;
  }
  if (!state.activePlugin) {
    const intro = text("section", undefined, "dashboard-block");
    intro.append(text("h2", "Dashboard dei plugin"), text("p", "Seleziona un plugin dalla barra laterale per aprire risultati e sezioni."));
    host.append(intro);
    for (const pluginId of [...new Set(results.map((result) => result.plugin_id))].filter((id) => id !== "magic-wrapper")) {
      const pluginResults = results.filter((result) => result.plugin_id === pluginId);
      const button = action(pluginId, () => selectPluginOutput(pluginId));
      button.className = "plugin-dashboard-link";
      button.append(text("span", pluginHasEvidence(pluginResults) ? pluginStatus(pluginResults) : "nessun riscontro"));
      host.append(button);
    }
    host.scrollTop = scrollTop;
    return;
  }
  const pluginResults = results.filter((result) => result.plugin_id === state.activePlugin);
  const pluginPresentation = pluginResults.find((result) => result.presentation)?.presentation;
  if (pluginPresentation) {
    applyPalette(host, pluginPresentation.style || pluginPresentation.palette);
    host.dataset.palette = pluginPresentation.palette || "forensic";
  }
  const hasEvidence = pluginHasEvidence(pluginResults);
  dashboardHeader(host, state.activePlugin, pluginResults, hasEvidence);
  if (!hasEvidence) {
    host.scrollTop = scrollTop;
    return;
  }
  if (state.activeGroup === "all") renderPluginOverview(host, state.activePlugin, pluginResults);
  else renderPluginGroup(host, state.activePlugin, pluginResults, state.activeGroup);
  applyOutputSelection();
  host.scrollTop = scrollTop;
}

/** Keep plugin navigation and the active dashboard synchronized. */
function applyOutputSelection() {
  const pluginId = state.activePlugin;
  for (const button of $("plugin-run-list").querySelectorAll("button[data-plugin-id]")) {
    const active =
      button.dataset.pluginId === pluginId &&
      (button.dataset.group || "all") === state.activeGroup;
    button.classList.toggle("active", active);
    if (button.tagName === "BUTTON")
      button.setAttribute("aria-current", active ? "true" : "false");
  }
}

const tabTitles = {
  summary: "Riepilogo dell’analisi",
  graph: "Grafo esecuzione",
  outputs: "Tutti i risultati",
  flags: "Flag candidate",
  artifacts: "Artefatti",
  issues: "Problemi e diagnostica",
  logs: "Log & errori",
};

/** Switch only the result panel; plugin and log containers keep their DOM and scroll. */
function updateAnalysisRoute() {
  if (!state.analysisOpened || !state.case || !state.job) return;
  const params = new URLSearchParams();
  if (state.activeTab !== "summary") params.set("view", state.activeTab);
  if (state.activePlugin) params.set("plugin", state.activePlugin);
  if (state.activeGroup !== "all") params.set("section", state.activeGroup);
  const query = params.toString();
  history.replaceState(
    { caseId: state.case.id, jobId: state.job },
    "",
    `/cases/${state.case.id}/analysis/${state.job}${query ? `?${query}` : ""}`,
  );
}
function activateTab(name, resetPlugin = false, updateRoute = true) {
  state.activeTab = name;
  if (name === "outputs" && resetPlugin) {
    state.activePlugin = "";
    state.activeGroup = "all";
    renderOutputs();
  }
  for (const button of document.querySelectorAll(".result-navigation [data-tab]")) {
    const active = button.dataset.tab === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  }
  for (const list of document.querySelectorAll(".result-navigation[role=tablist]"))
    if (!list.querySelector('[aria-selected="true"]')) list.querySelector("[role=tab]").tabIndex = 0;
  for (const panel of document.querySelectorAll(".analysis-content > .tab-panel"))
    panel.hidden = panel.id !== `tab-${name}`;
  if (name === "graph") drawGraph();
  if (name === "artifacts") renderArtifacts(state.results);
  if (name === "issues" && state.jobData) renderIssues(state.jobData, state.results);
  if (name === "flags" && state.jobData) renderFlags(state.jobData.flags || []);
  if (name === "summary" && state.jobData) renderSummary(state.jobData, state.results, state.graph);
  const pluginContext = name === "outputs" && state.activePlugin;
  $("analysis-view-kicker").textContent = pluginContext
    ? "RISULTATI PLUGIN"
    : "ANALISI";
  $("analysis-view-title").textContent = pluginContext
    ? `${state.activePlugin} / ${state.activeGroup === "all" ? "Panoramica" : state.activeGroup === "utilities" ? "Diagnostica e utility" : groupCatalog(state.results.filter((result) => result.plugin_id === state.activePlugin)).find((group) => group.id === state.activeGroup)?.title || state.activeGroup}`
    : tabTitles[name] || "Analisi";
  if (updateRoute) updateAnalysisRoute();
  if (matchMedia("(max-width: 760px)").matches) {
    document.querySelector(".analysis-sidebar").classList.remove("menu-open");
    $("analysis-menu-toggle").setAttribute("aria-expanded", "false");
  }
}

function selectPluginOutput(pluginId, groupId = "all") {
  state.activePlugin = pluginId;
  state.activeGroup = groupId;
  activateTab("outputs");
  renderOutputs();
  $("outputs").scrollTop = 0;
}
function artifactRow(a) {
  const row = document.createElement("div");
  row.className = "artifact-row";
  const label = text("div", a.name);
  const sourceId = a.source_asset_id || a.parent_asset_id || a.asset_id;
  const source = sourceId ? assetName(sourceId) : a.source || a.original_path;
  const sourceDetail = sourceId ? a.source || a.source_location : null;
  const offset = a.source_offset ?? a.offset ?? a.byte_offset;
  const facts = [`${a.size ?? 0} byte`, a.status, a.plugin_id, a.method];
  if (source) facts.push(`origine ${source}`);
  if (sourceDetail && sourceDetail !== source) facts.push(`contesto ${String(sourceDetail).slice(0, 240)}`);
  if (offset !== undefined && offset !== null) facts.push(`offset ${offset}`);
  if (a.sha256) facts.push(`SHA-256 ${String(a.sha256).slice(0, 16)}…`);
  label.append(text("small", facts.filter(Boolean).join(" · ")));
  row.append(label);
  if (a.id) {
    row.append(
      action("Anteprima", async () => {
        const p = await api(`/artifacts/${a.id}/preview`);
        const content = document.createElement("div");
        content.append(
          text(
            "p",
            p.partial
              ? "Anteprima parziale (64 KiB)."
              : "Anteprima testuale / esadecimale.",
            "hint",
          ),
          text("pre", p.text, "json-output"),
          text("pre", p.hex, "json-output"),
        );
        dialog(p.name, content);
      }),
    );
    const aLink = text("a", "Scarica ↓");
    aLink.href = `/api/artifacts/${a.id}/download`;
    row.append(aLink);
  }
  return row;
}
function renderArtifacts(results) {
  $("artifacts").replaceChildren();
  const all = results.flatMap((r) => r.artifacts || []);
  if (!all.length) return empty($("artifacts"), "Nessun artefatto prodotto.");
  all.forEach((a) => $("artifacts").append(artifactRow(a)));
}
function issueItems(job, results) {
  const items = [
    ...results.flatMap((result) => [
      ...(result.warnings || []).map((message) => ({ source: result.plugin_id, level: "warning", message })),
      ...(result.errors || []).map((message) => ({ source: result.plugin_id, level: "error", message })),
    ]),
    ...(job?.warnings || []).map((message) => ({ source: "Hub", level: "warning", message })),
  ];
  const unique = new Map();
  for (const item of items) {
    const message = typeof item.message === "string" ? item.message : JSON.stringify(item.message);
    const key = `${item.level}:${message}`;
    if (!unique.has(key)) unique.set(key, { ...item, message });
  }
  return [...unique.values()];
}
function renderIssues(job, results) {
  const host = $("issues");
  const issues = issueItems(job, results);
  $("issue-count").textContent = issues.length;
  host.replaceChildren();
  if (!issues.length) return empty(host, "Nessun errore o warning registrato.");
  for (const issue of issues) {
    const row = text("article", undefined, "issue-row");
    row.append(
      text("span", issue.level, "issue-level mono"),
      text("strong", issue.source),
      text("p", typeof issue.message === "string" ? issue.message : JSON.stringify(issue.message)),
    );
    host.append(row);
  }
}
function renderSummary(job, results, graph) {
  const host = $("analysis-summary");
  host.replaceChildren();
  const flags = [...(job.flags || [])].sort((a, b) =>
    (confidencePercent(b.confidence) ?? -1) - (confidencePercent(a.confidence) ?? -1),
  );
  const issues = issueItems(job, results);
  const findings = results.flatMap((result) =>
    (result.findings || []).map((finding) => ({ ...finding, plugin_id: result.plugin_id })),
  ).sort(compareFindings);
  const pluginIds = [...new Set(results.map((result) => result.plugin_id))].filter((id) => id !== "magic-wrapper");
  const assets = new Set(graph.nodes.filter((node) => node.type === "asset").map((node) => node.asset_id || node.id));
  const status = job.status || "queued";
  const lead = text("section", undefined, `summary-lead status-${status}`);
  lead.append(
    text("span", status, "summary-status mono"),
    text("h2", status === "partial" ? "Analisi completata con risultati parziali" : status === "completed" ? "Analisi completata" : status === "failed" ? "Analisi non completata" : status === "cancelled" ? "Analisi annullata" : "Analisi in corso"),
    text("p", status === "partial"
      ? `${issues.length || "Alcuni"} avvisi o errori hanno limitato una parte dell’analisi. I risultati prodotti restano consultabili.`
      : status === "completed"
        ? "Tutti i moduli previsti hanno terminato. Consulta prima flag e finding, poi gli strumenti diagnostici."
        : status === "cancelled"
          ? "L’esecuzione è stata interrotta su richiesta. I risultati già raccolti e la loro provenienza restano consultabili."
        : "I risultati vengono aggiornati senza spostare la posizione di lettura."),
  );
  const metrics = text("dl", undefined, "summary-metrics");
  for (const [label, value] of [["Flag", flags.length], ["Finding", findings.length], ["Plugin", pluginIds.length], ["Asset", assets.size]]) {
    const metric = text("div"); metric.append(text("dt", label), text("dd", value)); metrics.append(metric);
  }
  lead.append(metrics); host.append(lead);
  const evidence = text("section", undefined, "summary-section");
  evidence.append(text("h3", "Evidenze prioritarie"));
  if (!flags.length && !findings.length) evidence.append(text("p", "Nessuna flag o finding prioritario rilevato.", "dashboard-note"));
  for (const flag of flags.slice(0, 5)) evidence.append(flagCard(flag));
  for (const finding of findings.slice(0, 10)) evidence.append(compactFinding(finding, finding.plugin_id));
  host.append(evidence);
  const plugins = text("section", undefined, "summary-section");
  plugins.append(text("h3", "Dashboard plugin"));
  for (const pluginId of pluginIds) {
    const pluginResults = results.filter((result) => result.plugin_id === pluginId);
    const button = action(pluginId, () => selectPluginOutput(pluginId));
    button.className = "summary-plugin-row";
    button.append(text("span", pluginHasEvidence(pluginResults) ? pluginStatus(pluginResults) : "nessun riscontro"));
    plugins.append(button);
  }
  host.append(plugins);
  if (issues.length) {
    const diagnostics = text("section", undefined, "summary-section summary-diagnostics");
    diagnostics.append(text("h3", "Diagnostica e utility senza successo"));
    for (const issue of issues.slice(0, 8))
      diagnostics.append(compactFinding({
        title: issue.source,
        description: typeof issue.message === "string" ? issue.message : JSON.stringify(issue.message),
      }, issue.level));
    diagnostics.append(action("Apri tutti i problemi →", () => activateTab("issues")));
    host.append(diagnostics);
  }
}
function flagCard(flag) {
  const item = document.createElement("article");
  item.className = "flag-item";
  item.dataset.pluginId = flag.plugin_id || "";
  const content = text("div");
  const confidence = confidencePercent(flag.confidence);
  content.append(
    text("span", flag.category || flag.classification || "candidate", "flag-classification mono"),
    text("strong", flag.value, "flag-value"),
    text("small", `${flag.plugin_id || "Flag detector"} · ${flag.method || flag.decoder || "raw"} · offset ${flag.offset ?? "trasformato"}`),
    text("small", `Origine: ${assetName(flag.asset_id) || flag.source || "dato derivato"}${confidence != null ? ` · affidabilità ${confidence}%` : ""}`),
  );
  const actions = text("div", undefined, "flag-actions");
  actions.append(
    action("Copia", async () => {
      await navigator.clipboard.writeText(flag.value);
      notice("Flag copiata negli appunti.");
    }),
    action("Apri origine", () => {
      if (flag.plugin_id) return selectPluginOutput(flag.plugin_id);
      activateTab("graph");
      const node = state.graph.nodes.find((candidate) => candidate.id === flag.node_id || candidate.asset_id === flag.asset_id);
      if (node) nodeDetails(node);
    }),
  );
  item.append(text("span", "◇", "flag-symbol"), content, actions);
  return item;
}
function renderFlags(flags) {
  $("flag-count").textContent = flags.length;
  $("flags").replaceChildren();
  if (!flags.length)
    return empty(
      $("flags"),
      "Nessuna flag candidata nella porzione analizzata.",
    );
  flags.forEach((flag) => $("flags").append(flagCard(flag)));
}
function nodeDetails(node) {
  const target = $("node-details");
  target.hidden = false;
  target.replaceChildren(text("h3", node.label));
  const actions = document.createElement("div");
  actions.className = "node-actions";
  if (node.plugin_id)
    actions.append(
      action("Focus plugin", () => {
        $("graph-plugin").value = node.plugin_id;
        drawGraph();
      }),
    );
  if (node.asset_id)
    actions.append(
      action("Apri asset", async () =>
        dialog("Asset", json(await api("/assets/" + node.asset_id))),
      ),
    );
  if (node.artifact_id)
    actions.append(
      action("Apri artefatto", async () => {
        const data = await api("/artifacts/" + node.artifact_id);
        dialog(data.name, artifactRow(data));
      }),
    );
  if (node.type === "report")
    actions.append(
      action("Scarica report", () =>
        window.location.assign(`/api/reports/${state.case.id}?format=html`),
      ),
    );
  target.append(actions);
  if (node.visualization) renderVisualization(target, node.visualization);
  target.append(json(node.result || node.partial_result || node));
}
function compactGraph(graph, pluginFilter = "") {
  const original = graph.nodes || [];
  const nodes = [];
  const edges = [];
  const add = (id, label, type, values = {}) => {
    const node = { id, label, type, status: "completed", ...values };
    nodes.push(node);
    return node;
  };
  const connect = (source, target, label) =>
    edges.push({ source: source.id, target: target.id, type: "execution", label });
  const assets = add("compact-assets", "Asset acquisiti", "asset", {
    result: { summary: "Asset originali e derivati raggruppati", total: original.filter((node) => node.type === "asset").length },
  });
  const identification = add("compact-identification", "Identificazione", "identification");
  connect(assets, identification, "identifica");
  const pluginIds = [...new Set(original.filter((node) => node.type === "plugin").map((node) => node.plugin_id).filter(Boolean))]
    .filter((id) => !pluginFilter || id === pluginFilter);
  const pluginNodes = [];
  for (const pluginId of pluginIds) {
    const source = original.filter((node) => node.type === "plugin" && node.plugin_id === pluginId);
    const node = add(`compact-plugin-${pluginId}`, pluginId, "plugin", {
      plugin_id: pluginId,
      status: pluginStatus(source),
      result: { summary: "Fasi e asset raggruppati. Attiva Dettaglio completo per il percorso integrale." },
    });
    connect(identification, node, "analizza");
    pluginNodes.push(node);
  }
  const outputTypes = [
    ["artifact", "Artefatti"],
    ["visualization", "Visualizzazioni"],
    ["flag", "Flag"],
  ];
  let last = pluginNodes;
  for (const [type, label] of outputTypes) {
    const matching = original.filter((node) => node.type === type && (!pluginFilter || !node.plugin_id || node.plugin_id === pluginFilter));
    if (!matching.length) continue;
    const status = pluginStatus(matching);
    const grouped = add(`compact-${type}`, label, type, { status, result: { total: matching.length, summary: `${matching.length} elementi raggruppati` } });
    for (const source of last) connect(source, grouped, "produce");
    last = [grouped];
  }
  const reports = original.filter((node) => node.type === "report");
  if (reports.length) {
    const report = add("compact-report", "Report finale", "report", { status: pluginStatus(reports) });
    for (const source of last.length ? last : pluginNodes) connect(source, report, "riepiloga");
  }
  return { nodes, edges };
}
function drawGraph() {
  const detailed = $("graph-phases").checked;
  const plugin = $("graph-plugin").value;
  const presentation = state.results.find((result) => result.plugin_id === plugin)?.presentation;
  renderGraph($("graph"), detailed ? state.graph : compactGraph(state.graph, plugin), {
    plugin: detailed ? plugin : "",
    status: $("graph-status").value,
    phases: detailed,
    palette: presentation?.palette || "forensic",
    style: presentation?.style,
    onSelect: nodeDetails,
  });
}
function updateProgress(value, status) {
  const progress = Math.max(0, Math.min(100, Number(value) || 0));
  const line = document.querySelector(".progress-line");
  line.dataset.state = status || "queued";
  if (progress !== state.progress) {
    state.progress = progress;
    requestAnimationFrame(() => {
      $("job-progress").style.width = `${progress}%`;
      $("analysis-progress-label").textContent = `${Math.round(progress)}%`;
      line.setAttribute("aria-valuenow", String(Math.round(progress)));
      line.setAttribute("aria-valuetext", `${Math.round(progress)}%, stato ${status || "queued"}`);
    });
  }
  if ($("job-status").textContent !== status) $("job-status").textContent = status;
}
function updateProgressContext(job) {
  const processed = Number(job?.processed_assets || 0);
  const phase = job?.current_phase || (job?.status === "running" ? "Pipeline ricorsiva" : "Analisi");
  const plugin = job?.current_plugin ? ` · ${job.current_plugin}` : "";
  const assets = processed ? ` · ${processed} asset esaminati` : "";
  $("analysis-progress-context").textContent = `${phase}${plugin}${assets}`;
}
async function poll() {
  if (!state.job) return;
  const jobId = state.job;
  try {
    const [job, results, graph, logs] = await Promise.all([
      api(`/jobs/${jobId}`),
      api(`/jobs/${jobId}/results`),
      api(`/jobs/${jobId}/graph`),
      api(`/jobs/${jobId}/logs`),
    ]);
    if (state.job !== jobId) return;
    updateProgress(job.progress, job.status);
    updateProgressContext(job);
    $("cancel-job").hidden = !["running", "queued"].includes(job.status);
    state.jobData = job;
    state.results = results;
    state.graph = graph;
    const sig = JSON.stringify(results);
    if (sig !== state.signature) {
      state.signature = sig;
      if (state.activeTab === "outputs") renderOutputs(results);
      if (state.activeTab === "artifacts") renderArtifacts(results);
    }
    const graphSignature = JSON.stringify(graph);
    if (graphSignature !== state.graphSignature) {
      state.graphSignature = graphSignature;
      const prev = $("graph-plugin").value;
      $("graph-plugin").replaceChildren(new Option("Tutti", ""));
      for (const p of [
        ...new Set(graph.nodes.map((n) => n.plugin_id).filter(Boolean)),
      ])
        $("graph-plugin").add(new Option(p, p));
      $("graph-plugin").value = prev;
      if (state.activeTab === "graph") drawGraph();
    }
    const issueSignature = JSON.stringify([job.warnings, results.map((result) => [result.plugin_id, result.warnings, result.errors])]);
    if (issueSignature !== state.issueSignature) {
      state.issueSignature = issueSignature;
      renderIssues(job, results);
    }
    const navigationSignature = JSON.stringify([
      graph.nodes.filter((node) => node.type === "plugin").map((node) => [node.plugin_id, node.status]),
      results.map((result) => [result.plugin_id, result.status, aggregateCounts([result])]),
    ]);
    if (navigationSignature !== state.navigationSignature) {
      state.navigationSignature = navigationSignature;
      renderPluginRuns(graph, results);
    }
    const flagsSignature = JSON.stringify(job.flags || []);
    if (flagsSignature !== state.flagsSignature) {
      state.flagsSignature = flagsSignature;
      renderFlags(job.flags || []);
    }
    const summarySignature = JSON.stringify([
      job.status,
      job.warnings,
      flagsSignature,
      results.map((result) => [result.plugin_id, result.status, result.findings, result.errors]),
      graph.nodes.filter((node) => node.type === "asset").map((node) => node.id),
    ]);
    if (summarySignature !== state.summarySignature) {
      state.summarySignature = summarySignature;
      renderSummary(job, results, graph);
    }
    const logPanel = $("logs");
    const nearBottom =
      logPanel.scrollHeight - logPanel.scrollTop - logPanel.clientHeight < 48;
    const logText =
      [
        ...logs.map(
          (l) =>
            `${l.timestamp || ""} [${l.level || "info"}] ${l.message || JSON.stringify(l)}${l.command ? "\n$ " + (Array.isArray(l.command) ? l.command.join(" ") : l.command) : ""}`,
        ),
        ...(job.warnings || []).map((w) => "[warning] " + w),
        ...results.flatMap((r) =>
          (r.errors || []).map((e) => `[${r.plugin_id}] ${e}`),
        ),
      ].join("\n") || "Nessun messaggio di log.";
    if (logPanel.textContent !== logText) logPanel.textContent = logText;
    if ($("follow-logs").checked && nearBottom && logPanel.textContent === logText)
      logPanel.scrollTop = logPanel.scrollHeight;
    $("pause-job").hidden = !["running", "paused"].includes(job.status);
    $("pause-job").textContent = job.status === "paused" ? "▶ Riprendi" : "Ⅱ Pausa";
    if (["queued", "running", "paused"].includes(job.status))
      state.timer = setTimeout(poll, 1200);
    else {
      state.timer = null;
      $("run").disabled = false;
    }
  } catch (e) {
    notice(e.message);
    $("run").disabled = false;
  }
}
function setAnalysisView(active, updateRoute = true) {
  const existingCase = Boolean(state.case?.jobs?.length);
  document.body.classList.toggle("analysis-page", active);
  $("results-section").hidden = !active;
  $("workflow-section").hidden = true;
  document.querySelector(".intake").hidden = active || existingCase;
  $("case-console").hidden = active || !state.case;
  $("asset-section").hidden = active || existingCase || !state.assets.length;
  if (active) {
    $("breadcrumb-case").textContent = state.case?.name || "Caso";
    $("analysis-job-id").textContent =
      state.job?.slice(0, 12).toUpperCase() || "—";
    if (!state.analysisOpened) {
      state.analysisOpened = true;
      window.scrollTo(0, 0);
      $("outputs").scrollTop = 0;
    }
    if (updateRoute && state.case && state.job)
      history.pushState(
        { caseId: state.case.id, jobId: state.job },
        "",
        `/cases/${state.case.id}/analysis/${state.job}`,
      );
  } else {
    state.analysisOpened = false;
    if (updateRoute) history.pushState({}, "", "/");
    window.scrollTo(0, 0);
  }
}
function showJob(id, updateRoute = true) {
  clearTimeout(state.timer);
  state.job = id;
  state.signature = "";
  state.graphSignature = "";
  state.issueSignature = "";
  state.summarySignature = "";
  state.flagsSignature = "";
  state.navigationSignature = "";
  state.progress = -1;
  state.activePlugin = "";
  state.activeGroup = "all";
  activateTab("summary", false, false);
  $("report-json").href = `/api/reports/${state.case.id}`;
  $("report-html").href = `/api/reports/${state.case.id}?format=html`;
  setAnalysisView(true, updateRoute);
  poll();
}
function renderPluginRuns(graph, results) {
  const host = $("plugin-run-list");
  const openPlugins = new Set(
    [...host.querySelectorAll("details[open]")].map((item) => item.dataset.pluginId),
  );
  const plugins = new Map();
  for (const node of graph.nodes.filter((item) => item.type === "plugin")) {
    if (!node.plugin_id || node.plugin_id === "magic-wrapper") continue;
    if (!plugins.has(node.plugin_id)) plugins.set(node.plugin_id, { nodes: [], results: [] });
    plugins.get(node.plugin_id).nodes.push(node);
  }
  for (const result of results) {
    if (!result.plugin_id || result.plugin_id === "magic-wrapper") continue;
    if (!plugins.has(result.plugin_id)) plugins.set(result.plugin_id, { nodes: [], results: [] });
    plugins.get(result.plugin_id).results.push(result);
  }
  host.replaceChildren();
  for (const [pluginId, data] of plugins) {
    const settledStatus = data.results.length
      ? pluginStatus(data.results)
      : data.nodes.map((node) => node.status).filter(Boolean)[0] || "queued";
    const status = data.nodes.some((node) => node.status === "running") ? "running" : settledStatus;
    const hasEvidence = pluginHasEvidence(data.results);
    const groups = groupCatalog(data.results);
    const totals = aggregateCounts(data.results);
    const details = document.createElement("details");
    details.className = "plugin-nav";
    details.dataset.pluginId = pluginId;
    details.open =
      openPlugins.has(pluginId) || state.activePlugin === pluginId || plugins.size === 1;
    const summary = document.createElement("summary");
    const identity = text("span", pluginId, "plugin-nav-name");
    identity.title = pluginId;
    const statusLabel =
      state.jobData?.status === "running" && status === "completed" ? "completato finora" : status;
    summary.append(identity, text("span", statusLabel, `plugin-nav-status status-${status}`));
    const resultFacts = [];
    if (hasEvidence) {
      if (totals.findings) resultFacts.push(`${totals.findings} finding`);
      if (totals.artifacts) resultFacts.push(`${totals.artifacts} artefatti`);
      if (totals.flags) resultFacts.push(`${totals.flags} flag`);
      if (!resultFacts.length) resultFacts.push("Dati rilevati");
    }
    const meta = text(
      "p",
      resultFacts.join(" · ") || ({
        completed: "Nessun riscontro",
        partial: "Nessun riscontro · copertura parziale",
        failed: "Errore durante l’analisi",
        cancelled: "Interrotto su richiesta",
        skipped: "Non analizzato",
      }[status] || "In elaborazione"),
      "plugin-result-facts",
    );
    const sections = text("div", undefined, "plugin-section-links");
    const overview = action(hasEvidence ? "Panoramica" : "Nessun riscontro", () => selectPluginOutput(pluginId));
    overview.dataset.pluginId = pluginId;
    overview.dataset.group = "all";
    sections.append(overview);
    for (const group of groups.filter((item) => !isUtilityGroup(item))) {
      const button = action(group.title || group.id, () => selectPluginOutput(pluginId, group.id));
      button.dataset.pluginId = pluginId;
      button.dataset.group = group.id;
      sections.append(button);
    }
    const utilityAvailable = groups.some(isUtilityGroup) || totals.warnings || totals.errors;
    if (hasEvidence && utilityAvailable) {
      const utility = action("Diagnostica e utility", () => selectPluginOutput(pluginId, "utilities"));
      utility.dataset.pluginId = pluginId;
      utility.dataset.group = "utilities";
      utility.classList.add("utility-link");
      sections.append(utility);
    }
    details.append(summary, meta, sections);
    host.append(details);
  }
  applyOutputSelection();
}
async function refreshCases() {
  const cases = await api("/cases");
  $("case-total").textContent = cases.length;
  $("case-list").replaceChildren();
  if (!cases.length)
    $("case-list").append(
      text("p", "Nessun caso. Aggiungi un asset per iniziare.", "hint"),
    );
  for (const c of cases.reverse()) {
    const b = text(
      "button",
      c.name,
      "case-link" + (state.case?.id === c.id ? " active" : ""),
    );
    b.append(
      text("small", c.id.slice(0, 8) + " / " + c.created_at.slice(0, 10)),
    );
    b.dataset.search = `${c.name} ${c.id}`.toLocaleLowerCase("it-IT");
    b.onclick = () =>
      transitionView("Apertura console del caso…", () => selectCase(c.id)).catch((e) => notice(e.message, true));
    $("case-list").append(b);
  }
  filterCases();
}
function renderCaseConsole() {
  const host = $("case-job-list");
  host.replaceChildren();
  if (!state.case) {
    $("case-console").hidden = true;
    return;
  }
  const jobs = state.case.jobs || [];
  $("case-console-meta").textContent = `${state.assets.length} ASSET · ${jobs.length} ANALISI`;
  $("case-console").hidden = false;
  if (jobs.length) {
    const job = jobs.at(-1);
    const open = action("Entra nella dashboard →", () =>
      transitionView("Apertura dashboard…", () => showJob(job.id)),
    );
    open.classList.add("case-job-open");
    host.append(open);
  } else host.append(text("p", "Nessuna analisi registrata.", "empty"));
}
function filterCases() {
  const query = $("case-search").value.trim().toLocaleLowerCase("it-IT");
  for (const item of $("case-list").querySelectorAll(".case-link"))
    item.hidden = query && !item.dataset.search.includes(query);
}
async function selectCase(id) {
  clearTimeout(state.timer);
  state.job = null;
  state.case = await api("/cases/" + id);
  state.assets = state.case.assets;
  $("case-title").textContent = state.case.name;
  $("case-number").textContent = id.slice(0, 8).toUpperCase();
  $("delete-case").disabled = false;
  setAnalysisView(false, true);
  await refreshCases();
  // Existing cases expose only the dashboard entry, so rebuilding every asset
  // compatibility row here would keep the transition open without adding UI.
  if (!state.case.jobs?.length) await renderAssets();
  renderCaseConsole();
}
async function ensureCase() {
  if (state.case) return state.case;
  const name =
    $("asset-files").files[0]?.name ||
    "Analisi " + new Intl.DateTimeFormat("it-IT", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date()).replace(/[/:]/g, ".");
  const c = await post("/cases", { name });
  state.case = c;
  $("case-title").textContent = c.name;
  $("case-number").textContent = c.id.slice(0, 8).toUpperCase();
  $("delete-case").disabled = false;
  await refreshCases();
  renderCaseConsole();
  return c;
}
async function renderAssets() {
  const section = $("asset-section");
  section.hidden = !state.assets.length || Boolean(state.case?.jobs?.length && !state.analysisOpened);
  $("asset-count").textContent = `${state.assets.length} ASSET`;
  $("asset-list").replaceChildren();
  const candidates = new Map();
  for (const a of state.assets) {
    const row = document.createElement("div");
    row.className = "asset-row";
    const check = document.createElement("input");
    check.type = "checkbox";
    check.checked = !a.parent_id;
    check.dataset.asset = a.id;
    check.setAttribute("aria-label", "Analizza " + a.name);
    const info = document.createElement("div");
    info.append(
      text("span", a.name, "asset-name"),
      text(
        "p",
        `${a.type} · ${a.size.toLocaleString("it-IT")} byte · ${a.triage?.summary || a.mime}`,
      ),
      text("code", "SHA-256 " + a.hashes.sha256, "asset-hash"),
    );
    if (a.triage?.extension_mismatch)
      info.append(text("p", "≠ Estensione e contenuto non corrispondono"));
    if (a.hash_matches)
      info.append(
        text(
          "p",
          a.hash_matches.length
            ? "✓ Hash atteso verificato: " + a.hash_matches.join(", ")
            : "≠ Nessun hash corrisponde al valore atteso",
        ),
      );
    const actions = document.createElement("div");
    actions.className = "asset-actions";
    actions.append(action("Dettagli", () => dialog(a.name, json(a))));
    if (a.triage?.repair_available)
      actions.append(
        action("Ripara copia", async () => {
          if (
            !confirm(
              "Creare una copia con magic bytes riparati? La struttura sarà verificata e l’originale conservato.",
            )
          )
            return;
          const fixed = await post(`/assets/${a.id}/repair`, { confirm: true });
          notice("Copia riparata, validata e registrata nel report.");
          dialog("Riparazione", json(fixed));
          state.assets.push(fixed.asset);
          await renderAssets();
        }),
      );
    row.append(check, info, actions);
    $("asset-list").append(row);
    if (!a.compatible_plugins) {
      try {
        a.compatible_plugins = (
          await api("/assets/" + a.id)
        ).compatible_plugins;
      } catch (e) {
        notice(e.message);
        a.compatible_plugins = [];
      }
    }
    for (const c of a.compatible_plugins)
      if (
        !candidates.has(c.plugin_id) ||
        candidates.get(c.plugin_id).score < c.score
      )
        candidates.set(c.plugin_id, c);
  }
  $("plugin-selection").replaceChildren();
  for (const c of candidates.values()) {
    const row = document.createElement("div");
    row.className = "plugin-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.id = "plugin-" + c.plugin_id;
    input.dataset.plugin = c.plugin_id;
    input.checked = c.available && c.compatible;
    input.disabled = !c.available || !c.compatible;
    const label = text("label", c.name);
    label.htmlFor = input.id;
    label.append(
      text(
        "small",
        (c.available ? "" : "Non disponibile · ") + c.reasons.join(" / "),
      ),
    );
    row.append(
      input,
      label,
      text("span", Math.round(c.score * 100) + "%", "plugin-score"),
    );
    $("plugin-selection").append(row);
  }
  if (!candidates.size)
    empty(
      $("plugin-selection"),
      "Nessun plugin compatibile. Hash, Magic Wrapper per i file e ricerca flag restano disponibili.",
    );
  $("run").disabled = false;
}
$("asset-type").onchange = () => {
  const type = $("asset-type").value;
  const file = ["file", "directory"].includes(type);
  $("file-input-panel").hidden = !file;
  $("asset-content").hidden = file;
  $("content-label").hidden = file;
  $("custom-type").hidden = type !== "custom";
  $("asset-files").toggleAttribute("webkitdirectory", type === "directory");
  $("asset-files").value = "";
  $("file-selection").textContent = "Nessun file selezionato";
};
$("asset-files").onchange = () => {
  $("file-selection").textContent =
    [...$("asset-files").files].map((f) => f.name).join(", ") ||
    "Nessun file selezionato";
};
$("case-search").oninput = filterCases;
$("case-toggle").onclick = () => {
  const open = document.querySelector(".case-rail").classList.toggle("cases-open");
  $("case-toggle").setAttribute("aria-expanded", String(open));
};
$("analysis-menu-toggle").onclick = () => {
  const open = document.querySelector(".analysis-sidebar").classList.toggle("menu-open");
  $("analysis-menu-toggle").setAttribute("aria-expanded", String(open));
};
$("asset-form").onsubmit = (e) => {
  e.preventDefault();
  busy($("identify"), async () => {
    notice("");
    const kind = $("asset-type").value;
    if (["file", "directory"].includes(kind) && !$("asset-files").files.length)
      throw new Error("Seleziona almeno un file.");
    if (!["file", "directory"].includes(kind) && !$("asset-content").value)
      throw new Error("Inserisci il contenuto.");
    const c = await ensureCase();
    let response;
    if (["file", "directory"].includes(kind)) {
      const form = new FormData();
      form.append("case_id", c.id);
      form.append("asset_type", kind);
      form.append("expected_hash", $("expected-hash").value);
      for (const f of $("asset-files").files)
        form.append("files", f, f.webkitRelativePath || f.name);
      response = await api("/assets", { method: "POST", body: form });
    } else
      response = await post("/assets", {
        case_id: c.id,
        type: kind === "custom" ? $("custom-type").value : kind,
        content:
          kind === "json"
            ? JSON.parse($("asset-content").value)
            : $("asset-content").value,
      });
    state.assets.push(...response.assets);
    await renderAssets();
    $("asset-section").scrollIntoView({ behavior: "smooth", block: "start" });
  });
};
$("run").onclick = () =>
  busy($("run"), async () => {
    notice("");
    const ids = [...document.querySelectorAll("[data-asset]:checked")].map(
      (x) => x.dataset.asset,
    );
    if (!ids.length) throw new Error("Seleziona almeno un asset.");
    const plugins = [...document.querySelectorAll("[data-plugin]:checked")].map(
      (x) => x.dataset.plugin,
    );
    const depth = Number($("depth").value);
    const modeBudget = {
      quick: 64 * 1024 ** 2,
      balanced: 512 * 1024 ** 2,
      deep: 1024 ** 3,
    }[$("analysis-mode").value];
    const j = await post("/jobs", {
      case_id: state.case.id,
      asset_ids: ids,
      plugin_ids: plugins,
      recursive: depth > 0,
      max_depth: depth,
      mode: $("analysis-mode").value,
      byte_budget: modeBudget,
      prefixes: $("flag-prefix")
        .value.split(",")
        .map((x) => x.trim())
        .filter(Boolean),
      plugin_options: {},
    });
    await transitionView("Preparazione console di analisi…", () => showJob(j.id));
  });
$("cancel-job").onclick = () =>
  busy($("cancel-job"), () => post(`/jobs/${state.job}/cancel`, {}));
$("pause-job").onclick = () =>
  busy($("pause-job"), async () => {
    const paused = state.jobData?.status === "paused";
    await post(`/jobs/${state.job}/${paused ? "resume" : "pause"}`, {});
    $("pause-job").textContent = paused ? "Ⅱ Pausa" : "▶ Riprendi";
  });
$("new-case").onclick = () => {
  const f = document.createElement("form");
  const label = text("label", "Nome del caso");
  label.htmlFor = "new-case-name";
  const input = document.createElement("input");
  input.id = "new-case-name";
  input.className = "form-control";
  input.required = true;
  input.maxLength = 200;
  input.placeholder = "Nome del caso";
  const submit = text("button", "Crea caso", "action primary mt-3");
  submit.type = "submit";
  f.append(label, input, submit);
  f.onsubmit = (e) => {
    e.preventDefault();
    busy(submit, async () => {
      const c = await post("/cases", { name: input.value });
      $("detail-dialog").close();
      await transitionView("Preparazione console del caso…", () => selectCase(c.id));
    });
  };
  dialog("Nuovo caso", f);
  input.focus();
};
$("delete-case").onclick = () =>
  busy($("delete-case"), async () => {
    if (
      !confirm(
        `Eliminare definitivamente il caso “${state.case.name}”, gli asset e i report?`,
      )
    )
      return;
    await api("/cases/" + state.case.id, { method: "DELETE" });
    clearTimeout(state.timer);
    state.case = null;
    state.assets = [];
    state.job = null;
    $("case-title").textContent = "Nuova indagine";
    $("case-number").textContent = "NON SELEZIONATO";
    $("case-console").hidden = true;
    $("asset-section").hidden = $("results-section").hidden = true;
    await refreshCases();
    notice("Caso eliminato.");
  });
$("registry-button").onclick = async () => {
  try {
    const registry = await api("/plugins");
    const node = document.createElement("div");
    if (registry.message) node.append(text("p", registry.message));
    for (const p of registry.plugins) {
      const d = document.createElement("details");
      d.className = "output-plugin";
      d.append(
        text(
          "summary",
          `${p.available ? "✓" : "×"} ${p.manifest.name} / ${p.manifest.version}`,
        ),
        text("p", p.manifest.domains.join(" · "), "hint"),
        json(p),
      );
      node.append(d);
    }
    if (registry.errors.length) node.append(json(registry.errors));
    dialog("Registro plugin", node);
  } catch (e) {
    notice(e.message);
  }
};
$("close-dialog").onclick = () => $("detail-dialog").close();
$("detail-dialog").addEventListener("click", (e) => {
  if (e.target === $("detail-dialog")) {
    const r = e.target.getBoundingClientRect();
    if (
      e.clientX < r.left ||
      e.clientX > r.right ||
      e.clientY < r.top ||
      e.clientY > r.bottom
    )
      e.target.close();
  }
});
for (const tab of document.querySelectorAll(".result-navigation [data-tab]")) {
  tab.onclick = () => activateTab(tab.dataset.tab, tab.dataset.tab === "outputs");
  tab.onkeydown = (event) => {
    if (!["ArrowDown", "ArrowUp", "ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const tabs = [...tab.closest("[role=tablist]").querySelectorAll("[role=tab]")];
    const current = tabs.indexOf(tab);
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1
      : (current + (["ArrowDown", "ArrowRight"].includes(event.key) ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].focus();
    activateTab(tabs[next].dataset.tab);
  };
}
$("back-to-cases").onclick = () =>
  transitionView("Ritorno alla console del caso…", () => selectCase(state.case.id))
    .catch((e) => notice(e.message));
$("open-workflow-analysis").onclick = () =>
  transitionView("Apertura workflow…", async () => {
    state.case = await api(`/cases/${state.case.id}`);
    state.assets = state.case.assets;
    await openWorkflowWorkspace(state.case, state.assets);
  }).catch((e) => notice(e.message, true));
$("latest-results").onclick = () => {
  state.activePlugin = "";
  state.activeGroup = "all";
  const target = $("outputs").lastElementChild;
  activateTab("outputs");
  applyOutputSelection();
  if (target) $("outputs").scrollTop = target.offsetTop;
};
window.addEventListener("popstate", () =>
  restoreRoute().catch((e) => notice(e.message)),
);
for (const id of ["graph-plugin", "graph-status", "graph-phases"])
  $(id).onchange = drawGraph;
$("graph-export").onclick = () => download("execution-graph.json", state.graph);
async function init() {
  try {
    const h = await api("/health");
    $("health").textContent = h.sandbox
      ? `${h.plugins} plugin · isolamento attivo`
      : "Isolamento non disponibile";
    $("health-symbol").textContent = h.sandbox ? "●" : "×";
    if (!h.sandbox) notice(h.sandbox_error);
    await refreshCases();
    if (!(await restoreWorkflowRoute(async (caseId) => {
      state.case = await api(`/cases/${caseId}`);
      state.assets = state.case.assets;
      $("case-title").textContent = state.case.name;
      $("case-number").textContent = state.case.id.slice(0, 8).toUpperCase();
      $("delete-case").disabled = false;
      return state.case;
    }))) await restoreRoute();
  } catch (e) {
    $("health").textContent = "Backend non raggiungibile";
    notice(e.message);
  }
}
async function restoreRoute() {
  const match = location.pathname.match(
    /^\/cases\/([a-f0-9]+)\/analysis\/([a-f0-9]+)\/?$/,
  );
  if (!match) {
    if (state.analysisOpened) setAnalysisView(false, false);
    return;
  }
  clearTimeout(state.timer);
  state.case = await api("/cases/" + match[1]);
  state.assets = state.case.assets;
  if (!state.case.jobs.some((job) => job.id === match[2]))
    throw new Error("Il job non appartiene al caso indicato");
  $("case-title").textContent = state.case.name;
  $("case-number").textContent = state.case.id.slice(0, 8).toUpperCase();
  $("delete-case").disabled = false;
  await refreshCases();
  showJob(match[2], false);
  const params = new URLSearchParams(location.search);
  const plugin = params.get("plugin") || "";
  const section = params.get("section") || "all";
  const view = params.get("view") || (plugin ? "outputs" : "summary");
  state.activePlugin = plugin;
  state.activeGroup = section;
  activateTab(view, false, false);
}
initWorkflowWorkspace({
  busy,
  notice,
  onClose: (caseId) => transitionView("Ritorno al caso…", () => selectCase(caseId)),
  refreshCase: async (caseId) => {
    state.case = await api(`/cases/${caseId}`);
    state.assets = state.case.assets;
    return state.case;
  },
  openJob: (jobId) => transitionView("Apertura risultati…", () => showJob(jobId)),
});
init();
