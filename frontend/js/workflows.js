/**
 * Case-scoped extraction workflow editor.
 *
 * The editor stores only node positions and non-secret connector settings. Secret
 * fields live in this module's in-memory map and are sent once when a run starts.
 * Nodes use native pointer and drag events; connector execution remains in the
 * backend job sandbox and this module never opens or interprets evidence files.
 */
const $ = (id) => document.getElementById(id);
const element = (tag, value, className) => {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (className) node.className = className;
  return node;
};

let services;
let context = { case: null, assets: [] };
let connectors = [];
let workflow = emptyWorkflow();
let secrets = {};
let selectedNode = "";
let connectionSource = "";
let runId = "";
let pollTimer = null;
let wordlists = null;

function emptyWorkflow() {
  return { id: null, name: "Workflow estrazione", nodes: [], edges: [] };
}

function endpoint(path, options = {}) {
  return fetch(`/api${path}`, options).then(async (response) => {
    const body = await response.json();
    if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail || body));
    return body;
  });
}

function send(path, body, method = "POST") {
  return endpoint(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function uid(prefix) {
  return `${prefix}-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
}

function connectorById(id) {
  return connectors.find((item) => item.id === id);
}

/** Initialize callbacks supplied by the main SPA without creating another router. */
export function initWorkflowWorkspace(options) {
  services = options;
  bindEvents();
}

/** Open an editor for a case and optionally restore one saved workflow. */
export async function openWorkflowWorkspace(caseValue, assets, workflowId = "", updateRoute = true) {
  clearTimeout(pollTimer);
  context = { case: caseValue, assets };
  document.body.classList.remove("analysis-page");
  $("case-console").hidden = true;
  document.querySelector(".intake").hidden = true;
  $("asset-section").hidden = true;
  $("results-section").hidden = true;
  $("workflow-section").hidden = false;
  $("workflow-case-name").textContent = caseValue.name;
  if (!connectors.length) connectors = (await endpoint("/connectors")).connectors.filter((item) => item.available);
  await loadSavedWorkflows();
  if (workflowId) await loadWorkflow(workflowId, false);
  else resetWorkflow(false);
  renderPool();
  window.scrollTo(0, 0);
  if (updateRoute) history.pushState({}, "", `/cases/${caseValue.id}/workflows${workflow.id ? `/${workflow.id}` : ""}`);
}

/** Return true when the current permalink was restored as a workflow route. */
export async function restoreWorkflowRoute(loadCase) {
  const match = location.pathname.match(/^\/cases\/([a-f0-9]+)\/workflows(?:\/([a-f0-9]+))?\/?$/);
  if (!match) return false;
  const value = await loadCase(match[1]);
  await openWorkflowWorkspace(value, value.assets, match[2] || "", false);
  return true;
}

function closeWorkspace() {
  clearTimeout(pollTimer);
  $("workflow-section").hidden = true;
  services.onClose(context.case.id);
}

async function loadSavedWorkflows() {
  const values = await endpoint(`/workflows?case_id=${encodeURIComponent(context.case.id)}`);
  const select = $("workflow-saved");
  select.replaceChildren(new Option("Nuovo workflow", ""));
  for (const item of values) select.append(new Option(item.name, item.id));
}

async function loadWorkflow(id, updateRoute = true) {
  const value = await endpoint(`/workflows/${id}`);
  if (value.case_id !== context.case.id) throw new Error("Il workflow non appartiene al caso aperto");
  workflow = { ...value, nodes: structuredClone(value.nodes), edges: structuredClone(value.edges) };
  secrets = {};
  selectedNode = "";
  connectionSource = "";
  $("workflow-name").value = workflow.name;
  $("workflow-saved").value = workflow.id;
  renderBoard();
  renderInspector();
  if (updateRoute) history.pushState({}, "", `/cases/${context.case.id}/workflows/${id}`);
}

function resetWorkflow(updateRoute = true) {
  workflow = emptyWorkflow();
  secrets = {};
  selectedNode = "";
  connectionSource = "";
  runId = "";
  $("workflow-name").value = workflow.name;
  $("workflow-saved").value = "";
  setRunState({ status: "ready", progress: 0 });
  renderBoard();
  renderInspector();
  if (updateRoute) history.pushState({}, "", `/cases/${context.case.id}/workflows`);
}

function renderPool() {
  const host = $("workflow-pool-items");
  const mode = $("workflow-pool-mode").value;
  const needle = $("workflow-pool-search").value.trim().toLocaleLowerCase("it-IT");
  host.replaceChildren();
  const values = mode === "files"
    ? context.assets.map((asset) => ({ key: asset.id, title: asset.name, detail: `${asset.type} · ${formatBytes(asset.size || 0)}`, icon: "fa-file", kind: "asset" }))
    : connectors.map((connector) => ({ key: connector.id, title: connector.name, detail: connector.description, icon: connector.icon || "fa-puzzle-piece", kind: "connector" }));
  for (const item of values.filter((value) => `${value.title} ${value.detail}`.toLocaleLowerCase("it-IT").includes(needle))) {
    const row = element("div", undefined, "workflow-pool-item");
    row.draggable = true;
    row.tabIndex = 0;
    row.dataset.kind = item.kind;
    row.dataset.key = item.key;
    const icon = element("i", undefined, `fa-solid ${item.icon}`);
    icon.setAttribute("aria-hidden", "true");
    const copy = element("span");
    copy.append(element("strong", item.title), element("small", item.detail));
    row.append(icon, copy);
    row.ondragstart = (event) => event.dataTransfer.setData("application/x-forensic-node", JSON.stringify({ kind: item.kind, key: item.key }));
    row.ondblclick = () => {
      const position = defaultPosition(item.kind);
      addNode(item.kind, item.key, position.x, position.y);
    };
    row.onkeydown = (event) => {
      if (event.key === "Enter") {
        const position = defaultPosition(item.kind);
        addNode(item.kind, item.key, position.x, position.y);
      }
    };
    host.append(row);
  }
  if (!host.children.length) host.append(element("p", "Nessun elemento disponibile.", "empty"));
}

function defaultPosition(kind) {
  const peers = workflow.nodes.filter((node) => node.kind === kind).length;
  return { x: kind === "asset" ? 35 : 320 + Math.floor(peers / 5) * 230, y: 45 + (peers % 5) * 105 };
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 ** 2).toFixed(1)} MB`;
}

function addNode(kind, key, x, y) {
  const canvas = $("workflow-canvas");
  const node = {
    id: uid(kind === "asset" ? "asset" : "connector"),
    kind,
    asset_id: kind === "asset" ? key : null,
    connector_id: kind === "connector" ? key : null,
    x: Math.max(10, Math.min(x, canvas.clientWidth - 210)),
    y: Math.max(10, y),
    config: {},
  };
  const connector = kind === "connector" ? connectorById(key) : null;
  for (const field of connector?.configuration || []) if (field.default !== undefined) node.config[field.id] = field.default;
  workflow.nodes.push(node);
  selectedNode = node.id;
  renderBoard();
  renderInspector();
}

function nodeLabel(node) {
  if (node.kind === "asset") return context.assets.find((item) => item.id === node.asset_id)?.name || "Asset non disponibile";
  return connectorById(node.connector_id)?.name || node.connector_id;
}

function renderBoard() {
  const host = $("workflow-nodes");
  host.replaceChildren();
  $("workflow-empty").hidden = Boolean(workflow.nodes.length);
  $("workflow-board-count").textContent = `${workflow.nodes.length} nodi · ${workflow.edges.length} collegamenti`;
  for (const data of workflow.nodes) {
    const node = element(
      "article",
      undefined,
      `workflow-node node-${data.kind}${selectedNode === data.id ? " selected" : ""}${connectionSource === data.id ? " connecting" : ""}`,
    );
    node.dataset.nodeId = data.id;
    node.style.left = `${data.x}px`;
    node.style.top = `${data.y}px`;
    const input = element("button", "", "workflow-port input");
    input.type = "button";
    input.title = "Collega qui";
    input.hidden = data.kind === "asset";
    input.onclick = (event) => { event.stopPropagation(); finishConnection(data.id); };
    const heading = element("div", undefined, "workflow-node-heading");
    heading.append(element("span", data.kind === "asset" ? "FILE" : "CONNECTOR"), element("strong", nodeLabel(data)));
    const output = element("button", "", "workflow-port output");
    output.type = "button";
    output.title = "Inizia collegamento";
    output.onclick = (event) => { event.stopPropagation(); connectionSource = data.id; renderBoard(); };
    node.append(input, heading, element("small", data.status || (data.kind === "asset" ? "evidenza" : "da configurare")), output);
    node.onclick = () => { selectedNode = data.id; renderBoard(); renderInspector(); };
    enableNodeDrag(node, data);
    host.append(node);
  }
  requestAnimationFrame(drawEdges);
}

function enableNodeDrag(node, data) {
  node.onpointerdown = (event) => {
    if (event.button !== 0 || event.target.closest("button, input, select")) return;
    const origin = { x: event.clientX, y: event.clientY, left: data.x, top: data.y };
    node.setPointerCapture(event.pointerId);
    node.onpointermove = (move) => {
      data.x = Math.max(0, origin.left + move.clientX - origin.x);
      data.y = Math.max(0, origin.top + move.clientY - origin.y);
      node.style.left = `${data.x}px`;
      node.style.top = `${data.y}px`;
      drawEdges();
    };
    node.onpointerup = () => { node.onpointermove = null; node.onpointerup = null; };
  };
}

function finishConnection(target) {
  if (!connectionSource || connectionSource === target) return;
  if (workflow.edges.some((edge) => edge.source === connectionSource && edge.target === target)) return;
  if (wouldCycle(connectionSource, target)) {
    services.notice("Il collegamento creerebbe un ciclo.", true);
    return;
  }
  workflow.edges.push({ id: uid("edge"), source: connectionSource, target });
  connectionSource = "";
  renderBoard();
}

function wouldCycle(source, target) {
  const graph = new Map();
  for (const edge of workflow.edges) {
    if (!graph.has(edge.source)) graph.set(edge.source, []);
    graph.get(edge.source).push(edge.target);
  }
  if (!graph.has(source)) graph.set(source, []);
  graph.get(source).push(target);
  const stack = [target];
  const seen = new Set();
  while (stack.length) {
    const current = stack.pop();
    if (current === source) return true;
    if (seen.has(current)) continue;
    seen.add(current);
    stack.push(...(graph.get(current) || []));
  }
  return false;
}

function drawEdges() {
  const canvas = $("workflow-canvas").getBoundingClientRect();
  const group = $("workflow-edges").querySelector("g");
  group.replaceChildren();
  for (const edge of workflow.edges) {
    const source = document.querySelector(`[data-node-id="${CSS.escape(edge.source)}"]`);
    const target = document.querySelector(`[data-node-id="${CSS.escape(edge.target)}"]`);
    if (!source || !target) continue;
    const a = source.getBoundingClientRect();
    const b = target.getBoundingClientRect();
    const x1 = a.right - canvas.left;
    const y1 = a.top + a.height / 2 - canvas.top;
    const x2 = b.left - canvas.left;
    const y2 = b.top + b.height / 2 - canvas.top;
    const bend = Math.max(40, Math.abs(x2 - x1) * 0.45);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`);
    path.setAttribute("marker-end", "url(#workflow-arrow)");
    group.append(path);
  }
}

function renderInspector() {
  const host = $("workflow-inspector");
  host.replaceChildren(element("h3", "Configurazione"));
  const node = workflow.nodes.find((item) => item.id === selectedNode);
  if (!node) { host.append(element("p", "Seleziona un nodo per vedere proprietà e parametri.", "empty")); return; }
  host.append(element("p", nodeLabel(node), "workflow-inspector-title"), element("code", node.id));
  if (node.kind === "asset") {
    const asset = context.assets.find((item) => item.id === node.asset_id) || {};
    host.append(facts({ Tipo: asset.type, MIME: asset.mime, Dimensione: formatBytes(asset.size || 0), SHA256: asset.hashes?.sha256 }));
  } else {
    const connector = connectorById(node.connector_id);
    host.append(element("p", connector.description, "workflow-inspector-description"));
    for (const field of connector.configuration || []) host.append(renderField(node, field));
  }
  const related = workflow.edges.filter((edge) => edge.source === node.id || edge.target === node.id);
  if (related.length) {
    const edges = element("div", undefined, "workflow-edge-list");
    edges.append(element("h4", "Collegamenti"));
    for (const edge of related) {
      const otherId = edge.source === node.id ? edge.target : edge.source;
      const other = workflow.nodes.find((item) => item.id === otherId);
      const row = element("div");
      row.append(element("span", `${edge.source === node.id ? "→" : "←"} ${nodeLabel(other)}`));
      const removeEdge = element("button", "×", "plain");
      removeEdge.type = "button";
      removeEdge.title = "Rimuovi collegamento";
      removeEdge.onclick = () => {
        workflow.edges = workflow.edges.filter((item) => item.id !== edge.id);
        renderBoard();
        renderInspector();
      };
      row.append(removeEdge);
      edges.append(row);
    }
    host.append(edges);
  }
  const remove = element("button", "Rimuovi nodo", "plain workflow-remove");
  remove.onclick = () => {
    workflow.nodes = workflow.nodes.filter((item) => item.id !== node.id);
    workflow.edges = workflow.edges.filter((edge) => edge.source !== node.id && edge.target !== node.id);
    delete secrets[node.id];
    selectedNode = "";
    renderBoard();
    renderInspector();
  };
  host.append(remove);
}

function facts(values) {
  const dl = element("dl", undefined, "workflow-facts");
  for (const [key, value] of Object.entries(values)) if (value !== undefined) dl.append(element("dt", key), element("dd", value));
  return dl;
}

function renderField(node, field) {
  const wrap = element("label", field.label, "workflow-field");
  if (field.type === "select") {
    const input = element("select", undefined, "form-select");
    for (const value of field.options || []) input.append(new Option(value, value));
    input.value = node.config[field.id] ?? field.default ?? "";
    input.onchange = () => { node.config[field.id] = input.value; };
    wrap.append(input);
  } else if (field.type === "boolean") {
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = Boolean(node.config[field.id]);
    input.onchange = () => { node.config[field.id] = input.checked; };
    wrap.prepend(input);
  } else if (field.type === "wordlist_multiselect") {
    const box = element("div", "Caricamento liste…", "workflow-wordlists");
    wrap.append(box);
    loadWordlists(box, node);
  } else {
    const input = document.createElement("input");
    input.className = "form-control";
    input.type = field.type === "password" ? "password" : field.type === "number" ? "number" : "text";
    input.autocomplete = field.type === "password" ? "new-password" : "off";
    input.value = field.type === "password" ? secrets[node.id]?.[field.id] || "" : node.config[field.id] ?? field.default ?? "";
    input.oninput = () => {
      if (field.type === "password") secrets[node.id] = { ...(secrets[node.id] || {}), [field.id]: input.value };
      else node.config[field.id] = field.type === "number" ? Number(input.value) : input.value;
    };
    wrap.append(input);
  }
  return wrap;
}

async function loadWordlists(host, node) {
  try {
    if (!wordlists) wordlists = (await endpoint("/plugins/bruteforce/wordlists")).wordlists;
    host.replaceChildren();
    const selected = new Set(node.config.wordlists || []);
    for (const item of wordlists.slice(0, 250)) {
      const label = element("label");
      const input = document.createElement("input");
      input.type = "checkbox";
      input.checked = selected.has(item.path);
      input.onchange = () => {
        input.checked ? selected.add(item.path) : selected.delete(item.path);
        node.config.wordlists = [...selected];
      };
      label.append(input, document.createTextNode(` ${item.relative_path || item.name}`));
      host.append(label);
    }
    if (!wordlists.length) host.append(element("p", "Nessuna wordlist configurata.", "empty"));
  } catch (error) { host.textContent = error.message; }
}

async function saveWorkflow() {
  if (!workflow.nodes.length) throw new Error("Aggiungi almeno un nodo al workflow.");
  workflow.name = $("workflow-name").value.trim() || "Workflow estrazione";
  const body = { case_id: context.case.id, name: workflow.name, nodes: workflow.nodes.map(({ status, outputs, ...node }) => node), edges: workflow.edges };
  const saved = workflow.id ? await send(`/workflows/${workflow.id}`, body, "PUT") : await send("/workflows", body);
  workflow.id = saved.id;
  await loadSavedWorkflows();
  $("workflow-saved").value = saved.id;
  history.replaceState({}, "", `/cases/${context.case.id}/workflows/${saved.id}`);
  services.notice("Workflow salvato.");
  return saved;
}

async function runWorkflow() {
  await saveWorkflow();
  const missingSecret = workflow.nodes.find((node) => node.connector_id === "known-password" && !secrets[node.id]?.password);
  if (missingSecret) { selectedNode = missingSecret.id; renderBoard(); renderInspector(); throw new Error("Inserisci la password nel connector selezionato."); }
  const missingVolumeSecret = workflow.nodes.find((node) => node.connector_id === "bitlocker-readonly" && !secrets[node.id]?.password && !secrets[node.id]?.recovery_key);
  if (missingVolumeSecret) { selectedNode = missingVolumeSecret.id; renderBoard(); renderInspector(); throw new Error("Inserisci una password o recovery key BitLocker."); }
  const run = await send(`/workflows/${workflow.id}/run`, { secrets });
  runId = run.id;
  secrets = {};
  renderInspector();
  setRunState(run);
  pollRun();
}

async function pollRun() {
  try {
    const run = await endpoint(`/workflow-runs/${runId}`);
    setRunState(run);
    renderRunOutput(run);
    if (["queued", "running", "paused"].includes(run.status)) pollTimer = setTimeout(pollRun, 700);
    else {
      pollTimer = null;
      const refreshed = await services.refreshCase(context.case.id);
      context = { case: refreshed, assets: refreshed.assets };
      renderPool();
    }
  } catch (error) { services.notice(error.message, true); }
}

function setRunState(run) {
  const progress = Math.max(0, Math.min(100, run.progress || 0));
  $("workflow-run-status").textContent = String(run.status || "ready").toUpperCase();
  $("workflow-run-detail").textContent = run.id ? `RUN ${run.id.slice(0, 12).toUpperCase()} · ${run.jobs?.length || 0} job` : "Costruisci il flusso trascinando i nodi.";
  $("workflow-progress-bar").style.width = `${progress}%`;
  $("workflow-progress-bar").parentElement.setAttribute("aria-valuenow", progress);
  $("workflow-cancel").hidden = !["queued", "running", "paused"].includes(run.status);
  for (const current of run.nodes || []) {
    const node = workflow.nodes.find((item) => item.id === current.id);
    if (node) node.status = current.status;
  }
  for (const node of $("workflow-nodes").children) {
    const data = workflow.nodes.find((item) => item.id === node.dataset.nodeId);
    if (data) { node.dataset.status = data.status || ""; node.querySelector("small").textContent = data.status || (data.kind === "asset" ? "evidenza" : "da configurare"); }
  }
}

function renderRunOutput(run) {
  const host = $("workflow-run-output");
  host.replaceChildren();
  for (const node of (run.nodes || []).filter((item) => item.kind === "connector")) {
    const section = element("section", undefined, "workflow-output-node");
    section.append(element("h4", nodeLabel(node)), element("span", node.status, `status-${node.status}`));
    section.append(facts({ "Asset in ingresso": node.input_assets?.length || 0, "Asset prodotti": node.output_count || 0, "Job plugin": node.job_id || "—" }));
    if (node.job_id) {
      const open = element("button", "Apri risultati plugin →", "plain");
      open.onclick = () => services.openJob(node.job_id);
      section.append(open);
    }
    host.append(section);
  }
  if (run.warnings?.length) host.append(facts({ Warning: run.warnings.join(" · ") }));
  if (run.errors?.length) host.append(facts({ Errori: run.errors.join(" · ") }));
  if (!host.children.length) host.append(element("p", "Workflow in preparazione…", "empty"));
}

function bindEvents() {
  $("workflow-back").onclick = closeWorkspace;
  $("workflow-pool-mode").onchange = renderPool;
  $("workflow-pool-search").oninput = renderPool;
  $("workflow-saved").onchange = () => $("workflow-saved").value ? loadWorkflow($("workflow-saved").value) : resetWorkflow();
  $("workflow-save").onclick = () => services.busy($("workflow-save"), saveWorkflow);
  $("workflow-run").onclick = () => services.busy($("workflow-run"), runWorkflow);
  $("workflow-cancel").onclick = () => send(`/workflow-runs/${runId}/cancel`, {});
  const canvas = $("workflow-canvas");
  canvas.ondragover = (event) => { if (event.dataTransfer.types.includes("application/x-forensic-node")) event.preventDefault(); };
  canvas.ondrop = (event) => {
    event.preventDefault();
    const payload = JSON.parse(event.dataTransfer.getData("application/x-forensic-node"));
    const box = canvas.getBoundingClientRect();
    addNode(payload.kind, payload.key, event.clientX - box.left, event.clientY - box.top);
  };
  window.addEventListener("resize", drawEdges);
}
