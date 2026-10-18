/** JSON → presentation. Declarative fields only; no HTML, templates or evaluation. */
const make = (tag, value, className) => {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = String(value);
  if (className) node.className = className;
  return node;
};
export const labelFor = (key) =>
  String(key)
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/^./, (c) => c.toUpperCase());
export function readPath(value, path) {
  for (const key of String(path).split(".")) {
    if (
      ["__proto__", "prototype", "constructor"].includes(key) ||
      value == null ||
      !Object.hasOwn(value, key)
    )
      return undefined;
    value = value[key];
  }
  return value;
}
const isObject = (value) => value !== null && typeof value === "object";
const scalar = (value) => !isObject(value);
const fieldsFor = (fields) =>
  (fields || []).map((f) =>
    typeof f === "string"
      ? { field: f, label: labelFor(f) }
      : {
          ...f,
          label: f.label || labelFor(f.field || f.id),
          field: f.field || f.id,
        },
  );
export function formatted(value, field = {}) {
  if (value === null || value === undefined || value === "") return "—";
  if (field.format === "boolean" || typeof value === "boolean")
    return value ? "Sì" : "No";
  let result = String(value);
  const number = Number(value);
  if (
    ["number", "bytes", "percent", "duration"].includes(field.format) &&
    Number.isFinite(number)
  ) {
    if (field.format === "number")
      result = new Intl.NumberFormat("it-IT", {
        maximumFractionDigits: 4,
      }).format(number);
    if (field.format === "percent")
      result = new Intl.NumberFormat("it-IT", {
        style: "percent",
        maximumFractionDigits: 1,
      }).format(number);
    if (field.format === "bytes") {
      const unit = Math.min(
        4,
        Math.max(0, Math.floor(Math.log2(Math.max(1, Math.abs(number))) / 10)),
      );
      result =
        new Intl.NumberFormat("it-IT", { maximumFractionDigits: 2 }).format(
          number / 1024 ** unit,
        ) +
        " " +
        ["B", "KiB", "MiB", "GiB", "TiB"][unit];
    }
    if (field.format === "duration")
      result =
        new Intl.NumberFormat("it-IT", { maximumFractionDigits: 3 }).format(
          number,
        ) + " s";
  }
  if (field.format === "datetime") {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime()))
      result = new Intl.DateTimeFormat("it-IT", {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(date);
  }
  if (field.format === "hex") {
    try {
      result = "0x" + BigInt(value).toString(16).toUpperCase();
    } catch {
      /* Preserve nonnumeric evidence as text. */
    }
  }
  return result + (field.unit ? " " + field.unit : "");
}
function valueNode(value, field = {}, depth = 0) {
  if (isObject(value))
    return renderData(value, {
      depth: depth + 1,
      type: field.format === "tags" ? "list" : "auto",
    });
  const tag = ["hex", "code"].includes(field.format) ? "code" : "span";
  const node = make(tag, formatted(value, field), "data-value");
  if (typeof value === "boolean") node.classList.add("data-boolean");
  if (field.description) node.title = field.description;
  return node;
}
function fold(label, value, depth, open = false) {
  const details = make("details", undefined, "data-fold");
  const size = Array.isArray(value)
    ? `${value.length} elementi`
    : `${Object.keys(value).length} campi`;
  const summary = make("summary");
  summary.append(make("span", label), make("small", size));
  details.append(summary);
  const fill = () => {
    if (!details.dataset.loaded && details.open) {
      details.dataset.loaded = "true";
      details.append(renderData(value, { depth: depth + 1 }));
    }
  };
  details.addEventListener("toggle", fill);
  details.open = open;
  fill();
  return details;
}
function detailsView(data, fields, depth) {
  const host = make("div", undefined, "data-details");
  const declared = fieldsFor(fields);
  const used = new Set(declared.map((f) => f.field));
  const specs = [
    ...declared,
    ...Object.keys(data)
      .filter((k) => !used.has(k))
      .map((field) => ({ field, label: labelFor(field) })),
  ];
  const facts = make("dl", undefined, "data-facts");
  host.append(facts);
  for (const field of specs) {
    const value = readPath(data, field.field);
    if (value === undefined && declared.length) continue;
    if (isObject(value)) {
      host.append(fold(field.label, value, depth, depth < 1));
      continue;
    }
    const pair = make("div", undefined, "data-fact");
    pair.append(make("dt", field.label));
    const dd = make("dd");
    dd.append(valueNode(value, field, depth));
    pair.append(dd);
    facts.append(pair);
  }
  return host;
}
export function renderTable(data, fields = [], depth = 0) {
  if (
    !Array.isArray(data) ||
    data.some((x) => !isObject(x) || Array.isArray(x))
  )
    return renderData(data, { type: "auto", depth });
  const host = make("div", undefined, "mapped-table");
  if (!data.length) {
    host.append(make("p", "Nessun elemento disponibile.", "data-empty"));
    return host;
  }
  const inferred = [...new Set(data.flatMap((row) => Object.keys(row)))];
  const columns = fieldsFor(fields.length ? fields : inferred.slice(0, 6));
  const toolbar = make("div", undefined, "data-table-tools");
  const search = make("input");
  search.type = "search";
  search.placeholder = "Cerca nei campi visibili";
  search.setAttribute("aria-label", "Cerca nei campi visibili della sezione");
  const counter = make("output");
  counter.setAttribute("aria-live", "polite");
  toolbar.append(search);
  const filterFields = [
    "technique", "severity", "parser", "event_type", "host", "user",
    "source_ip", "session_id", "status",
  ].filter((key) =>
    data.some((row) => row[key] !== undefined && row[key] !== null),
  );
  const filters = {};
  for (const key of filterFields) {
    const select = make("select");
    select.setAttribute("aria-label", `Filtra per ${labelFor(key)}`);
    select.append(new Option(`Tutte: ${labelFor(key)}`, ""));
    [...new Set(data.map((row) => String(row[key] ?? "")).filter(Boolean))]
      .sort((a, b) => a.localeCompare(b, "it-IT"))
      .forEach((value) => select.append(new Option(value, value)));
    filters[key] = select;
    toolbar.append(select);
  }
  let confidenceFilter = null;
  if (data.some((row) => Number.isFinite(Number(row.confidence)))) {
    confidenceFilter = make("select");
    confidenceFilter.setAttribute("aria-label", "Confidenza minima");
    confidenceFilter.append(
      new Option("Qualsiasi confidenza", ""),
      new Option("Confidenza ≥ 0,50", "0.5"),
      new Option("Confidenza ≥ 0,75", "0.75"),
      new Option("Confidenza ≥ 0,90", "0.9"),
    );
    toolbar.append(confidenceFilter);
  }
  toolbar.append(counter);
  host.append(toolbar);
  const wrap = make("div", undefined, "table-wrap");
  const table = make("table");
  const thead = make("thead"),
    tr = make("tr");
  const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  let sortField = columns.some((field) => field.field === "severity")
    ? "severity"
    : columns.some((field) => field.field === "confidence")
      ? "confidence"
      : "";
  let sortDirection = "descending";
  columns.forEach((c) => {
    const th = make("th");
    th.scope = "col";
    const sort = make("button", c.label, "table-sort");
    sort.type = "button";
    sort.setAttribute("aria-label", `Ordina per ${c.label}`);
    sort.onclick = () => {
      if (sortField === c.field)
        sortDirection = sortDirection === "ascending" ? "descending" : "ascending";
      else {
        sortField = c.field;
        sortDirection = "ascending";
      }
      page = 0;
      draw();
    };
    th.append(sort);
    tr.append(th);
  });
  tr.append(make("th", "Dettaglio"));
  thead.append(tr);
  table.append(thead);
  const tbody = make("tbody");
  table.append(tbody);
  wrap.append(table);
  host.append(wrap);
  const paging = make("div", undefined, "data-paging");
  const previous = make("button", "← Precedenti"),
    next = make("button", "Successivi →");
  previous.type = next.type = "button";
  paging.append(previous, next);
  host.append(paging);
  let page = 0;
  const size = 25;
  const rows = data.map((value, index) => ({
    value,
    index,
    search: null,
  }));
  function draw() {
    const query = search.value.toLocaleLowerCase("it-IT");
    const filtered = rows.filter(
      (r) =>
        (!query || (r.search ??= columns
          .map((field) => readPath(r.value, field.field))
          .filter((value) => !isObject(value) && value !== undefined && value !== null)
          .map((value) => String(value).slice(0, 2048))
          .join(" ")
          .toLocaleLowerCase("it-IT")).includes(query)) &&
        Object.entries(filters).every(
          ([key, select]) =>
            !select.value || String(r.value[key] ?? "") === select.value,
        ) &&
        (!confidenceFilter?.value ||
          Number(r.value.confidence) >= Number(confidenceFilter.value)),
    );
    const direction = sortDirection === "ascending" ? 1 : -1;
    const ordered = sortField
      ? filtered.sort((a, b) => {
          const av = readPath(a.value, sortField);
          const bv = readPath(b.value, sortField);
          let comparison = 0;
          if (sortField === "severity")
            comparison = (severityOrder[String(av).toLowerCase()] || 0) - (severityOrder[String(bv).toLowerCase()] || 0);
          else if (Number.isFinite(Number(av)) && Number.isFinite(Number(bv)))
            comparison = Number(av) - Number(bv);
          else
            comparison = String(av ?? "").localeCompare(String(bv ?? ""), "it-IT", { numeric: true, sensitivity: "base" });
          if (comparison) return comparison * direction;
          if (sortField === "severity") {
            const confidence = Number(b.value.confidence || 0) - Number(a.value.confidence || 0);
            if (confidence) return confidence;
          }
          return a.index - b.index;
        })
      : filtered;
    const start = page * size;
    tbody.replaceChildren();
    counter.textContent = ordered.length
      ? `${start + 1}–${Math.min(start + size, ordered.length)} / ${ordered.length}`
      : "Nessun risultato";
    previous.disabled = page === 0;
    next.disabled = start + size >= ordered.length;
    paging.hidden = ordered.length <= size;
    columns.forEach((field, index) => {
      const th = tr.children[index];
      const active = sortField === field.field;
      th.setAttribute("aria-sort", active ? sortDirection : "none");
      th.firstChild.textContent = `${field.label}${active ? sortDirection === "ascending" ? " ↑" : " ↓" : ""}`;
    });
    for (const { value: row, index } of ordered.slice(start, start + size)) {
      const tr = make("tr");
      tr.dataset.index = index;
      tr.dataset.selectionKey = String(row.id ?? row.key ?? index);
      for (const field of columns) {
        const td = make("td");
        const value = readPath(row, field.field);
        if (isObject(value))
          td.append(
            fold(Array.isArray(value) ? "Elementi" : "Campi", value, depth),
          );
        else td.append(valueNode(value, field, depth));
        tr.append(td);
      }
      const td = make("td");
      const toggle = make("button", "Apri", "data-row-toggle");
      toggle.type = "button";
      toggle.setAttribute("aria-expanded", "false");
      td.append(toggle);
      tr.append(td);
      tbody.append(tr);
      const detailRow = make("tr", undefined, "data-expanded-row");
      detailRow.hidden = true;
      const cell = make("td");
      cell.colSpan = columns.length + 1;
      detailRow.append(cell);
      tbody.append(detailRow);
      toggle.onclick = () => {
        detailRow.hidden = !detailRow.hidden;
        toggle.setAttribute("aria-expanded", String(!detailRow.hidden));
        toggle.textContent = detailRow.hidden ? "Apri" : "Chiudi";
        if (!cell.childNodes.length)
          cell.append(detailsView(row, fields, depth + 1));
      };
    }
  }
  search.oninput = () => {
    page = 0;
    draw();
  };
  Object.values(filters).forEach((select) => {
    select.onchange = () => { page = 0; draw(); };
  });
  if (confidenceFilter) confidenceFilter.onchange = () => { page = 0; draw(); };
  previous.onclick = () => {
    page--;
    draw();
  };
  next.onclick = () => {
    page++;
    draw();
  };
  draw();
  return host;
}
function metrics(data, fields) {
  const grid = make("dl", undefined, "data-metrics");
  const specs = Array.isArray(data)
    ? data.map((row, i) => ({
        label: row.metric ?? row.label ?? row.name ?? String(i + 1),
        value: row.value ?? row.count ?? row,
      }))
    : fieldsFor(fields?.length ? fields : Object.keys(data)).map((field) => ({
        ...field,
        value: readPath(data, field.field),
      }));
  for (const field of specs) {
    const metric = make("div", undefined, "data-metric");
    metric.append(make("dt", field.label));
    const dd = make("dd");
    dd.append(valueNode(field.value, field));
    metric.append(dd);
    grid.append(metric);
  }
  return grid;
}
export function renderData(data, options = {}) {
  const { type = "auto", fields = [], depth = 0 } = options;
  if (
    data === null ||
    data === undefined ||
    (Array.isArray(data) && !data.length) ||
    (isObject(data) && !Object.keys(data).length)
  )
    return make("p", options.empty || "Nessun dato disponibile.", "data-empty");
  if (depth > 7 && isObject(data)) {
    const boundary = fold("Esplora il livello successivo", data, 0);
    boundary.classList.add("data-depth-boundary");
    return boundary;
  }
  if (type === "metrics" && isObject(data)) return metrics(data, fields);
  if (
    (type === "table" || type === "auto") &&
    Array.isArray(data) &&
    data.every((x) => isObject(x) && !Array.isArray(x))
  )
    return renderTable(data, fields, depth);
  if (Array.isArray(data)) {
    const host = make(
      "div",
      undefined,
      data.every(scalar) ? "data-list" : "data-records",
    );
    let shown = 0;
    const more = make("button", "Mostra altri elementi", "plain");
    more.type = "button";
    function append() {
      const end = Math.min(shown + 50, data.length);
      for (let i = shown; i < end; i++) {
        const value = data[i];
        host.insertBefore(
          isObject(value)
            ? fold(`Elemento ${i + 1}`, value, depth)
            : valueNode(value, {}, depth),
          more,
        );
      }
      shown = end;
      more.hidden = shown >= data.length;
      more.textContent = `Mostra altri elementi (${data.length - shown})`;
    }
    host.append(more);
    more.onclick = append;
    append();
    return host;
  }
  if (isObject(data)) return detailsView(data, fields, depth);
  return make(
    type === "terminal" ? "pre" : "p",
    formatted(data),
    type === "terminal" ? "terminal" : "data-prose",
  );
}
export function technicalView(data, label = "JSON originale") {
  const details = make("details", undefined, "technical-view");
  details.append(make("summary", label));
  details.addEventListener("toggle", () => {
    if (details.open && !details.dataset.loaded) {
      details.dataset.loaded = "true";
      details.append(make("pre", JSON.stringify(data, null, 2), "json-output"));
    }
  });
  return details;
}
export function renderStructured(data, options = {}) {
  const host = make("div", undefined, "structured-output");
  host.append(renderData(data, options), technicalView(data));
  return host;
}
