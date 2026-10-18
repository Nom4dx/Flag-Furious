const NS = "http://www.w3.org/2000/svg";
export const PALETTES = Object.freeze({
  forensic: { background: "#080a0d", surface: "#11151a", foreground: "#f4f7f5", primary: "#27d6a1", secondary: "#f1c75b", critical: "#ff6b6b", muted: "#87929c" },
  document: { background: "#0b0907", surface: "#17120d", foreground: "#fff8e7", primary: "#d9a441", secondary: "#71c4d6", critical: "#e36b6b", muted: "#9d9485" },
  filesystem: { background: "#070b09", surface: "#0e1813", foreground: "#effff7", primary: "#48c98b", secondary: "#d9c95e", critical: "#ef6a6a", muted: "#789488" },
  network: { background: "#070a0d", surface: "#0d151c", foreground: "#edf9ff", primary: "#42bce8", secondary: "#a78bfa", critical: "#ff6f7d", muted: "#768e9b" },
  signal: { background: "#0b080d", surface: "#18101d", foreground: "#fff3ff", primary: "#db73ef", secondary: "#61d8d0", critical: "#ff7171", muted: "#96829b" },
  archive: { background: "#0d0906", surface: "#1a120b", foreground: "#fff7ed", primary: "#f0a34a", secondary: "#e3d15b", critical: "#ef6f61", muted: "#9d8b78" },
  code: { background: "#08090d", surface: "#11131c", foreground: "#f2f2ff", primary: "#8fa8ff", secondary: "#55d6be", critical: "#ff6f91", muted: "#85899d" },
  volume: { background: "#07090c", surface: "#101722", foreground: "#f2f7ff", primary: "#56a8ff", secondary: "#d6b85c", critical: "#f06b78", muted: "#7f8c9d" },
  text: { background: "#090909", surface: "#151515", foreground: "#fafafa", primary: "#e5cf68", secondary: "#66c7b5", critical: "#eb7070", muted: "#909090" },
  monochrome: { background: "#000000", surface: "#111111", foreground: "#ffffff", primary: "#ffffff", secondary: "#bdbdbd", critical: "#ffffff", muted: "#808080" },
});
export function paletteFor(value) {
  if (value && typeof value === "object") {
    const safe = Object.fromEntries(Object.entries(value).filter(([key, color]) => key in PALETTES.forensic && /^#[0-9a-f]{6}$/i.test(color)));
    return { ...PALETTES.forensic, ...safe };
  }
  return PALETTES[value] || PALETTES.forensic;
}
export function applyPalette(node, value) {
  const palette = paletteFor(value);
  for (const [name, color] of Object.entries(palette)) node.style.setProperty(`--viz-${name}`, color);
  return palette;
}
export const el = (tag, attrs = {}, text = "") => {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs))
    node.setAttribute(key, value);
  if (text !== "") node.textContent = text;
  return node;
};
export function download(name, value, type = "application/json") {
  const blob = new Blob(
    [typeof value === "string" ? value : JSON.stringify(value, null, 2)],
    { type },
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function button(text, callback) {
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = text;
  b.onclick = callback;
  return b;
}
function interactive(svg, group, width, height) {
  let x = 0,
    y = 0,
    scale = 1,
    drag = null;
  function apply() {
    group.setAttribute("transform", `translate(${x} ${y}) scale(${scale})`);
  }
  const point = (e) => {
    const p = svg.createSVGPoint();
    p.x = e.clientX;
    p.y = e.clientY;
    return p.matrixTransform(svg.getScreenCTM().inverse());
  };
  function zoom(factor, p = { x: width / 2, y: height / 2 }) {
    const old = scale;
    scale = Math.min(8, Math.max(0.12, scale * factor));
    x = p.x - ((p.x - x) * scale) / old;
    y = p.y - ((p.y - y) * scale) / old;
    apply();
  }
  svg.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      zoom(e.deltaY < 0 ? 1.12 : 0.89, point(e));
    },
    { passive: false },
  );
  svg.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || e.target.closest('[role="button"]')) return;
    const p = point(e);
    drag = { x: p.x, y: p.y, ox: x, oy: y };
    svg.setPointerCapture(e.pointerId);
  });
  svg.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const p = point(e);
    x = drag.ox + p.x - drag.x;
    y = drag.oy + p.y - drag.y;
    apply();
  });
  svg.addEventListener("pointerup", () => (drag = null));
  svg.addEventListener("pointercancel", () => (drag = null));
  const reset = () => {
    x = y = 0;
    scale = 1;
    apply();
  };
  svg.tabIndex = 0;
  svg.addEventListener("keydown", (e) => {
    if (e.target !== svg) return;
    if (e.key === "+") zoom(1.2);
    if (e.key === "-") zoom(0.8);
    if (e.key === "0") reset();
    if (e.key.startsWith("Arrow")) {
      e.preventDefault();
      x += e.key === "ArrowRight" ? -30 : e.key === "ArrowLeft" ? 30 : 0;
      y += e.key === "ArrowDown" ? -30 : e.key === "ArrowUp" ? 30 : 0;
      apply();
    }
  });
  return { zoom, reset };
}
function controls(svg, api, title) {
  const bar = document.createElement("div");
  bar.className = "chart-controls";
  bar.append(
    button("+", () => api.zoom(1.25)),
    button("−", () => api.zoom(0.8)),
    button("Ripristina", api.reset),
    button("SVG ↓", () =>
      download(
        title + ".svg",
        new XMLSerializer().serializeToString(svg),
        "image/svg+xml",
      ),
    ),
  );
  return bar;
}
function svgRoot(width, height, label, palette = PALETTES.forensic) {
  const svg = el("svg", {
    viewBox: `0 0 ${width} ${height}`,
    role: "img",
    "aria-label": label,
    xmlns: NS,
  });
  const bg = el("rect", { x: 0, y: 0, width: "100%", height: "100%", fill: palette.background });
  bg.setAttribute("opacity", "1");
  svg.append(bg);
  return svg;
}
export function renderGraph(container, data, options = {}) {
  container.replaceChildren();
  const palette = paletteFor(options.style || options.palette);
  const width = 1100,
    height = 450;
  const svg = svgRoot(
    width,
    height,
    "Grafo interattivo di esecuzione. Usa rotella o più e meno per lo zoom, trascina per spostare.", palette,
  );
  const group = el("g");
  svg.append(group);
  const defs = el("defs");
  const marker = el("marker", {
    id: "arrow-" + Math.random().toString(36).slice(2),
    viewBox: "0 0 10 10",
    refX: 9,
    refY: 5,
    markerWidth: 6,
    markerHeight: 6,
    orient: "auto-start-reverse",
  });
  marker.append(el("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: palette.secondary }));
  defs.append(marker);
  svg.append(defs);
  const all = data.nodes || [],
    allEdges = data.edges || [];
  const nodes = all.filter(
    (n) =>
      (!options.plugin ||
        n.plugin_id === options.plugin ||
        n.type === "asset") &&
      (!options.status || n.status === options.status) &&
      (options.phases !== false || n.type !== "phase"),
  );
  const ids = new Set(nodes.map((n) => n.id));
  const edges = allEdges.filter((e) => ids.has(e.source) && ids.has(e.target));
  const levels = new Map(nodes.map((n) => [n.id, 0]));
  for (let i = 0; i < Math.min(nodes.length, 30); i++) {
    let changed = false;
    for (const e of edges) {
      const d = Math.min(30, levels.get(e.source) + 1);
      if (d > levels.get(e.target)) {
        levels.set(e.target, d);
        changed = true;
      }
    }
    if (!changed) break;
  }
  const columns = new Map();
  for (const n of nodes) {
    const l = levels.get(n.id);
    if (!columns.has(l)) columns.set(l, []);
    columns.get(l).push(n);
  }
  const maxLevel = Math.max(1, ...levels.values());
  const maxRows = Math.max(1, ...[...columns.values()].map((v) => v.length));
  const graphWidth = Math.max(1050, (maxLevel + 1) * 210),
    graphHeight = Math.max(400, maxRows * 100);
  svg.setAttribute("viewBox", `0 0 ${graphWidth} ${graphHeight}`);
  const positions = new Map();
  for (const [l, column] of columns)
    column.forEach((n, i) =>
      positions.set(n.id, {
        x: 30 + l * 210,
        y: 25 + i * 100 + (graphHeight - column.length * 100) / 2,
      }),
    );
  const edgeNodes = [];
  for (const e of edges) {
    const a = positions.get(e.source),
      b = positions.get(e.target);
    const path = el("path", {
      d: `M ${a.x + 172} ${a.y + 27} C ${a.x + 195} ${a.y + 27},${b.x - 25} ${b.y + 27},${b.x} ${b.y + 27}`,
      fill: "none",
      stroke: palette.secondary,
      "stroke-opacity": ".35",
      "stroke-width": 1.3,
      "marker-end": `url(#${marker.id})`,
      "stroke-dasharray": e.type === "dependency" ? "4 4" : "",
    });
    path.append(el("title", {}, e.label || e.type || ""));
    group.append(path);
    edgeNodes.push([e, path]);
  }
  function select(n) {
    const ancestry = new Set([n.id]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const e of allEdges)
        if (ancestry.has(e.target) && !ancestry.has(e.source)) {
          ancestry.add(e.source);
          changed = true;
        }
    }
    for (const [e, p] of edgeNodes) {
      const active = ancestry.has(e.source) && ancestry.has(e.target);
      p.setAttribute("stroke-width", active ? "3" : "1");
      p.setAttribute("stroke-opacity", active ? "1" : ".15");
    }
    options.onSelect?.(n);
  }
  const statusSymbols = {
    completed: "✓",
    running: "◌",
    failed: "×",
    cancelled: "■",
    partial: "◐",
    skipped: "–",
    queued: "○",
  };
  for (const n of nodes) {
    const p = positions.get(n.id);
    const node = el("g", {
      transform: `translate(${p.x} ${p.y})`,
      class: "graph-node",
      tabindex: 0,
      role: "button",
      "aria-label": `${n.label}, ${n.status || ""}`,
    });
    let shape;
    const attr = {
      fill: palette.surface,
      stroke: n.status === "failed" ? palette.critical : n.status === "running" ? palette.secondary : palette.primary,
      "stroke-width": n.status === "running" ? 2.5 : 1.2,
      "stroke-dasharray": ["partial", "skipped", "cancelled"].includes(n.status)
        ? "5 3"
        : "",
    };
    if (n.type === "flag")
      shape = el("polygon", {
        points: "0,27 16,0 156,0 172,27 156,54 16,54",
        ...attr,
      });
    else
      shape = el("rect", {
        x: 0,
        y: 0,
        width: 172,
        height: 54,
        rx: n.type === "plugin" ? 12 : n.type === "phase" ? 22 : 0,
        ...attr,
      });
    node.append(
      shape,
      el(
        "text",
        { x: 12, y: 21, "font-size": 10, fill: palette.foreground },
        String(n.label).slice(0, 23),
      ),
      el(
        "text",
        { x: 12, y: 40, "font-size": 8, fill: palette.muted },
        `${statusSymbols[n.status] || "○"} ${n.status || ""} ${n.duration ? Number(n.duration).toFixed(2) + "s" : ""}`,
      ),
      el(
        "title",
        {},
        `${n.label}\n${n.type} · ${n.status || ""}\n${n.started_at || ""}`,
      ),
    );
    node.onclick = () => select(n);
    node.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        select(n);
      }
    };
    group.append(node);
  }
  if (!nodes.length)
    group.append(
      el(
        "text",
        { x: 40, y: 60, "font-size": 16, fill: palette.foreground },
        "Nessun nodo per i filtri selezionati.",
      ),
    );
  const api = interactive(svg, group, graphWidth, graphHeight);
  container.append(controls(svg, api, "execution-graph"), svg);
  return svg;
}
const number = (value, otherwise = 0) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : otherwise;
};
export function renderVisualization(container, spec, onSelect = () => {}) {
  const wrapper = document.createElement("div");
  wrapper.className = "chart";
  const palette = applyPalette(wrapper, spec.style || spec.palette);
  const title = document.createElement("h3");
  title.textContent = spec.title || spec.type;
  wrapper.append(title);
  container.append(wrapper);
  if (
    ["graph", "network_graph", "execution_graph", "tree"].includes(spec.type)
  ) {
    renderGraph(wrapper, spec.data, { onSelect, palette: spec.palette, style: spec.style });
    wrapper.prepend(title);
    return;
  }
  const W = 900,
    H = 300,
    margin = { l: 55, r: 25, t: 25, b: 40 },
    pw = W - margin.l - margin.r,
    ph = H - margin.t - margin.b;
  const svg = svgRoot(W, H, spec.title || spec.type, palette);
  const group = el("g");
  svg.append(group);
  const api = interactive(svg, group, W, H);
  const bar = controls(svg, api, spec.title || spec.type);
  const input = document.createElement("input");
  input.placeholder = "Filtrer les données";
  input.placeholder = "Filtra dati";
  input.setAttribute("aria-label", "Filtra i dati del grafico");
  const output = document.createElement("output");
  bar.append(input, output);
  wrapper.append(bar, svg);
  function draw() {
    group.replaceChildren();
    const query = input.value.toLowerCase();
    let data = (spec.data || []).filter(
      (d) => !query || JSON.stringify(d).toLowerCase().includes(query),
    );
    const type = spec.type;
    output.textContent = `${data.length} elementi${spec.inferred ? " · tipo inferito" : ""}`;
    if (!data.length) {
      group.append(
        el(
          "text",
          { x: 40, y: 60, fill: palette.foreground, "font-size": 14 },
          "Nessun dato disponibile",
        ),
      );
      return;
    }
    const xf = spec.encoding?.x?.field || "x",
      yf = spec.encoding?.y?.field || "y";
    if (type === "histogram" || type === "distribution") {
      const values = data.map((d) => number(typeof d === "object" ? d[xf] : d));
      const min = Math.min(...values),
        max = Math.max(...values),
        bins = Math.min(30, Math.max(1, Math.ceil(Math.sqrt(values.length))));
      const counts = Array(bins).fill(0);
      values.forEach(
        (v) =>
          counts[
            Math.min(
              bins - 1,
              Math.floor(((v - min) / (max - min || 1)) * bins),
            )
          ]++,
      );
      data = counts.map((n, i) => ({
        [xf]: min + ((max - min) * i) / bins,
        [yf]: n,
        label: `${(min + ((max - min) * i) / bins).toFixed(2)}`,
      }));
    }
    function mark(shape, d, i) {
      shape.dataset.index = i;
      shape.dataset.selectionKey = String(d?.id ?? d?.key ?? i);
      shape.append(el("title", {}, JSON.stringify(d)));
      shape.setAttribute("tabindex", "0");
      shape.setAttribute("role", "button");
      shape.setAttribute("aria-label", JSON.stringify(d));
      shape.style.cursor = "pointer";
      const select = () => {
        output.textContent = JSON.stringify(d);
        onSelect({ data: d, index: i, visualization: spec });
        wrapper.dispatchEvent(
          new CustomEvent("hub-select", {
            bubbles: true,
            detail: { data: d, index: i, visualization: spec },
          }),
        );
      };
      shape.onclick = select;
      shape.onkeydown = (e) => {
        if (e.key === "Enter") select();
      };
      group.append(shape);
    }
    if (["pie", "donut"].includes(type)) {
      const vals = data.map((d) => Math.max(0, number(d[yf] ?? d.value)));
      const total = vals.reduce((a, b) => a + b, 0);
      let angle = -Math.PI / 2;
      data.forEach((d, i) => {
        const fraction = vals[i] / (total || 1);
        const end = angle + fraction * Math.PI * 2;
        const cx = 270,
          cy = 150,
          r = 110;
        const defs = el("defs");
        const id = "pattern-" + Math.random().toString(36).slice(2);
        const pat = el("pattern", {
          id,
          width: 4 + i * 2,
          height: 4 + i * 2,
          patternUnits: "userSpaceOnUse",
          patternTransform: `rotate(${i * 23})`,
        });
        pat.append(
          el("rect", { width: 30, height: 30, fill: i % 2 ? palette.surface : palette.background }),
          el("path", {
            d: "M 0 0 L 0 30",
            stroke: i % 2 ? palette.primary : palette.secondary,
            "stroke-width": 1 + (i % 3),
          }),
        );
        defs.append(pat);
        svg.append(defs);
        const path =
          fraction >= 0.9999
            ? el("circle", { cx, cy, r, fill: `url(#${id})`, stroke: palette.foreground })
            : el("path", {
                d: `M ${cx} ${cy} L ${cx + r * Math.cos(angle)} ${cy + r * Math.sin(angle)} A ${r} ${r} 0 ${fraction > 0.5 ? 1 : 0} 1 ${cx + r * Math.cos(end)} ${cy + r * Math.sin(end)} Z`,
                fill: `url(#${id})`,
                stroke: palette.foreground,
              });
        mark(path, d, i);
        group.append(
          el(
            "text",
            { x: 460, y: 40 + i * 21, fill: palette.foreground, "font-size": 12 },
            `${d.label ?? d[xf] ?? i}: ${(fraction * 100).toFixed(1)}%`,
          ),
        );
        angle = end;
      });
      if (type === "donut")
        group.append(
          el("circle", {
            cx: 270,
            cy: 150,
            r: 58,
            fill: palette.background,
            stroke: palette.primary,
          }),
        );
      return;
    }
    if (["heatmap", "matrix", "hex_map", "byte_grid", "diff"].includes(type)) {
      let cells = [];
      if (Array.isArray(data[0]))
        data.forEach((row, y) =>
          row.forEach((v, x) => cells.push({ x, y, value: v })),
        );
      else
        cells = data.map((d, i) =>
          typeof d === "object"
            ? {
                ...d,
                x: d.x ?? i % 16,
                y: d.y ?? Math.floor(i / 16),
                value: d.value ?? d.byte ?? d.after ?? 0,
              }
            : { x: i % 16, y: Math.floor(i / 16), value: d },
        );
      const cols = Math.max(1, ...cells.map((c) => number(c.x) + 1)),
        rows = Math.max(1, ...cells.map((c) => number(c.y) + 1));
      const size = Math.min(45, pw / cols, ph / rows);
      const max = Math.max(1, ...cells.map((c) => number(c.value)));
      cells.forEach((c, i) => {
        const x = margin.l + number(c.x) * size,
          y = margin.t + number(c.y) * size;
        const changed = type === "diff" && c.before !== c.after;
        const opacity =
          type === "diff" ? (changed ? 1 : 0) : number(c.value) / max;
        mark(
          el("rect", {
            x,
            y,
            width: size - 1,
            height: size - 1,
            fill: changed ? palette.critical : palette.primary,
            "fill-opacity": opacity,
            stroke: palette.secondary,
            "stroke-width": 0.5,
            "stroke-dasharray": changed ? "3 2" : "",
          }),
          c,
          i,
        );
        if (size > 22)
          group.append(
            el(
              "text",
              {
                x: x + 3,
                y: y + size / 2 + 4,
                "font-size": 9,
                fill: opacity > 0.5 ? palette.background : palette.foreground,
              },
              type === "byte_grid" || type === "hex_map"
                ? number(c.value).toString(16).padStart(2, "0")
                : String(c.value).slice(0, 4),
            ),
          );
      });
      return;
    }
    const dated = type === "timeline";
    const xs = data.map((d, i) =>
      dated
        ? number(Date.parse(d.timestamp ?? d.start ?? d[xf]), i)
        : number(d[xf], i),
    );
    const ys = data.map((d) => number(d[yf] ?? d.value));
    let xmin = Math.min(...xs),
      xmax = Math.max(...xs),
      ymin = Math.min(0, ...ys),
      ymax = Math.max(1, ...ys);
    const sx = (v) => margin.l + ((v - xmin) / (xmax - xmin || 1)) * pw,
      sy = (v) => margin.t + ph - ((v - ymin) / (ymax - ymin || 1)) * ph;
    group.append(
      el("path", {
        d: `M ${margin.l} ${margin.t} V ${margin.t + ph} H ${W - margin.r}`,
        fill: "none",
        stroke: palette.foreground,
      }),
    );
    for (let i = 0; i <= 4; i++) {
      const v = ymin + ((ymax - ymin) * i) / 4,
        y = sy(v);
      group.append(
        el("line", {
          x1: margin.l,
          y1: y,
          x2: W - margin.r,
          y2: y,
          stroke: palette.muted,
          "stroke-opacity": ".12",
          "stroke-dasharray": "3 4",
        }),
        el(
          "text",
          {
            x: margin.l - 7,
            y: y + 4,
            "text-anchor": "end",
            "font-size": 9,
            fill: palette.foreground,
          },
          v.toFixed(ymax < 10 ? 1 : 0),
        ),
      );
    }
    if (["line", "area"].includes(type)) {
      const points = data.map((d, i) => `${sx(xs[i])},${sy(ys[i])}`);
      if (type === "area")
        group.append(
          el("polygon", {
            points: `${sx(xs[0])},${sy(0)} ${points.join(" ")} ${sx(xs.at(-1))},${sy(0)}`,
            fill: palette.primary,
            "fill-opacity": ".15",
          }),
        );
      group.append(
        el("polyline", {
          points: points.join(" "),
          fill: "none",
          stroke: palette.primary,
          "stroke-width": 2,
        }),
      );
      data.forEach((d, i) =>
        mark(
          el("circle", { cx: sx(xs[i]), cy: sy(ys[i]), r: 3, fill: palette.secondary }),
          d,
          i,
        ),
      );
    } else if (["scatter", "coordinates"].includes(type))
      data.forEach((d, i) =>
        mark(
          el("circle", {
            cx: sx(xs[i]),
            cy: sy(ys[i]),
            r: 4,
            fill: palette.surface,
            stroke: palette.primary,
            "stroke-width": 1.5,
          }),
          d,
          i,
        ),
      );
    else if (type === "timeline") {
      data.forEach((d, i) => {
        const y = margin.t + 20 + (i % 6) * 29,
          x = sx(xs[i]);
        group.append(
          el("line", {
            x1: x,
            y1: margin.t + ph,
            x2: x,
            y2: y,
            stroke: palette.secondary,
            "stroke-opacity": ".3",
            "stroke-dasharray": "2 3",
          }),
        );
        mark(
          el("circle", { cx: x, cy: y, r: 5, fill: palette.surface, stroke: palette.primary }),
          d,
          i,
        );
        group.append(
          el(
            "text",
            { x: x + 8, y: y + 4, "font-size": 9, fill: palette.foreground },
            String(d.label ?? d.event ?? d.title ?? "Evento").slice(0, 28),
          ),
        );
      });
    } else if (type === "offset_map") {
      const maxEnd = Math.max(
        1,
        ...data.map((d, i) => xs[i] + Math.max(0, ys[i])),
      );
      data.forEach((d, i) => {
        const x = margin.l + (xs[i] / maxEnd) * pw,
          w = Math.max(2, (ys[i] / maxEnd) * pw),
          y = margin.t + (i % 6) * 34;
        mark(
          el("rect", {
            x,
            y,
            width: w,
            height: 24,
            fill: i % 2 ? palette.primary : palette.surface,
            stroke: palette.secondary,
          }),
          d,
          i,
        );
      });
    } else {
      const bw = pw / data.length;
      data.forEach((d, i) => {
        const y = sy(ys[i]),
          zero = sy(0);
        mark(
          el("rect", {
            x: margin.l + i * bw + 1,
            y: Math.min(y, zero),
            width: Math.max(0.5, bw - 2),
            height: Math.max(1, Math.abs(zero - y)),
            fill: i % 2 && type === "comparison" ? palette.secondary : palette.primary,
            stroke: palette.foreground,
            "stroke-width": 0.5,
          }),
          d,
          i,
        );
      });
    }
    for (let i = 0; i < Math.min(6, data.length); i++) {
      const idx = Math.min(
        data.length - 1,
        Math.floor(
          (i * (data.length - 1)) / Math.max(1, Math.min(6, data.length) - 1),
        ),
      );
      const label = dated
        ? new Date(xs[idx]).toISOString().slice(0, 10)
        : String(data[idx].label ?? data[idx][xf] ?? idx).slice(0, 16);
      group.append(
        el(
          "text",
          {
            x: margin.l + (i / Math.max(1, Math.min(6, data.length) - 1)) * pw,
            y: H - 12,
            "font-size": 9,
            fill: palette.foreground,
            "text-anchor": "middle",
          },
          label,
        ),
      );
    }
  }
  input.oninput = draw;
  draw();
}
