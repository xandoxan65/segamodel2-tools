const BANK_VADDRS = ["0x02200000", "0x02400000"];
const SHEET_IMAGES = [
  "/api/sheet/0/logical.png",
  "/api/sheet/1/logical.png",
];

const state = {
  catalog: null,
  sheetIndex: 0,
  regions: [],
  selectedId: null,
  image: null,
  zoom: 0.5,
  panX: 20,
  panY: 20,
  drawing: false,
  drawStart: null,
  draftRect: null,
  panning: false,
  panStart: null,
  snap32: true,
  viewMode: "logical",
  audit: { available: false, by_id: {}, by_rect: {} },
};

let paletteReloadTimer = null;

const canvas = document.getElementById("atlas-canvas");
const ctx = canvas.getContext("2d");
const wrap = document.getElementById("canvas-wrap");
const viewport = document.getElementById("viewport");
const hud = document.getElementById("hud");
const statusEl = document.getElementById("status");
const regionList = document.getElementById("region-list");

const fields = {
  id: document.getElementById("field-id"),
  label: document.getElementById("field-label"),
  x: document.getElementById("field-x"),
  y: document.getElementById("field-y"),
  w: document.getElementById("field-w"),
  h: document.getElementById("field-h"),
  colorbase: document.getElementById("field-cb"),
  lumabase: document.getElementById("field-lb"),
  source: document.getElementById("field-source"),
  notes: document.getElementById("field-notes"),
  cutout: document.getElementById("field-cutout"),
  checker: document.getElementById("field-checker"),
};

function setStatus(msg, ok = true) {
  statusEl.textContent = msg;
  statusEl.style.color = ok ? "#8c8" : "#c88";
}

function snap(v) {
  return state.snap32 ? Math.round(v / 32) * 32 : Math.round(v);
}

function clampRect(x, y, w, h) {
  const img = state.image;
  if (!img) return { x, y, w, h };
  let nx = Math.max(0, Math.min(x, img.width - 1));
  let ny = Math.max(0, Math.min(y, img.height - 1));
  let nw = Math.max(1, w);
  let nh = Math.max(1, h);
  if (nx + nw > img.width) nw = img.width - nx;
  if (ny + nh > img.height) nh = img.height - ny;
  if (state.snap32) {
    nx = snap(nx);
    ny = snap(ny);
    nw = Math.max(32, snap(nw));
    nh = Math.max(32, snap(nh));
    if (nx + nw > img.width) nw = img.width - nx;
    if (ny + nh > img.height) nh = img.height - ny;
  }
  return { x: nx, y: ny, w: nw, h: nh };
}

function defaultId(r) {
  return `manual_s${state.sheetIndex}_x${r.x}_y${r.y}_w${r.w}_h${r.h}`;
}

function screenToAtlas(clientX, clientY) {
  const rect = viewport.getBoundingClientRect();
  const sx = clientX - rect.left;
  const sy = clientY - rect.top;
  return {
    x: (sx - state.panX) / state.zoom,
    y: (sy - state.panY) / state.zoom,
  };
}

function applyTransform() {
  wrap.style.transform = `translate(${state.panX}px, ${state.panY}px) scale(${state.zoom})`;
}

function currentBankRegions() {
  const bank = state.catalog?.banks?.[state.sheetIndex];
  return bank?.regions ?? [];
}

function syncRegionsFromCatalog() {
  state.regions = currentBankRegions();
}

function findRegion(id) {
  return state.regions.find((r) => r.id === id) ?? null;
}

function formatPalette(region) {
  if (!region) return null;
  const cb = region.colorbase;
  const lb = region.lumabase;
  if (cb == null && lb == null) return null;
  const parts = [];
  if (cb != null) parts.push(`cb${cb}`);
  if (lb != null) parts.push(`lb${lb}`);
  return parts.join(" ");
}

function formatPaletteDetail(region) {
  return formatPalette(region) ?? "no cb/lb";
}

function auditRectKey(region) {
  const sheet = region.sheet_index ?? state.sheetIndex;
  return `s${sheet}_x${region.x}_y${region.y}_w${region.w}_h${region.h}`;
}

function getAuditForRegion(region, sheetIndex = state.sheetIndex) {
  if (!region || !state.audit?.available) return null;
  const withSheet = { ...region, sheet_index: region.sheet_index ?? sheetIndex };
  return (
    state.audit.by_id?.[region.id] ??
    state.audit.by_rect?.[auditRectKey(withSheet)] ??
    null
  );
}

function updateAuditStatus() {
  const el = document.getElementById("audit-status");
  if (!state.audit?.available) {
    el.className = "audit-status err";
    el.textContent =
      state.audit?.hint ??
      "Audit not loaded — click Refresh audit (restart tagger if that fails)";
    return;
  }
  el.className = "audit-status ok";
  const n = Object.keys(state.audit.by_id ?? {}).length;
  const when = state.audit.generated_at
    ? ` · ${String(state.audit.generated_at).slice(0, 19)}`
    : "";
  el.textContent = `Audit loaded: ${state.audit.course_id ?? "desert"} · ${n} regions${when}`;
}

function updateAuditPanel(region) {
  const panel = document.getElementById("audit-panel");
  const text = document.getElementById("audit-panel-text");
  const wrap = document.getElementById("audit-binding-wrap");
  const select = document.getElementById("audit-binding-select");
  const btn = document.getElementById("btn-apply-audit");

  if (!state.audit?.available) {
    panel.hidden = false;
    text.className = "audit-panel-text muted";
    text.textContent =
      state.audit?.hint ??
      "Audit not loaded — use Refresh audit above";
    wrap.hidden = true;
    btn.hidden = true;
    return;
  }

  const audit = getAuditForRegion(region);
  if (!region || !audit) {
    panel.hidden = true;
    return;
  }

  panel.hidden = false;
  btn.hidden = false;
  const hits = audit.placement_hits ?? 0;
  if (hits === 0) {
    text.className = "audit-panel-text muted";
    text.textContent =
      "Audit: no placement-stream polys for this rect (menu / other draw path).";
    wrap.hidden = true;
    btn.hidden = true;
    return;
  }

  text.className = "audit-panel-text";
  const bindings = audit.bindings ?? [];
  if (bindings.length <= 1) {
    wrap.hidden = true;
    const cb = audit.suggested_colorbase;
    const lb = audit.suggested_lumabase;
    let msg = `Audit (${hits} polys): cb${cb} lb${lb}`;
    if ((audit.binding_count ?? 0) > 1) {
      msg += ` — ${audit.binding_count} bindings share this rect`;
    }
    text.textContent = msg;
  } else {
    text.textContent = `Audit: ${hits} polys · ${bindings.length} bindings (conflict)`;
    text.title =
      "Each binding is the colorbase/lumabase from textures ROM texheader word3 " +
      "(per polygon draw), not guessed. This rect is shared by multiple bindings — " +
      "preview one binding at a time. Wrong hues usually mean palram slot contents " +
      "(CGM replay) are still incomplete for that colorbase.";
    wrap.hidden = false;
    select.innerHTML = "";
    for (const b of bindings) {
      const opt = document.createElement("option");
      opt.value = String(bindings.indexOf(b));
      opt.textContent = formatBindingLabel(b);
      select.appendChild(opt);
    }
  }
}

function applyAuditSuggestion() {
  const region = findRegion(state.selectedId);
  const audit = getAuditForRegion(region);
  if (!audit || !audit.placement_hits) return;
  const bindings = audit.bindings ?? [];
  let binding = bindings[0];
  const select = document.getElementById("audit-binding-select");
  if (bindings.length > 1 && select.value !== "") {
    binding = bindings[Number(select.value)];
  }
  if (!binding) return;
  fields.colorbase.value = binding.colorbase;
  fields.lumabase.value = binding.lumabase;
  fields.cutout.checked = Boolean(binding.cutout);
  fields.checker.checked = Boolean(binding.checker);
  applyFormToSelected();
  setStatus(`Applied audit palette cb${binding.colorbase} lb${binding.lumabase}`);
  enablePalettePreview();
}

function formatBindingLabel(b) {
  let s = `cb${b.colorbase} lb${b.lumabase}`;
  if (b.cutout) s += " cutout";
  if (b.checker) s += " checker";
  if (b.poly_count != null) s += ` (${b.poly_count} polys)`;
  return s;
}

async function refreshAudit(runBuild = false) {
  const status = document.getElementById("audit-status");
  status.className = "audit-status";
  status.textContent = runBuild ? "Running polygon audit (~15s)…" : "Loading audit…";
  try {
    if (runBuild) {
      const res = await fetch("/api/audit/refresh", { method: "POST" });
      const body = await res.json();
      if (!res.ok || !body.ok) {
        throw new Error(body.error || `refresh failed (${res.status})`);
      }
      state.audit = body;
    } else {
      await loadAudit();
    }
    updateAuditStatus();
    renderRegionList();
    if (state.selectedId) {
      fillForm(findRegion(state.selectedId));
    } else {
      updateAuditPanel(null);
    }
    setStatus(
      state.audit?.available
        ? `Audit loaded (${Object.keys(state.audit.by_id ?? {}).length} regions)`
        : "Audit unavailable",
      Boolean(state.audit?.available),
    );
  } catch (err) {
    state.audit = {
      available: false,
      by_id: {},
      by_rect: {},
      hint: String(err.message || err),
    };
    updateAuditStatus();
    setStatus(String(err.message || err), false);
  }
}

function applyAuditToCatalog() {
  if (!state.audit?.available) {
    setStatus("Load audit first (Refresh audit)", false);
    return;
  }
  let applied = 0;
  let skipped = 0;
  for (const bank of state.catalog.banks) {
    const sheetIndex = Number(bank.sheet_index);
    for (const region of bank.regions) {
      const audit = getAuditForRegion(region, sheetIndex);
      if (!audit?.placement_hits || !audit.bindings?.length) {
        skipped += 1;
        continue;
      }
      const binding = audit.bindings[0];
      region.colorbase = binding.colorbase;
      region.lumabase = binding.lumabase;
      region.cutout = Boolean(binding.cutout);
      region.checker = Boolean(binding.checker);
      applied += 1;
    }
  }
  syncRegionsFromCatalog();
  renderRegionList();
  if (state.selectedId) fillForm(findRegion(state.selectedId));
  enablePalettePreview();
  setStatus(
    `Applied audit palette to ${applied} regions (${skipped} skipped, no placement hits) — Save catalog`,
  );
}

function fillForm(region) {
  if (!region) {
    fields.id.value = "";
    fields.label.value = "";
    fields.x.value = "";
    fields.y.value = "";
    fields.w.value = "";
    fields.h.value = "";
    fields.colorbase.value = "";
    fields.lumabase.value = "";
    fields.source.value = "manual";
    fields.notes.value = "";
    fields.cutout.checked = false;
    fields.checker.checked = false;
    const badge = document.getElementById("palette-badge");
    badge.hidden = true;
    badge.textContent = "";
    updateAuditPanel(null);
    return;
  }
  fields.id.value = region.id ?? "";
  fields.label.value = region.label ?? "";
  fields.x.value = region.x;
  fields.y.value = region.y;
  fields.w.value = region.w;
  fields.h.value = region.h;
  fields.colorbase.value = region.colorbase ?? "";
  fields.lumabase.value = region.lumabase ?? "";
  fields.source.value = region.source ?? "manual";
  fields.notes.value = region.notes ?? "";
  fields.cutout.checked = Boolean(region.cutout);
  fields.checker.checked = Boolean(region.checker);
  const badge = document.getElementById("palette-badge");
  const pal = formatPalette(region);
  badge.hidden = false;
  badge.textContent = pal ?? "no cb/lb";
  badge.className = pal ? "palette-badge has-pal" : "palette-badge no-pal";
  updateAuditPanel(region);
}

function readFormRect() {
  const x = Number(fields.x.value);
  const y = Number(fields.y.value);
  const w = Number(fields.w.value);
  const h = Number(fields.h.value);
  if (![x, y, w, h].every(Number.isFinite)) return null;
  return clampRect(x, y, w, h);
}

function renderRegionList() {
  regionList.innerHTML = "";
  const sorted = [...state.regions].sort((a, b) => a.y - b.y || a.x - b.x);
  for (const r of sorted) {
    const li = document.createElement("li");
    li.className = r.id === state.selectedId ? "active" : "";
    const title = r.label || r.id;
    const pal = formatPalette(r);
    const palHtml = pal
      ? `<div class="meta pal">${pal}</div>`
      : `<div class="meta pal muted">no cb/lb</div>`;
    const audit = getAuditForRegion(r);
    let auditHtml = "";
    if (audit?.placement_hits > 0 && audit.suggested_colorbase != null) {
      const conflict = (audit.binding_count ?? 1) > 1 ? " · conflict" : "";
      auditHtml = `<div class="meta audit">audit cb${audit.suggested_colorbase} lb${audit.suggested_lumabase}${conflict}</div>`;
    }
    li.innerHTML = `<div>${title}</div><div class="meta">(${r.x},${r.y}) ${r.w}×${r.h}</div>${palHtml}${auditHtml}`;
    li.addEventListener("click", () => selectRegion(r.id));
    regionList.appendChild(li);
  }
}

function draw() {
  const img = state.image;
  if (!img) return;
  canvas.width = img.width;
  canvas.height = img.height;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0);

  for (const r of state.regions) {
    const selected = r.id === state.selectedId;
    ctx.strokeStyle = selected ? "#4af" : r.source === "manual" ? "#fa4" : "#4f4";
    ctx.lineWidth = selected ? 2 : 1;
    ctx.strokeRect(r.x + 0.5, r.y + 0.5, r.w, r.h);
    if (selected) {
      ctx.fillStyle = "rgba(68, 170, 255, 0.12)";
      ctx.fillRect(r.x, r.y, r.w, r.h);
    }
    const tag = r.label || r.id;
    const pal = formatPalette(r);
    const palLine = selected || pal ? (pal ?? "no cb/lb") : null;
    const lineCount = palLine ? 2 : 1;
    const boxH = 14 * lineCount + 2;
    ctx.fillStyle = "rgba(0,0,0,0.65)";
    ctx.fillRect(r.x, r.y, Math.min(r.w, Math.max(tag.length * 6 + 8, palLine ? palLine.length * 6 + 8 : 0)), boxH);
    ctx.fillStyle = "#fff";
    ctx.font = "11px system-ui";
    ctx.fillText(tag.slice(0, 28), r.x + 3, r.y + 11);
    if (palLine) {
      ctx.fillStyle = pal ? "#9cf" : "#888";
      ctx.font = "10px ui-monospace, monospace";
      ctx.fillText(palLine, r.x + 3, r.y + 23);
    }
  }

  const draft = state.draftRect;
  if (draft) {
    ctx.strokeStyle = "#fff";
    ctx.setLineDash([4, 3]);
    ctx.strokeRect(draft.x + 0.5, draft.y + 0.5, draft.w, draft.h);
    ctx.setLineDash([]);
  }

  const sel = findRegion(state.selectedId);
  const palHud = sel ? ` · ${formatPaletteDetail(sel)}` : "";
  hud.textContent = `sheet ${state.sheetIndex} · zoom ${(state.zoom * 100).toFixed(0)}% · ${img.width}×${img.height}${sel ? ` · ${sel.label || sel.id}${palHud}` : ""}`;
}

function selectRegion(id) {
  state.selectedId = id;
  fillForm(findRegion(id));
  renderRegionList();
  draw();
  schedulePaletteReload();
}

async function loadAudit() {
  try {
    const res = await fetch(`/api/audit?t=${Date.now()}`);
    if (!res.ok) {
      state.audit = {
        available: false,
        by_id: {},
        by_rect: {},
        hint: `Audit API HTTP ${res.status} — restart tagger: python3 -m tools.extract.atlas_tagger`,
      };
      return;
    }
    state.audit = await res.json();
  } catch (err) {
    state.audit = {
      available: false,
      by_id: {},
      by_rect: {},
      hint: `Audit fetch failed: ${err.message}`,
    };
  }
}

async function loadCatalog() {
  const res = await fetch("/api/catalog");
  if (!res.ok) throw new Error("Failed to load catalog");
  state.catalog = await res.json();
  syncRegionsFromCatalog();
  renderRegionList();
  if (state.selectedId && !findRegion(state.selectedId)) {
    state.selectedId = null;
    fillForm(null);
  }
  draw();
}

async function reloadSheetImage() {
  const img = new Image();
  img.src = sheetImageUrl();
  await new Promise((resolve, reject) => {
    img.onload = resolve;
    img.onerror = () => reject(new Error(`Sheet ${state.sheetIndex} image failed to load`));
  });
  state.image = img;
  draw();
}

async function loadSheet(index) {
  state.sheetIndex = index;
  document.getElementById("sheet-select").value = String(index);
  syncRegionsFromCatalog();
  state.selectedId = null;
  fillForm(null);
  renderRegionList();
  await reloadSheetImage();
}

function sheetImageUrl() {
  if (state.viewMode === "palette") {
    const params = new URLSearchParams();
    if (document.getElementById("palette-selected-only").checked) {
      params.set("selected_only", "1");
    }
    const cb = fields.colorbase.value.trim();
    if (cb !== "") {
      const rect = readFormRect();
      if (rect) {
        params.set("overlay_x", String(rect.x));
        params.set("overlay_y", String(rect.y));
        params.set("overlay_w", String(rect.w));
        params.set("overlay_h", String(rect.h));
        params.set("overlay_cb", cb);
        const lb = fields.lumabase.value.trim();
        params.set("overlay_lb", lb === "" ? "0" : lb);
        params.set("overlay_cutout", fields.cutout.checked ? "1" : "0");
        params.set("overlay_checker", fields.checker.checked ? "1" : "0");
      }
    }
    params.set("t", String(Date.now()));
    return `/api/sheet/${state.sheetIndex}/palette.png?${params}`;
  }
  return `${SHEET_IMAGES[state.sheetIndex]}?t=${Date.now()}`;
}

function enablePalettePreview() {
  const toggle = document.getElementById("show-palette");
  if (!toggle.checked) {
    toggle.checked = true;
    state.viewMode = "palette";
    reloadSheetImage().catch((err) => setStatus(err.message, false));
    return;
  }
  schedulePaletteReload();
}

function schedulePaletteReload() {
  if (state.viewMode !== "palette") return;
  clearTimeout(paletteReloadTimer);
  paletteReloadTimer = setTimeout(() => {
    reloadSheetImage().catch((err) => setStatus(err.message, false));
  }, 350);
}

async function saveCatalog() {
  const res = await fetch("/api/catalog", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(state.catalog, null, 2),
  });
  if (!res.ok) throw new Error(await res.text());
  setStatus("Saved catalog/atlas_regions.json");
}

function upsertRegion(region) {
  const bank = state.catalog.banks[state.sheetIndex];
  const idx = bank.regions.findIndex((r) => r.id === region.id);
  if (idx >= 0) bank.regions[idx] = region;
  else bank.regions.push(region);
  syncRegionsFromCatalog();
}

function applyFormToSelected() {
  const rect = readFormRect();
  if (!rect) {
    setStatus("Invalid rectangle fields", false);
    return;
  }
  let id = fields.id.value.trim();
  if (!id) id = defaultId(rect);
  const region = {
    id,
    label: fields.label.value.trim() || null,
    x: rect.x,
    y: rect.y,
    w: rect.w,
    h: rect.h,
    source: fields.source.value || "manual",
    cutout: fields.cutout.checked,
    checker: fields.checker.checked,
    notes: fields.notes.value.trim() || undefined,
  };
  const cb = fields.colorbase.value.trim();
  const lb = fields.lumabase.value.trim();
  region.colorbase = cb === "" ? null : Number(cb);
  region.lumabase = lb === "" ? null : Number(lb);
  if (region.notes === undefined) delete region.notes;

  if (state.selectedId && state.selectedId !== id) {
    const bank = state.catalog.banks[state.sheetIndex];
    bank.regions = bank.regions.filter((r) => r.id !== state.selectedId);
  }
  upsertRegion(region);
  state.selectedId = id;
  fillForm(region);
  renderRegionList();
  draw();
  setStatus(`Updated ${id}`);
  if (region.colorbase != null) {
    enablePalettePreview();
  }
}

function deleteSelected() {
  if (!state.selectedId) return;
  const id = state.selectedId;
  const bank = state.catalog.banks[state.sheetIndex];
  bank.regions = bank.regions.filter((r) => r.id !== id);
  state.selectedId = null;
  fillForm(null);
  syncRegionsFromCatalog();
  renderRegionList();
  draw();
  setStatus(`Deleted ${id}`);
}

function newFromDraft() {
  if (!state.draftRect) return;
  const rect = state.draftRect;
  state.draftRect = null;
  const region = {
    id: defaultId(rect),
    label: null,
    ...rect,
    source: "manual",
    colorbase: null,
    lumabase: null,
    cutout: false,
    checker: false,
  };
  upsertRegion(region);
  state.selectedId = region.id;
  fillForm(region);
  renderRegionList();
  draw();
  setStatus(`Created ${region.id} — add label and Save`);
}

function regionAt(px, py) {
  for (const r of [...state.regions].reverse()) {
    if (px >= r.x && px < r.x + r.w && py >= r.y && py < r.y + r.h) return r;
  }
  return null;
}

viewport.addEventListener("mousedown", (e) => {
  if (e.button === 1 || (e.button === 0 && e.altKey)) {
    state.panning = true;
    state.panStart = { x: e.clientX - state.panX, y: e.clientY - state.panY };
    viewport.classList.add("panning");
    e.preventDefault();
    return;
  }
  if (e.button !== 0) return;
  const p = screenToAtlas(e.clientX, e.clientY);
  const hit = regionAt(p.x, p.y);
  if (hit && !e.shiftKey) {
    selectRegion(hit.id);
    state.drawing = false;
    state.drawStart = null;
    state.draftRect = null;
    return;
  }
  state.drawing = true;
  state.drawStart = p;
  state.draftRect = null;
});

window.addEventListener("mousemove", (e) => {
  if (state.panning && state.panStart) {
    state.panX = e.clientX - state.panStart.x;
    state.panY = e.clientY - state.panStart.y;
    applyTransform();
    return;
  }
  if (!state.drawing || !state.drawStart) return;
  const p = screenToAtlas(e.clientX, e.clientY);
  const x = Math.min(state.drawStart.x, p.x);
  const y = Math.min(state.drawStart.y, p.y);
  const w = Math.abs(p.x - state.drawStart.x);
  const h = Math.abs(p.y - state.drawStart.y);
  state.draftRect = clampRect(x, y, w, h);
  draw();
});

window.addEventListener("mouseup", () => {
  if (state.panning) {
    state.panning = false;
    state.panStart = null;
    viewport.classList.remove("panning");
  }
  if (state.drawing) {
    state.drawing = false;
    if (state.draftRect && state.draftRect.w >= 4 && state.draftRect.h >= 4) {
      newFromDraft();
    } else {
      state.draftRect = null;
      draw();
    }
  }
});

viewport.addEventListener("wheel", (e) => {
  e.preventDefault();
  const factor = e.deltaY < 0 ? 1.1 : 0.9;
  const before = screenToAtlas(e.clientX, e.clientY);
  state.zoom = Math.min(4, Math.max(0.05, state.zoom * factor));
  const after = screenToAtlas(e.clientX, e.clientY);
  state.panX += (after.x - before.x) * state.zoom;
  state.panY += (after.y - before.y) * state.zoom;
  applyTransform();
  draw();
}, { passive: false });

document.getElementById("sheet-select").addEventListener("change", (e) => {
  loadSheet(Number(e.target.value)).catch((err) => setStatus(err.message, false));
});

document.getElementById("snap32").addEventListener("change", (e) => {
  state.snap32 = e.target.checked;
});

document.getElementById("show-palette").addEventListener("change", (e) => {
  state.viewMode = e.target.checked ? "palette" : "logical";
  reloadSheetImage().catch((err) => setStatus(err.message, false));
});

document.getElementById("palette-selected-only").addEventListener("change", () => {
  if (state.viewMode === "palette") {
    reloadSheetImage().catch((err) => setStatus(err.message, false));
  }
});

for (const id of ["field-cb", "field-lb", "field-cutout", "field-checker"]) {
  document.getElementById(id).addEventListener("input", schedulePaletteReload);
  document.getElementById(id).addEventListener("change", schedulePaletteReload);
}

document.getElementById("btn-audit-refresh").addEventListener("click", () => {
  refreshAudit(true).catch((err) => setStatus(err.message, false));
});
document.getElementById("btn-audit-catalog").addEventListener("click", applyAuditToCatalog);
document.getElementById("btn-apply-audit").addEventListener("click", applyAuditSuggestion);
document.getElementById("btn-apply").addEventListener("click", applyFormToSelected);
document.getElementById("btn-save").addEventListener("click", () => {
  saveCatalog().catch((err) => setStatus(err.message, false));
});
document.getElementById("btn-delete").addEventListener("click", deleteSelected);
document.getElementById("btn-clear-draft").addEventListener("click", () => {
  state.draftRect = null;
  draw();
});

async function init() {
  applyTransform();
  await Promise.all([loadCatalog(), loadAudit()]);
  updateAuditStatus();
  await loadSheet(0);
  renderRegionList();
  setStatus("Drag on atlas · Alt+drag pan · wheel zoom · use Refresh audit if panel is empty");
}

init().catch((err) => setStatus(err.message, false));
