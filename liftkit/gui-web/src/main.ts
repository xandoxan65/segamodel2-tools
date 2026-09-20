import "./style.css";
import {
  FunctionDetail,
  FunctionRow,
  ProjectSummary,
  getFunction,
  getStatus,
  initProject,
  listFunctions,
  openProject,
  postLift,
  postRewrite,
} from "./api";

const app = document.querySelector<HTMLDivElement>("#app")!;

app.innerHTML = `
  <div class="topbar">
    <h1>liftkit</h1>
    <div class="grow">
      <input id="projectPath" placeholder="/path/to/decomp or lift project"/>
    </div>
    <button class="small" id="openBtn" type="button">Open</button>
    <button class="small secondary" id="initBtn" type="button">Init</button>
    <select id="arch" style="width:auto;min-width:6rem"></select>
  </div>
  <div class="layout">
    <aside class="sidebar">
      <div class="stats" id="stats"></div>
      <div class="filter-row">
        <label style="margin:0">Status
          <select id="statusFilter">
            <option value="">all</option>
            <option value="curated">curated</option>
            <option value="scaffold">scaffold</option>
            <option value="semantic_draft">semantic draft</option>
            <option value="not_lifted">not lifted</option>
            <option value="missing_slice">missing slice</option>
          </select>
        </label>
        <label style="margin:0">Search
          <input id="search" placeholder="name / addr"/>
        </label>
      </div>
      <div class="fn-list" id="fnList"></div>
      <p class="muted" id="fnCount"></p>
      <h3 style="margin-top:0.75rem;font-size:0.8rem;color:var(--muted)">Recent</h3>
      <div class="recent" id="recent"></div>
    </aside>
    <main class="main" id="main">
      <div class="empty">Open a project, then select a function from the catalog.</div>
    </main>
  </div>
`;

const projectPathEl = document.querySelector<HTMLInputElement>("#projectPath")!;
const archEl = document.querySelector<HTMLSelectElement>("#arch")!;
const statusFilter = document.querySelector<HTMLSelectElement>("#statusFilter")!;
const searchEl = document.querySelector<HTMLInputElement>("#search")!;
const fnListEl = document.querySelector<HTMLDivElement>("#fnList")!;
const fnCountEl = document.querySelector<HTMLParagraphElement>("#fnCount")!;
const statsEl = document.querySelector<HTMLDivElement>("#stats")!;
const recentEl = document.querySelector<HTMLDivElement>("#recent")!;
const mainEl = document.querySelector<HTMLElement>("#main")!;

let summary: ProjectSummary | null = null;
let functions: FunctionRow[] = [];
let selected: string | null = null;
let detail: FunctionDetail | null = null;
let viewTab: "curated" | "scaffold" | "semantic" | "lifted" | "ir" | "slice" | "meta" = "curated";
let lastMeta = "";

function hex(n: number): string {
  return "0x" + n.toString(16);
}

function renderStats(s: ProjectSummary) {
  statsEl.innerHTML = `
    <div class="stat"><b>${s.functions_total}</b><span>symbols</span></div>
    <div class="stat"><b>${s.with_slice}</b><span>sliced</span></div>
    <div class="stat"><b>${s.scaffolded}</b><span>lifted</span></div>
    <div class="stat"><b>${s.curated}</b><span>curated</span></div>
  `;
}

function renderRecent(items: { path: string; exists: boolean; name: string }[]) {
  recentEl.innerHTML = "";
  for (const item of items.slice(0, 6)) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "small secondary";
    b.textContent = item.name;
    b.title = item.path;
    b.disabled = !item.exists;
    b.addEventListener("click", () => {
      projectPathEl.value = item.path;
      void doOpen(item.path);
    });
    recentEl.appendChild(b);
  }
}

function renderFnList() {
  fnListEl.innerHTML = "";
  for (const fn of functions) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "fn-item" + (fn.name === selected ? " active" : "");
    b.innerHTML = `
      <div>${fn.name}</div>
      <div class="meta">
        <span>${hex(fn.address)}${fn.length != null ? ` +${hex(fn.length)}` : ""}</span>
        <span class="badge ${fn.status}">${fn.status.replace("_", " ")}</span>
      </div>
    `;
    b.addEventListener("click", () => void selectFunction(fn.name));
    fnListEl.appendChild(b);
  }
  fnCountEl.textContent = `${functions.length} function(s)`;
}

function pickDefaultTab(d: FunctionDetail): typeof viewTab {
  if (d.texts.curated) return "curated";
  if (d.texts.semantic) return "semantic";
  if (d.texts.scaffold) return "scaffold";
  if (d.texts.lifted) return "lifted";
  if (d.texts.slice) return "slice";
  return "meta";
}

function renderWorkbench() {
  if (!detail) {
    mainEl.innerHTML = `<div class="empty">Select a function from the catalog.</div>`;
    return;
  }
  const f = detail.function;
  const tabs: { id: typeof viewTab; label: string; ok: boolean }[] = [
    { id: "curated", label: "Curated C", ok: !!detail.texts.curated },
    { id: "scaffold", label: "Scaffold", ok: !!detail.texts.scaffold },
    { id: "semantic", label: "AI draft", ok: !!detail.texts.semantic },
    { id: "lifted", label: "Lifted text", ok: !!detail.texts.lifted },
    { id: "ir", label: "IR", ok: !!detail.texts.ir },
    { id: "slice", label: "Asm", ok: !!detail.texts.slice },
    { id: "meta", label: "Meta", ok: true },
  ];

  let body = "";
  if (viewTab === "meta") {
    body = lastMeta || JSON.stringify({ function: f, paths: detail.paths }, null, 2);
  } else if (viewTab === "ir") {
    body = detail.texts.ir || "(no IR yet — lift first)";
  } else {
    body = detail.texts[viewTab] || `(no ${viewTab} artifact yet)`;
  }

  mainEl.innerHTML = `
    <section class="panel">
      <h2>${f.name}</h2>
      <p class="muted">${hex(f.address)}${f.length != null ? ` + ${hex(f.length)}` : ""} · ${f.section || "no section"} · <span class="badge ${f.status}">${f.status}</span></p>
      <p class="muted">${f.slice_path ? `slice: ${f.slice_path}` : "no disasm slice on disk"} · src: ${f.src_dir}</p>
      <div class="row-actions">
        <button type="button" id="liftFnBtn">Lift / re-lift</button>
        <button type="button" class="secondary" id="rwDraftBtn">AI rewrite draft</button>
        <button type="button" class="secondary" id="rwApplyBtn">AI rewrite + apply</button>
      </div>
      <label>AI provider
        <select id="provider">
          <option value="echo">echo (offline)</option>
          <option value="openai">openai (LIFTKIT_API_KEY)</option>
        </select>
      </label>
      <p class="error" id="workErr"></p>
    </section>
    <section class="panel">
      <div class="tabs" id="tabs"></div>
      <pre id="out"></pre>
    </section>
    <section class="panel">
      <h2>One-shot tools</h2>
      <p class="muted">For slices not yet in the symbol catalog.</p>
      <label>Slice path <input id="slice" placeholder="disasm/maincpu/maincpu_….asm"/></label>
      <label>Or address + length
        <div class="filter-row">
          <input id="address" placeholder="0x5daa0"/>
          <input id="length" placeholder="0x140"/>
        </div>
      </label>
      <label>Name <input id="oneshotName" placeholder="optional name"/></label>
      <button type="button" id="oneshotLift" class="secondary">Lift one-shot</button>
      <p class="error" id="oneshotErr"></p>
    </section>
  `;

  const tabsEl = mainEl.querySelector("#tabs")!;
  for (const t of tabs) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = t.label + (t.ok ? "" : " ·");
    b.className = t.id === viewTab ? "active" : "";
    b.addEventListener("click", () => {
      viewTab = t.id;
      renderWorkbench();
    });
    tabsEl.appendChild(b);
  }
  mainEl.querySelector("#out")!.textContent = body;

  mainEl.querySelector("#liftFnBtn")!.addEventListener("click", async () => {
    const err = mainEl.querySelector("#workErr")!;
    err.textContent = "";
    try {
      const data = await postLift({ arch: archEl.value, function: f.name });
      lastMeta = JSON.stringify(data.report, null, 2);
      if (data.summary) {
        summary = data.summary;
        renderStats(summary);
      }
      await refreshFunctions();
      await selectFunction(f.name);
      viewTab = "scaffold";
      renderWorkbench();
    } catch (e) {
      err.textContent = e instanceof Error ? e.message : String(e);
    }
  });

  const doRw = async (apply: boolean) => {
    const err = mainEl.querySelector("#workErr")!;
    err.textContent = "";
    try {
      const provider = (mainEl.querySelector("#provider") as HTMLSelectElement).value;
      const data = await postRewrite({
        arch: archEl.value,
        function: f.name,
        provider,
        apply,
      });
      lastMeta = JSON.stringify(
        {
          provider: data.provider,
          model: data.model,
          prompt_hash: data.prompt_hash,
          draft: data.draft,
          applied: data.applied,
        },
        null,
        2,
      );
      if (data.summary) {
        summary = data.summary;
        renderStats(summary);
      }
      await refreshFunctions();
      await selectFunction(f.name);
      viewTab = apply ? "curated" : "semantic";
      renderWorkbench();
    } catch (e) {
      err.textContent = e instanceof Error ? e.message : String(e);
    }
  };
  mainEl.querySelector("#rwDraftBtn")!.addEventListener("click", () => void doRw(false));
  mainEl.querySelector("#rwApplyBtn")!.addEventListener("click", () => void doRw(true));

  mainEl.querySelector("#oneshotLift")!.addEventListener("click", async () => {
    const err = mainEl.querySelector("#oneshotErr")!;
    err.textContent = "";
    const slice = (mainEl.querySelector("#slice") as HTMLInputElement).value.trim();
    const address = (mainEl.querySelector("#address") as HTMLInputElement).value.trim();
    const length = (mainEl.querySelector("#length") as HTMLInputElement).value.trim();
    const name = (mainEl.querySelector("#oneshotName") as HTMLInputElement).value.trim();
    try {
      const data = await postLift({
        arch: archEl.value,
        slice: slice || null,
        address: address || null,
        length: length || null,
        name: name || null,
      });
      lastMeta = JSON.stringify(data.report, null, 2);
      if (data.summary) {
        summary = data.summary;
        renderStats(summary);
      }
      await refreshFunctions();
      const n = (data.report.name as string) || name;
      if (n) await selectFunction(n);
    } catch (e) {
      err.textContent = e instanceof Error ? e.message : String(e);
    }
  });
}

async function refreshFunctions() {
  const data = await listFunctions({
    status: statusFilter.value || undefined,
    q: searchEl.value.trim() || undefined,
  });
  functions = data.functions;
  summary = data.summary;
  renderStats(summary);
  renderFnList();
}

async function selectFunction(name: string) {
  selected = name;
  detail = await getFunction(name);
  viewTab = pickDefaultTab(detail);
  lastMeta = JSON.stringify({ function: detail.function, paths: detail.paths }, null, 2);
  renderFnList();
  renderWorkbench();
}

async function doOpen(path: string) {
  summary = await openProject(path);
  projectPathEl.value = summary.root;
  renderStats(summary);
  await refreshFunctions();
  selected = null;
  detail = null;
  renderWorkbench();
  const st = await getStatus();
  renderRecent(st.recent);
}

document.querySelector("#openBtn")!.addEventListener("click", () => {
  void doOpen(projectPathEl.value.trim()).catch((e) => {
    mainEl.innerHTML = `<div class="empty error">${e instanceof Error ? e.message : String(e)}</div>`;
  });
});

document.querySelector("#initBtn")!.addEventListener("click", () => {
  void initProject(projectPathEl.value.trim())
    .then(async (s) => {
      summary = s;
      projectPathEl.value = s.root;
      renderStats(s);
      await refreshFunctions();
      const st = await getStatus();
      renderRecent(st.recent);
    })
    .catch((e) => {
      mainEl.innerHTML = `<div class="empty error">${e instanceof Error ? e.message : String(e)}</div>`;
    });
});

statusFilter.addEventListener("change", () => void refreshFunctions());
searchEl.addEventListener("input", () => {
  window.clearTimeout((searchEl as HTMLInputElement & { _t?: number })._t);
  (searchEl as HTMLInputElement & { _t?: number })._t = window.setTimeout(
    () => void refreshFunctions(),
    200,
  );
});

async function boot() {
  const st = await getStatus();
  projectPathEl.value = st.project;
  summary = st.summary;
  renderStats(st.summary);
  renderRecent(st.recent);
  archEl.innerHTML = "";
  for (const a of st.arches) {
    const o = document.createElement("option");
    o.value = a;
    o.textContent = a;
    if (a === "i960") o.selected = true;
    archEl.appendChild(o);
  }
  await refreshFunctions();
}

boot().catch((e) => {
  mainEl.innerHTML = `<div class="empty error">${e instanceof Error ? e.message : String(e)}</div>`;
});
