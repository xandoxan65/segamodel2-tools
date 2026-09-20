export type ProjectSummary = {
  root: string;
  name: string;
  arch_default: string;
  functions_total: number;
  with_slice: number;
  scaffolded: number;
  curated: number;
  semantic_drafts: number;
  slices_on_disk: number;
  has_symbols: boolean;
  has_disasm: boolean;
  has_src: boolean;
  config_present: boolean;
};

export type Status = {
  project: string;
  arches: string[];
  spa?: boolean;
  summary: ProjectSummary;
  recent: { path: string; exists: boolean; name: string }[];
};

export type FunctionRow = {
  name: string;
  address: number;
  length: number | null;
  section: string | null;
  kind: string;
  has_slice: boolean;
  slice_path: string | null;
  has_scaffold: boolean;
  has_curated: boolean;
  has_semantic: boolean;
  has_ir: boolean;
  src_dir: string;
  status: string;
};

export type FunctionDetail = {
  function: FunctionRow;
  paths: Record<string, string | null>;
  texts: Record<string, string | null>;
};

export type LiftResponse = {
  report: Record<string, unknown>;
  scaffold_c: string;
  lifted_text: string;
  summary?: ProjectSummary;
};

export type RewriteResponse = {
  provider: string;
  model: string;
  prompt_hash: string;
  draft: string | null;
  applied: string | null;
  c_text: string;
  summary?: ProjectSummary;
};

async function json<T>(res: Response): Promise<T> {
  const data = await res.json();
  if (!res.ok) {
    const detail = (data as { detail?: string }).detail ?? JSON.stringify(data);
    throw new Error(detail);
  }
  return data as T;
}

export function getStatus(): Promise<Status> {
  return fetch("/api/status").then((r) => json<Status>(r));
}

export function openProject(path: string): Promise<ProjectSummary> {
  return fetch("/api/project/open", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  }).then((r) => json<ProjectSummary>(r));
}

export function initProject(path: string, name?: string): Promise<ProjectSummary> {
  return fetch("/api/project/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path, name }),
  }).then((r) => json<ProjectSummary>(r));
}

export function listFunctions(params?: {
  status?: string;
  q?: string;
}): Promise<{ count: number; functions: FunctionRow[]; summary: ProjectSummary }> {
  const sp = new URLSearchParams();
  if (params?.status) sp.set("status", params.status);
  if (params?.q) sp.set("q", params.q);
  const qs = sp.toString();
  return fetch(`/api/project/functions${qs ? `?${qs}` : ""}`).then((r) =>
    json<{ count: number; functions: FunctionRow[]; summary: ProjectSummary }>(r),
  );
}

export function getFunction(name: string): Promise<FunctionDetail> {
  return fetch(`/api/project/functions/${encodeURIComponent(name)}`).then((r) =>
    json<FunctionDetail>(r),
  );
}

export function postLift(body: {
  arch: string;
  slice?: string | null;
  function?: string | null;
  address?: string | null;
  length?: string | null;
  name?: string | null;
}): Promise<LiftResponse> {
  return fetch("/api/lift", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => json<LiftResponse>(r));
}

export function postRewrite(body: {
  arch: string;
  function: string;
  provider: string;
  apply: boolean;
}): Promise<RewriteResponse> {
  return fetch("/api/rewrite", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => json<RewriteResponse>(r));
}
