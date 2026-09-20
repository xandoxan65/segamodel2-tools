(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const a of document.querySelectorAll('link[rel="modulepreload"]'))y(a);new MutationObserver(a=>{for(const i of a)if(i.type==="childList")for(const o of i.addedNodes)o.tagName==="LINK"&&o.rel==="modulepreload"&&y(o)}).observe(document,{childList:!0,subtree:!0});function n(a){const i={};return a.integrity&&(i.integrity=a.integrity),a.referrerPolicy&&(i.referrerPolicy=a.referrerPolicy),a.crossOrigin==="use-credentials"?i.credentials="include":a.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function y(a){if(a.ep)return;a.ep=!0;const i=n(a);fetch(a.href,i)}})();async function h(t){const e=await t.json();if(!t.ok){const n=e.detail??JSON.stringify(e);throw new Error(n)}return e}function x(){return fetch("/api/status").then(t=>h(t))}function F(t){return fetch("/api/project/open",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:t})}).then(e=>h(e))}function I(t,e){return fetch("/api/project/init",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:t,name:e})}).then(n=>h(n))}function H(t){const e=new URLSearchParams;t!=null&&t.status&&e.set("status",t.status),t!=null&&t.q&&e.set("q",t.q);const n=e.toString();return fetch(`/api/project/functions${n?`?${n}`:""}`).then(y=>h(y))}function B(t){return fetch(`/api/project/functions/${encodeURIComponent(t)}`).then(e=>h(e))}function k(t){return fetch("/api/lift",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(t)}).then(e=>h(e))}function J(t){return fetch("/api/rewrite",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(t)}).then(e=>h(e))}const A=document.querySelector("#app");A.innerHTML=`
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
`;const v=document.querySelector("#projectPath"),S=document.querySelector("#arch"),_=document.querySelector("#statusFilter"),w=document.querySelector("#search"),N=document.querySelector("#fnList"),R=document.querySelector("#fnCount"),D=document.querySelector("#stats"),j=document.querySelector("#recent"),s=document.querySelector("#main");let c=null,q=[],$=null,r=null,d="curated",b="";function E(t){return"0x"+t.toString(16)}function m(t){D.innerHTML=`
    <div class="stat"><b>${t.functions_total}</b><span>symbols</span></div>
    <div class="stat"><b>${t.with_slice}</b><span>sliced</span></div>
    <div class="stat"><b>${t.scaffolded}</b><span>lifted</span></div>
    <div class="stat"><b>${t.curated}</b><span>curated</span></div>
  `}function C(t){j.innerHTML="";for(const e of t.slice(0,6)){const n=document.createElement("button");n.type="button",n.className="small secondary",n.textContent=e.name,n.title=e.path,n.disabled=!e.exists,n.addEventListener("click",()=>{v.value=e.path,M(e.path)}),j.appendChild(n)}}function P(){N.innerHTML="";for(const t of q){const e=document.createElement("button");e.type="button",e.className="fn-item"+(t.name===$?" active":""),e.innerHTML=`
      <div>${t.name}</div>
      <div class="meta">
        <span>${E(t.address)}${t.length!=null?` +${E(t.length)}`:""}</span>
        <span class="badge ${t.status}">${t.status.replace("_"," ")}</span>
      </div>
    `,e.addEventListener("click",()=>void L(t.name)),N.appendChild(e)}R.textContent=`${q.length} function(s)`}function K(t){return t.texts.curated?"curated":t.texts.semantic?"semantic":t.texts.scaffold?"scaffold":t.texts.lifted?"lifted":t.texts.slice?"slice":"meta"}function g(){if(!r){s.innerHTML='<div class="empty">Select a function from the catalog.</div>';return}const t=r.function,e=[{id:"curated",label:"Curated C",ok:!!r.texts.curated},{id:"scaffold",label:"Scaffold",ok:!!r.texts.scaffold},{id:"semantic",label:"AI draft",ok:!!r.texts.semantic},{id:"lifted",label:"Lifted text",ok:!!r.texts.lifted},{id:"ir",label:"IR",ok:!!r.texts.ir},{id:"slice",label:"Asm",ok:!!r.texts.slice},{id:"meta",label:"Meta",ok:!0}];let n="";d==="meta"?n=b||JSON.stringify({function:t,paths:r.paths},null,2):d==="ir"?n=r.texts.ir||"(no IR yet — lift first)":n=r.texts[d]||`(no ${d} artifact yet)`,s.innerHTML=`
    <section class="panel">
      <h2>${t.name}</h2>
      <p class="muted">${E(t.address)}${t.length!=null?` + ${E(t.length)}`:""} · ${t.section||"no section"} · <span class="badge ${t.status}">${t.status}</span></p>
      <p class="muted">${t.slice_path?`slice: ${t.slice_path}`:"no disasm slice on disk"} · src: ${t.src_dir}</p>
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
  `;const y=s.querySelector("#tabs");for(const i of e){const o=document.createElement("button");o.type="button",o.textContent=i.label+(i.ok?"":" ·"),o.className=i.id===d?"active":"",o.addEventListener("click",()=>{d=i.id,g()}),y.appendChild(o)}s.querySelector("#out").textContent=n,s.querySelector("#liftFnBtn").addEventListener("click",async()=>{const i=s.querySelector("#workErr");i.textContent="";try{const o=await k({arch:S.value,function:t.name});b=JSON.stringify(o.report,null,2),o.summary&&(c=o.summary,m(c)),await p(),await L(t.name),d="scaffold",g()}catch(o){i.textContent=o instanceof Error?o.message:String(o)}});const a=async i=>{const o=s.querySelector("#workErr");o.textContent="";try{const f=s.querySelector("#provider").value,l=await J({arch:S.value,function:t.name,provider:f,apply:i});b=JSON.stringify({provider:l.provider,model:l.model,prompt_hash:l.prompt_hash,draft:l.draft,applied:l.applied},null,2),l.summary&&(c=l.summary,m(c)),await p(),await L(t.name),d=i?"curated":"semantic",g()}catch(f){o.textContent=f instanceof Error?f.message:String(f)}};s.querySelector("#rwDraftBtn").addEventListener("click",()=>void a(!1)),s.querySelector("#rwApplyBtn").addEventListener("click",()=>void a(!0)),s.querySelector("#oneshotLift").addEventListener("click",async()=>{const i=s.querySelector("#oneshotErr");i.textContent="";const o=s.querySelector("#slice").value.trim(),f=s.querySelector("#address").value.trim(),l=s.querySelector("#length").value.trim(),O=s.querySelector("#oneshotName").value.trim();try{const u=await k({arch:S.value,slice:o||null,address:f||null,length:l||null,name:O||null});b=JSON.stringify(u.report,null,2),u.summary&&(c=u.summary,m(c)),await p();const T=u.report.name||O;T&&await L(T)}catch(u){i.textContent=u instanceof Error?u.message:String(u)}})}async function p(){const t=await H({status:_.value||void 0,q:w.value.trim()||void 0});q=t.functions,c=t.summary,m(c),P()}async function L(t){$=t,r=await B(t),d=K(r),b=JSON.stringify({function:r.function,paths:r.paths},null,2),P(),g()}async function M(t){c=await F(t),v.value=c.root,m(c),await p(),$=null,r=null,g();const e=await x();C(e.recent)}document.querySelector("#openBtn").addEventListener("click",()=>{M(v.value.trim()).catch(t=>{s.innerHTML=`<div class="empty error">${t instanceof Error?t.message:String(t)}</div>`})});document.querySelector("#initBtn").addEventListener("click",()=>{I(v.value.trim()).then(async t=>{c=t,v.value=t.root,m(t),await p();const e=await x();C(e.recent)}).catch(t=>{s.innerHTML=`<div class="empty error">${t instanceof Error?t.message:String(t)}</div>`})});_.addEventListener("change",()=>void p());w.addEventListener("input",()=>{window.clearTimeout(w._t),w._t=window.setTimeout(()=>void p(),200)});async function U(){const t=await x();v.value=t.project,c=t.summary,m(t.summary),C(t.recent),S.innerHTML="";for(const e of t.arches){const n=document.createElement("option");n.value=e,n.textContent=e,e==="i960"&&(n.selected=!0),S.appendChild(n)}await p()}U().catch(t=>{s.innerHTML=`<div class="empty error">${t instanceof Error?t.message:String(t)}</div>`});
