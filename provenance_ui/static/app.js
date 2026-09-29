const state = { view: null };

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}
function shortId(value) {
  if (!value) return "—";
  if (value.startsWith("sha256:") && value.length > 25) return value.slice(0,15) + "…" + value.slice(-10);
  return value;
}
function renderVerification(view) {
  const root=document.querySelector("#verification"); root.replaceChildren();
  for (const key of ["integrity","custody","signature","replay"]) {
    const card=el("div",null,"status"); card.dataset.state=view.verification[key];
    card.append(el("strong",key),el("div",view.verification[key],"value")); root.append(card);
  }
  for (const [key,value] of Object.entries(view.summary)) {
    const card=el("div",null,"status"); card.append(el("strong",key),el("div",value ?? "—","value")); root.append(card);
  }
}
function renderGaps(view) {
  const root=document.querySelector("#gaps"); root.replaceChildren();
  if (!view.gaps.length) { root.append(el("p","No viewer-detected gaps in the current finalized projection.","hint")); return; }
  for (const gap of view.gaps) {
    const card=el("div",null,"gap"); card.append(el("strong",gap.kind));
    card.append(el("p",typeof gap.detail==="string" ? gap.detail : JSON.stringify(gap.detail)));
    if (gap.identity) card.append(el("code",gap.identity)); root.append(card);
  }
}
function renderGraph(view) {
  const root=document.querySelector("#graph"); root.replaceChildren(); const counts=new Map();
  for (const edge of view.graph.edges) { counts.set(edge.from,(counts.get(edge.from)||0)+1); counts.set(edge.to,(counts.get(edge.to)||0)+1); }
  for (const node of view.graph.nodes) {
    const card=el("div",null,"card"); card.append(el("div",node.kind,"node-kind"),el("div",node.label||shortId(node.id)),el("div",shortId(node.id),"node-id"),el("div",String(counts.get(node.id)||0)+" relation(s)","hint")); root.append(card);
  }
}
function renderTimeline(view) {
  document.querySelector("#ordering-note").textContent=view.timeline.ordering_note;
  const root=document.querySelector("#timeline"); root.replaceChildren(); const records=view.timeline.timestamped_custody;
  if (!records.length) root.append(el("p","No custody timestamps are present.","hint"));
  else {
    const table=el("table"), head=el("tr"); for (const label of ["time","action","subject","actor/source"]) head.append(el("th",label)); table.append(head);
    for (const item of records) { const row=el("tr"); row.append(el("td",item.recorded_at||"—"),el("td",item.action||"—")); const s=el("td"); s.append(el("code",shortId(item.subject_identity))); row.append(s,el("td",item.actor||item.source||"unknown")); table.append(row); }
    root.append(table);
  }
  if (view.timeline.untimed_events.length) root.append(el("p",String(view.timeline.untimed_events.length)+" event(s) are intentionally untimed in event schema v1.","hint"));
}
function metaRow(dl,key,value) {
  dl.append(el("dt",key)); const dd=el("dd"); dd.textContent=Array.isArray(value) ? (value.length ? value.join(", ") : "—") : (value ?? "—"); dl.append(dd);
}
function renderArtifacts(view) {
  const query=document.querySelector("#artifact-filter").value.trim().toLowerCase(), root=document.querySelector("#artifacts"); root.replaceChildren();
  const artifacts=view.artifacts.filter((item)=>!query || [item.identity,item.media_type,item.retention].some((v)=>String(v||"").toLowerCase().includes(query)));
  for (const item of artifacts) {
    const details=el("details"), summary=el("summary"); summary.append(el("strong",item.media_type||"unknown media"),document.createTextNode(" · "),el("code",shortId(item.identity))); details.append(summary);
    const dl=el("dl",null,"meta"); metaRow(dl,"identity",item.identity); metaRow(dl,"record identity",item.record_identity); metaRow(dl,"media type",item.media_type); metaRow(dl,"byte count",item.byte_count); metaRow(dl,"retention",item.retention); metaRow(dl,"integrity",item.verification.integrity); metaRow(dl,"custody",item.verification.custody); metaRow(dl,"source",item.sources); metaRow(dl,"events",item.events); metaRow(dl,"custody records",item.custody.map((r)=>r.identity)); details.append(dl); root.append(details);
  }
  if (!artifacts.length) root.append(el("p","No matching artifacts.","hint"));
}
function renderEvents(view) {
  const root=document.querySelector("#events"); root.replaceChildren();
  for (const item of view.events) {
    const details=el("details"); details.append(el("summary",(item.operation||"event")+" · "+(item.evidence_class||"unknown")));
    const dl=el("dl",null,"meta"); metaRow(dl,"identity",item.identity); metaRow(dl,"actor",item.actor); metaRow(dl,"operation",item.operation); metaRow(dl,"evidence class",item.evidence_class); metaRow(dl,"collection status",item.collection_status); metaRow(dl,"inputs",item.inputs); metaRow(dl,"outputs",item.outputs); details.append(dl); root.append(details);
  }
}
function render(view) { state.view=view; renderVerification(view); renderGaps(view); renderGraph(view); renderTimeline(view); renderArtifacts(view); renderEvents(view); }
async function refresh() {
  const button=document.querySelector("#refresh"); button.disabled=true;
  try { const response=await fetch("/api/view",{cache:"no-store"}); const payload=await response.json(); if (!response.ok || payload.ok!==true) throw new Error(payload.error||"viewer request failed"); render(payload.view); }
  catch (error) { document.querySelector("main").prepend(el("p",String(error),"error")); }
  finally { button.disabled=false; }
}
document.querySelector("#refresh").addEventListener("click",refresh);
document.querySelector("#artifact-filter").addEventListener("input",()=>{ if (state.view) renderArtifacts(state.view); });
refresh();
