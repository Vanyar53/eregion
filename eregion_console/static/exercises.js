// What Glorfindel did inside an exercise window — shared by the injectors' pages and the
// overview. A technique expects a detection; a fault expects nothing disruptive (G0, G1).
// Needs console.js (Console.hms: times in UTC).
const DISRUPTIVE = ['isolate_vm', 'block_suspicious_ip'];
const esc = Console.esc;
const hms = Console.hms;
const vmName = rid => String(rid || '').split('/').pop();

function toDate(v) {
  if (v === null || v === undefined || v === '') return null;
  const d = typeof v === 'number' ? new Date(v * 1000) : new Date(v);
  return isNaN(d) ? null : d;
}
function dur(s) {
  if (s === null || s === undefined || isNaN(s)) return '—';
  s = Math.round(s);
  if (Math.abs(s) < 120) return `${s}s`;
  if (Math.abs(s) < 3600) return `${Math.floor(s / 60)}m${String(Math.abs(s % 60)).padStart(2, '0')}`;
  if (Math.abs(s) < 172800) return `${Math.floor(s / 3600)}h${String(Math.floor(Math.abs(s % 3600) / 60)).padStart(2, '0')}`;
  return `${Math.floor(s / 86400)}d`;
}
function ago(v) { const d = toDate(v); return d ? dur((Date.now() - d) / 1000) : '—'; }
const pct = c => (typeof c === 'number' ? `${Math.round(c * 100)}%` : '');
async function getJSON(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function attackTime(w) {
  const at = w.run && w.run.metrics && w.run.metrics.attack_time;
  return toDate(at) ? { d: toDate(at), from: 'attack' } : { d: toDate(w.start), from: 'window start' };
}
// The ATT&CK id an Annatar window opens with (`<mitre> <scenario>`), else '' (a fault, an id
// that is not one): then no cycle is set apart by its technique.
function ownTtp(w) {
  return w.kind === 'technique' && /^T\d{4}(\.\d{3})?$/.test(w.experiment_id || '') ? w.experiment_id : '';
}
function decisionText(c) {
  if (!c || !c.action) return '';
  let how = c.status || '';
  if (c.executed === true) how = c.verified === true ? 'executed ✓' : c.verified === false ? 'executed, not verified' : 'executed';
  else if (c.escalate) how = c.status === 'escalated' ? 'held' : (c.status || 'escalated');
  return `${c.action} ${pct(c.confidence)}${how ? ' · ' + how : ''}${c.mode ? ' (' + c.mode + ')' : ''}`;
}
function response(w) {
  const live = w.state === 'open' || w.state === 'grace';
  const cycles = w.cycles || [];
  // H-1: a window Glorfindel does not believe, or on a VM not enrolled, marks nothing — its
  // cycles are labelled real and are not attached here.
  if (w.refusal) return { cls: 'bad', text: `not believed by Glorfindel — ${w.refusal}` };
  const enrolled = Object.values(w.enrolled || {});
  if (enrolled.length && !enrolled.some(Boolean))
    return { cls: 'warn', text: 'target not enrolled — Glorfindel takes nothing here as an exercise' };
  if (w.kind === 'fault') {
    const disruptive = cycles.filter(c => DISRUPTIVE.includes(c.action));
    const done = disruptive.filter(c => c.executed === true);
    if (done.length) return { cls: 'bad', text: `${done[0].action} executed during a fault` };
    if (disruptive.length) return { cls: 'warn', text: `${disruptive[0].action} recommended during a fault, held` };
    if (cycles.length) return { cls: 'ok', text: `${cycles.length} cycle(s), nothing disruptive` };
    // V1: no watch, by choice — « nothing disruptive » would be a silence, not a proof.
    if (!live && w.run && w.run.metrics && w.run.metrics.without_glorfindel === true)
      return { cls: 'blue', text: 'not measured, by choice (--without-glorfindel)' };
    return live ? { cls: 'wait', text: 'nothing so far' } : { cls: 'ok', text: 'nothing disruptive — as expected' };
  }
  // An unattributed row is anchored on an arbitrary VM: it names none, and the return
  // channel never delivers it to the run (watch_channel.Publisher._note).
  const named = c => !c.attribution || c.attribution === 'asset';
  const det = cycles.filter(c => c.event === 'detection' && named(c));
  // A run's detection is of its own technique (#157): in a campaign, the next run on the
  // same VM falls in this window's grace.
  const ttp = ownTtp(w);
  const own = ttp ? det.filter(c => c.ttp === ttp) : det;
  if (own.length) {
    const t0 = attackTime(w), seen = toDate(own[0].signal_at);
    const lat = t0.d && seen ? ` +${dur((seen - t0.d) / 1000)} after ${t0.from}` : '';
    const dec = cycles.find(c => c.action && named(c) && (!ttp || c.ttp === ttp));
    return { cls: 'ok', text: `detected${lat}${dec ? ' → ' + decisionText(dec) : ''}` };
  }
  if (det.length) return { cls: 'blue', text: `no ${ttp} detection · ${det.length} of other techniques` };
  if (cycles.some(c => c.event === 'detection'))
    return { cls: 'warn', text: 'a detection, not attributed to this VM' };
  if (cycles.length) return { cls: 'blue', text: `${cycles.length} cycle(s), no detection` };
  if (live) return { cls: 'wait', text: 'waiting for a detection' };
  // Only the run concludes to a miss — on a heartbeat that vouches for its wait
  // (eregion_core/watch_channel.py): an absence in this host's files is not one.
  const verdict = w.run && w.run.metrics && w.run.metrics.detection;
  // V1: a run --without-glorfindel measured nothing, by choice — not an `unknown`.
  if (w.run && w.run.metrics && w.run.metrics.without_glorfindel === true)
    return { cls: 'blue', text: 'not measured, by choice (--without-glorfindel)' };
  if (verdict === 'missed') return { cls: 'bad', text: 'missed (the run\'s verdict)' };
  if (verdict === 'detected') return { cls: 'blue', text: 'detected per the run · no cycle in this host\'s files' };
  return { cls: 'warn', text: 'no detection seen by this watch' };
}
function runChip(w) {
  const r = w.run;
  if (!r) return `<span class="meta" title="Run reports stay on Orodruin unless a campaign carries them">run report not on this host</span>`;
  const cls = { PASS: 'c-ok', FAIL: 'c-bad', REFUSED: 'c-warn' }[r.result] || '';
  const det = r.metrics && r.metrics.detection;
  const dcls = { detected: 'c-ok', missed: 'c-bad', unknown: 'c-warn' }[det] || '';
  const without = r.metrics && r.metrics.without_glorfindel === true;   // V1
  return `<span class="chip ${cls}">RUN ${esc(r.result || '?')}</span>` +
    (without ? ` <span class="chip" title="Run --without-glorfindel: a development run, detection not measured, by choice">NOT MEASURED · BY CHOICE</span>`
     : det ? ` <span class="chip ${dcls}" title="The run's own verdict (return channel)">${esc(String(det).toUpperCase())}</span>` : '');
}
