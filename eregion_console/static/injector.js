// ── Which injector: the path says it ─────────────────────────────────────────────────
const INJECTOR = location.pathname.replace(/\/+$/, '') === '/gothmog' ? 'gothmog' : 'annatar';
const ABOUT = {
  annatar: {
    label: 'Annatar', kind: 'technique', catalog: 'TECHNIQUES', icon: '⚔',
    title: 'attacks run from Orodruin, armed, and what Glorfindel did',
    adds: 'Proof that Glorfindel detects real techniques: each attack, when Glorfindel saw it and what it decided, and the coverage of the catalogue.',
    how: 'README.md (Annatar) and infra/orodruin/README.md — then, on Orodruin: <code>annatar run &lt;scenario&gt;</code>, or a campaign (<code>make orodruin-campaign-plan</code>).',
  },
  gothmog: {
    label: 'Gothmog', kind: 'fault', catalog: 'FAULTS', icon: '⚡',
    title: 'faults run from Orodruin, armed, and what Glorfindel did',
    adds: 'Proof that Glorfindel holds when the infrastructure fails: the steady state checked before and after each fault, the return verified, and nothing disruptive decided on benign noise.',
    how: 'gothmog/README.md and infra/orodruin/README.md — then, on Orodruin: <code>gothmog run vm-shutdown --yes</code>.',
  },
}[INJECTOR];

Console.init(INJECTOR);
document.title = `Eregion — ${ABOUT.label}`;
document.getElementById('page-title').className = INJECTOR;
document.getElementById('page-title').innerHTML =
  `<b>${ABOUT.label.toUpperCase()}</b> <span>— ${esc(ABOUT.title)}. This page never launches a run · times UTC</span>`;
document.getElementById('cat-title').textContent = ABOUT.catalog;
if (INJECTOR !== 'annatar') document.getElementById('col-camp').remove();   // campaigns are Annatar's

// ── State ─────────────────────────────────────────────────────────────────────────────
const params = new URLSearchParams(location.search);
const S = {
  since: '7d', campSince: '30d',
  ex: null, camp: null, cat: null,
  errors: {},
  open: new Set(),          // expanded rows: 'w:<run_id>' / 'c:<dir>'
  campDetail: {},           // dir → {facts, report_md} | {error} | 'loading'
  delivered: {},            // run_id → {detections} | {error} | 'loading'
  showReport: new Set(),    // campaign dirs whose report.md is shown
  focus: null,              // the row a link opened (?run=, ?campaign=): scrolled to once
};
if (params.get('run')) { S.open.add('w:' + params.get('run')); S.focus = 'w:' + params.get('run'); }
if (params.get('campaign')) { S.open.add('c:' + params.get('campaign')); S.focus = S.focus || 'c:' + params.get('campaign'); }
const $ = id => document.getElementById(id);
const rowId = key => 'row-' + key.replace(/[^A-Za-z0-9._-]/g, '_');
function scrollToFocus() {
  if (!S.focus) return;
  const el = $(rowId(S.focus));
  if (!el) return;
  el.classList.add('focus');
  el.scrollIntoView({ block: 'start' });
  S.focus = null;
}

// ── Exercises ─────────────────────────────────────────────────────────────────────────
function renderExercises() {
  const list = $('ex-list');
  if (S.errors.ex) { list.innerHTML = `<div class="err">${esc(S.errors.ex)}</div>`; return; }
  if (!S.ex) return;
  const items = S.ex.exercises || [];
  const live = items.filter(w => w.state === 'open' || w.state === 'grace').length;
  $('ex-count').textContent = `${items.length}${live ? ` · ${live} live` : ''}`;
  if (!items.length) {
    list.innerHTML = `<div class="empty">No ${ABOUT.label} exercise window in this period.<br>
      A window opens when ${ABOUT.label} starts a run against an inscribed target
      (runs/exercises/, pulled from Orodruin by the watch). Windows are kept 7 days.</div>`;
    return;
  }
  const top = list.scrollTop;
  list.innerHTML = items.map(renderWindow).join('');
  list.scrollTop = top;
  scrollToFocus();
}

function renderWindow(w) {
  const key = 'w:' + w.run_id, isOpen = S.open.has(key);
  const stateCls = 'c-' + esc(w.state || 'closed');
  const end = toDate(w.end), start = toDate(w.start);
  let timing = `${hms(w.start)}`;
  if (w.state === 'open') timing += ` → running ${dur((Date.now() - start) / 1000)}`;
  else if (end && start) timing += ` → ${hms(w.end)} (${dur((end - start) / 1000)})`;
  else if (w.state === 'lapsed') timing += ` → never closed, lapsed ${hms(w.expires)}`;
  if (w.state === 'grace' && toDate(w.last_moment)) timing += ` · grace ${dur((toDate(w.last_moment) - Date.now()) / 1000)} left`;
  const resp = response(w);
  const targets = (w.targets || []).map(vmName).join(', ');
  const cards = w.cards || [];
  return `<div class="row inj-${esc(w.injector)}" id="${rowId(key)}">
    <div class="row-head" data-toggle="${esc(key)}">
      <span class="twist">${isOpen ? '▾' : '▸'}</span>
      <span class="chip ${stateCls} ${w.state === 'open' ? 'pulse' : ''}">${esc(String(w.state || '').toUpperCase())}</span>
      ${w.refusal ? `<span class="chip c-bad" title="${esc(w.refusal)}">NOT BELIEVED</span>` : ''}
      ${Object.values(w.enrolled || {}).some(e => !e) ? `<span class="chip c-warn" title="Not enrolled: ${esc(Object.keys(w.enrolled).filter(k => !w.enrolled[k]).map(vmName).join(', '))}">NOT ENROLLED</span>` : ''}
      ${w.closed_by ? `<span class="chip c-bad" title="Closed by ${esc(w.closed_by)}, not by its injector: what was in flight may not have been cleaned up">${esc(w.closed_by)}</span>` : ''}
      <span class="exp" title="${esc(w.experiment)}">${esc(w.experiment)}</span>
      <span class="meta tgt" title="${esc((w.targets || []).join('\n'))}">→ ${esc(targets)}</span>
      <span class="meta" style="margin-left:auto">${timing}</span>
    </div>
    <div class="row-sub">
      <span class="meta" style="width:10px"></span>
      <span class="resp r-${resp.cls}">${w.kind === 'fault' ? '⚡' : '⚔'} ${esc(resp.text)}</span>
      ${cards.length ? `<a class="chip c-blue" href="/glorfindel?card=${encodeURIComponent(cards[0].id)}" title="Judge it in Glorfindel's TO JUDGE">${Number(cards.length)} card${cards.length > 1 ? 's' : ''} ▸</a>` : ''}
      <span style="margin-left:auto">${runChip(w)}</span>
    </div>
    ${isOpen ? renderWindowDetail(w) : ''}
  </div>`;
}

// A fault's steady state (G0): each probe before the fault and after it, per target. A query's
// value is its last row's time, which must come after the fault's end (gothmog/probes.py).
function probeTable(m) {
  const before = m.before || {}, after = m.after || {};
  const vms = [...new Set([...Object.keys(before), ...Object.keys(after)])];
  if (!vms.length) return '';
  const end = toDate(m.fault_end);
  const cell = (p, isAfter) => {
    if (!p) return '<td style="color:var(--dim)">—</td>';
    const t = /^fresh\s/.test(p.expect) ? toDate(p.observed) : null;
    let shown = t ? hms(p.observed) : p.observed;
    if (t && isAfter && end) shown += ` (end ${t >= end ? '+' : ''}${dur((t - end) / 1000)})`;
    const long = shown.length > 30;   // "unreadable: …", in full on hover
    if (long) shown = shown.slice(0, 29) + '…';
    return `<td class="${long ? 'wrap ' : ''}${p.ok ? 'r-ok' : 'r-bad'}" title="${esc(p.observed)}">${p.ok ? '✓' : '✗'} ${esc(shown)}</td>`;
  };
  const rows = vms.map(vm => {
    const b = before[vm] || [], a = after[vm] || [];
    const names = [...new Set([...b, ...a].map(p => p.name))];
    return `<tr><td colspan="4" style="color:var(--dim)">${esc(vm)}</td></tr>` +
      names.map(n => {
        const pb = b.find(p => p.name === n), pa = a.find(p => p.name === n);
        return `<tr><td>${esc(n)}</td><td style="color:var(--dim)">${esc((pb || pa).expect)}</td>${cell(pb, false)}${cell(pa, true)}</tr>`;
      }).join('');
  }).join('');
  return `<table class="t" style="margin-top:4px"><tr><th>probe</th><th>expect</th><th>before the fault</th><th>after</th></tr>${rows}</table>`;
}

function renderWindowDetail(w) {
  const parts = [];
  // The VM's name, its full id on hover: the id carries the subscription (M-1 took it off the
  // contract's display too).
  const targets = (w.targets || []).map(t => `<span title="${esc(t)}">${esc(vmName(t))}</span>`).join(', ');
  parts.push(`<div class="dsec ${INJECTOR === 'gothmog' ? 's-orange' : 's-purple'}"><div class="dtitle">WINDOW</div><div class="kv">
    <span><b>run</b> ${esc(w.run_id)}</span><span><b>kind</b> ${esc(w.kind)}</span>
    <span><b>start</b> ${hms(w.start)}</span><span><b>end</b> ${w.end ? hms(w.end) : '—'}</span>
    <span><b>expires</b> ${hms(w.expires)}</span><span><b>counts until</b> ${hms(w.last_moment)}</span>
    <span><b>targets</b> ${targets}</span>
  </div></div>`);

  const cycles = w.cycles || [];
  const t0 = attackTime(w);
  parts.push(`<div class="dsec s-blue"><div class="dtitle">GLORFINDEL — ${Number(cycles.length)} cycle(s) on a target inside the window</div>` +
    (cycles.length ? `<table class="t"><tr><th>seen</th><th>+${esc(t0.from)}</th><th>event</th><th>ttp</th><th>rule</th><th>decision</th></tr>` +
      cycles.map(c => {
        const seen = toDate(c.signal_at), other = ownTtp(w) && c.ttp !== ownTtp(w);
        return `<tr${other ? ' style="opacity:.5" title="Another technique: another run\'s, or a real one"' : ''}><td>${hms(c.signal_at)}</td><td>${t0.d && seen ? dur((seen - t0.d) / 1000) : '—'}</td>
          <td>${esc(c.event)}${c.attribution && c.attribution !== 'asset' ? ` <span style="color:var(--yellow)">(${esc(c.attribution)})</span>` : ''}</td>
          <td>${esc(c.ttp)}</td><td>${esc(c.rule)}</td>
          <td class="wrap" style="color:${DISRUPTIVE.includes(c.action) && c.executed === true ? 'var(--red)' : 'var(--text)'}">${esc(decisionText(c) || '—')}${c.cycle_error ? ' <span style="color:var(--red)">cycle error</span>' : ''}</td></tr>`;
      }).join('') + '</table>'
      : `<div style="color:var(--dim)">No cycle of the watch on these targets between the window's start and its last moment.</div>`) +
    `</div>`);

  const cards = w.cards || [];
  if (cards.length) {
    parts.push(`<div class="dsec s-blue"><div class="dtitle">CARDS CARRYING THIS RUN (exercise) — judged in Glorfindel's TO JUDGE</div><table class="t">` +
      cards.map(c => `<tr><td>${hms(c.timestamp)}</td><td>${esc(c.escalation_type)}</td><td>${esc(c.action)} ${pct(c.confidence)}</td>
        <td>${esc(c.status)}</td><td>${c.verdict ? 'verdict ' + esc(c.verdict) : ''}</td>
        <td><a href="/glorfindel?card=${encodeURIComponent(c.id)}">${c.verdict ? 'see' : 'judge'} ▸</a></td></tr>`).join('') + '</table></div>');
  }

  if (w.run) {
    const r = w.run, m = r.metrics || {};
    const checks = Object.entries(r.checks || {}).map(([k, v]) =>
      `<span class="chip ${v === 'PASS' ? 'c-ok' : 'c-bad'}" title="${esc(v)}">${esc(k)}</span>`).join(' ');
    const facts = [];
    if (m.attack_time) facts.push(`<span><b>attack</b> ${hms(m.attack_time)}</span>`);
    if (m.detection) facts.push(`<span><b>detection</b> ${esc(m.detection)}${m.detection_latency_s != null ? ' +' + dur(m.detection_latency_s) : ''}</span>`);
    if (m.fault_start) facts.push(`<span><b>fault</b> ${hms(m.fault_start)} → ${hms(m.fault_end)}</span>`);
    if (m.seen_down_at) facts.push(`<span><b>seen down</b> ${hms(m.seen_down_at)}</span>`);
    if (m.time_to_restore_s != null) facts.push(`<span><b>restored</b> +${dur(m.time_to_restore_s)}${m.fallback_used ? ' (fallback start_vm)' : ''}</span>`);
    if (m.aborted) facts.push(`<span style="color:var(--red)"><b>aborted</b> ${esc(m.aborted)}</span>`);
    parts.push(`<div class="dsec ${w.injector === 'gothmog' ? 's-orange' : 's-purple'}"><div class="dtitle">RUN REPORT — ${esc(r.result)}</div>
      <div class="kv">${facts.join('')}</div><div style="margin-top:3px">${checks}</div>${probeTable(m)}</div>`);
  }

  const d = S.delivered[w.run_id];
  let rc = `<button class="mini" data-delivered="${esc(w.run_id)}">read the return channel</button>`;
  if (d === 'loading') rc = '<span style="color:var(--dim)">reading…</span>';
  else if (d && d.error) rc = `<span style="color:var(--red)">${esc(d.error)}</span>`;
  else if (d && d.configured === false) rc = '<span style="color:var(--dim)">no return channel configured on this host</span>';
  else if (d) rc = d.detections.length
    ? `<table class="t">${d.detections.map(x => `<tr><td>${hms(x.detected_at)}</td><td>${esc(x.ttp)}</td><td>${esc(x.rule)}</td><td>${esc(vmName(x.resource_id))}</td></tr>`).join('')}</table>`
    : '<span style="color:var(--dim)">nothing delivered for this run</span>';
  parts.push(`<div class="dsec s-green"><div class="dtitle">DELIVERED TO THE RUN (return channel)</div>${rc}</div>`);
  return `<div class="detail">${parts.join('')}</div>`;
}

// ── Campaigns (Annatar's) ─────────────────────────────────────────────────────────────
function renderCampaigns() {
  const list = $('camp-list');
  if (!list) return;
  if (S.errors.camp) { list.innerHTML = `<div class="err">${esc(S.errors.camp)}</div>`; return; }
  if (!S.camp) return;
  const items = S.camp.campaigns || [];
  $('camp-count').textContent = items.length ? String(items.length) : '';
  if (!items.length) {
    list.innerHTML = `<div class="empty">No campaign in this period.<br>
      A campaign launched from Orodruin reaches this host when it is over (runs/campaigns/,
      published on the exercise channel); its report is written here.</div>`;
    return;
  }
  const top = list.scrollTop;
  list.innerHTML = items.map(renderCampaign).join('');
  list.scrollTop = top;
  scrollToFocus();
}

function renderCampaign(c) {
  if (c.error) return `<div class="row"><span class="meta">${esc(c.dir)}</span> <span style="color:var(--red)">${esc(c.error)}</span></div>`;
  const key = 'c:' + c.dir, isOpen = S.open.has(key);
  const sc = c.scenarios || [];
  const executed = sc.filter(s => s.status === 'executed');
  const n = k => executed.filter(s => (s.detection || 'unknown') === k).length;
  const stateCls = { done: 'c-ok', aborted: 'c-bad', running: 'c-open' }[c.state] || 'c-closed';
  // V1: a campaign run --without-glorfindel measured nothing, by choice — not « unknown ».
  const summary = c.without_glorfindel
    ? `${executed.length}/${Number(sc.length)} executed · <span class="meta">not measured, by choice (--without-glorfindel) · no report</span>`
    : `${executed.length}/${Number(sc.length)} executed · <span class="r-ok">${n('detected')} detected</span>` +
    (n('missed') ? ` · <span class="r-bad">${n('missed')} missed</span>` : '') +
    (n('unknown') ? ` · <span class="r-warn">${n('unknown')} unknown</span>` : '');
  const rows = sc.map(s => {
    const det = s.status === 'executed' ? (s.detection || 'unknown') : '';
    const dcls = { detected: 'r-ok', missed: 'r-bad', unknown: 'r-warn' }[det] || 'r-wait';
    return `<tr><td>${esc(s.seq)}</td><td>${esc(s.ttp)}</td><td style="color:var(--dim)">${esc(s.tactic)}</td>
      <td>${esc(s.status)}${s.destructive ? ' <span style="color:var(--red)">D</span>' : ''}</td>
      <td class="${dcls}">${esc(det)}${s.detection_latency_s != null ? ' +' + dur(s.detection_latency_s) : ''}</td>
      <td style="color:var(--dim)">${hms(s.started_at)}</td>
      <td class="wrap" style="color:var(--red)">${esc(s.error || '')}</td></tr>`;
  }).join('');
  return `<div class="row inj-annatar" id="${rowId(key)}">
    <div class="row-head" data-toggle="${esc(key)}">
      <span class="twist">${isOpen ? '▾' : '▸'}</span>
      <span class="chip ${stateCls}">${esc(String(c.state || '?').toUpperCase())}</span>
      ${c.kill_switch ? '<span class="chip c-bad">KILL SWITCH</span>' : ''}
      <span class="exp">${esc(c.campaign_id || c.dir)}</span>
      <span class="meta tgt" title="${esc(c.objective || '')}">${esc(c.objective || '')}</span>
      <span class="meta tgt" style="margin-left:auto">${hms(c.created_at)} · ${esc(c.created_by || '')}</span>
    </div>
    <div class="row-sub"><span class="meta" style="width:10px"></span>
      <span>${summary}</span>
      <span class="meta">${esc(c.sandbox || '')}${c.budget && c.budget.allow_destructive ? ' · destructive allowed' : ''}</span>
      <span style="margin-left:auto">${c.report ? '<span class="chip c-blue" title="report.md written by the analysis AI (IA0)">REPORT</span>' : ''}
        ${c.pulled ? '<span class="chip" title="Published by Orodruin">FROM ORODRUIN</span>' : ''}</span>
    </div>
    <div class="detail"><table class="t"><tr><th>#</th><th>ttp</th><th>tactic</th><th>status</th><th>detection</th><th>started</th><th></th></tr>${rows}</table></div>
    ${isOpen ? renderCampaignDetail(c) : ''}
  </div>`;
}

function renderCampaignDetail(c) {
  const d = S.campDetail[c.dir];
  if (!d || d === 'loading') return '<div class="detail" style="color:var(--dim)">reading the facts…</div>';
  if (d.error) return `<div class="detail" style="color:var(--red)">${esc(d.error)}</div>`;
  const facts = d.facts || [];
  const rows = facts.map(f => `<tr><td>${esc(f.seq)}</td><td>${esc(f.ttp)}</td>
    <td title="${esc(f.target || '')}">${esc(vmName(f.target) || '—')}</td>
    <td>${f.decision ? esc(f.decision) + ' ' + pct(f.confidence) + (f.escalated === true ? ' · escalated' : f.escalated === false ? ' · not escalated' : '')
      : `<span style="color:var(--dim)">${esc(f.decision_unknown ? 'unknown — ' + f.decision_unknown : '—')}</span>`}</td>
    <td class="wrap" style="color:var(--dim)">${esc((f.excerpt || '').slice(0, 220))}${(f.excerpt || '').length > 220 ? '…' : ''}</td></tr>`).join('');
  const showing = S.showReport.has(c.dir);
  return `<div class="detail">
    <div class="dsec s-blue"><div class="dtitle">GLORFINDEL'S DECISION ON EACH RUN (read from the files, as the campaign report reads them)</div>
      <table class="t"><tr><th>#</th><th>ttp</th><th>target</th><th>decision</th><th>reasoning (excerpt)</th></tr>${rows}</table></div>
    ${renderContainment(d.containment)}
    ${(d.skipped || []).length ? `<div class="dsec" style="border-color:var(--yellow)"><div class="dtitle">LEFT OUT OF THE FACTS (and of the report)</div>
      ${(d.skipped || []).map(s => `<div style="color:var(--yellow)">${esc(s)}</div>`).join('')}</div>` : ''}
    <div class="dsec s-purple"><div class="dtitle">REPORT</div>${d.report_md
      ? `<button class="mini" data-report="${esc(c.dir)}">${showing ? 'hide' : 'show'} report.md</button>${showing ? `<pre class="report">${esc(d.report_md)}</pre>` : ''}`
      : '<span style="color:var(--dim)">not written (yet) — on H0 it waits for the decisions, up to ~25 min after the end</span>'}</div>
  </div>`;
}

// BL1: the time to contain and the share contained alone of a campaign (analysis/containment.py),
// computed from the same files as its facts.
function secs(s) {
  if (s == null) return '—';
  if (s < 60) return `${Number(s).toFixed(1)} s`;
  const m = Math.floor(Math.round(s) / 60), r = Math.round(s) % 60;
  return `${m} min ${String(r).padStart(2, '0')} s`;
}

function renderContainment(c) {
  if (!c) return '';
  if (c.error) return `<div class="dsec" style="border-color:var(--yellow)"><div class="dtitle">RESPONSE</div><span style="color:var(--yellow)">${esc(c.error)}</span></div>`;
  const s = c.summary || {};
  const share = s.incidents ? `${s.lower_bound ? 'at least ' : ''}${esc(s.contained)} of ${esc(s.incidents)}` : 'no incident';
  const rows = (c.incidents || []).map(i => `<tr><td>${esc(i.run_id)}</td><td>${esc(i.ttp)}</td>
    <td title="${esc(i.target || '')}">${esc(vmName(i.target) || '—')}</td>
    <td class="wrap" style="color:${i.outcome === 'contained_alone' ? 'var(--green)' : 'var(--dim)'}">${esc(i.label)}</td>
    <td>${i.action ? esc(i.action) + ' ' + pct(i.confidence) : '—'}</td><td>${esc(secs(i.time_to_contain_s))}</td></tr>`).join('');
  const faults = (c.faults || []).map(f => `<div style="color:${f.mistaken && f.mistaken.length ? 'var(--red)' : 'var(--dim)'}">fault ${esc(f.run_id)} (${esc(f.fault || '—')}) — ${f.why
    ? 'not checked: ' + esc(f.why)
    : (f.mistaken && f.mistaken.length ? 'taken for an attack: ' + f.mistaken.map(m => esc(m.action) + (m.executed ? ' (executed)' : ' (recommended)')).join(', ') : 'no decision to isolate or to block during it')}</div>`).join('');
  return `<div class="dsec s-blue"><div class="dtitle">RESPONSE — contained alone ${share} · time to contain ${s.median_s != null ? esc(secs(s.median_s)) + ' (median)' : '— nothing contained alone'} (computed from the files, BL1)</div>
    ${rows ? `<table class="t"><tr><th>run</th><th>ttp</th><th>target</th><th>outcome</th><th>action</th><th>to contain</th></tr>${rows}</table>` : ''}
    ${faults || '<div style="color:var(--dim)">no fault in this campaign</div>'}
    ${(c.notes || []).map(n => `<div style="color:var(--yellow)">${esc(n)}</div>`).join('')}</div>`;
}

// ── Catalogue: this injector's techniques or faults ───────────────────────────────────
function lastExercised(id) {
  const ws = ((S.ex && S.ex.exercises) || []).filter(w => w.experiment_id === id);
  return ws.length ? ws[0] : null;   // newest first
}
function renderCatalog() {
  const list = $('cat-list');
  if (S.errors.cat) { list.innerHTML = `<div class="err">${esc(S.errors.cat)}</div>`; return; }
  if (!S.cat) return;
  if (S.cat.error) { list.innerHTML = `<div class="err">${esc(S.cat.error)}</div>`; return; }
  const entries = S.cat.entries || [];
  const impl = entries.filter(e => e.status === 'implemented');
  const exercised = impl.filter(e => lastExercised(e.id)).length;
  $('cat-count').textContent = `${impl.length} implemented · ${exercised} exercised in ${S.since === '24h' ? '24 h' : '7 days'}`;
  const groups = {};
  for (const e of entries) (groups[e.resource_type] = groups[e.resource_type] || []).push(e);
  list.innerHTML = Object.entries(groups).map(([rt, es]) => {
    es.sort((a, b) => (a.status === 'implemented' ? 0 : 1) - (b.status === 'implemented' ? 0 : 1) || String(a.id).localeCompare(String(b.id)));
    return `<div class="cat-group">${esc(rt.toUpperCase())}</div>` + es.map(e => {
      const w = lastExercised(e.id);
      let last = '<span style="color:var(--dim)">—</span>';
      if (w) { const r = response(w); last = `<a class="r-${r.cls}" href="?run=${encodeURIComponent(w.run_id)}" title="${esc(r.text)}">${ago(w.start)} ago</a>`; }
      return `<div class="cat ${e.status === 'implemented' ? '' : 'planned'}" title="${esc(e.name)} — ${esc(e.engine)} · ${esc(e.log_source || '')}${e.expected_latency_s ? ' · ~' + esc(e.expected_latency_s) + 's' : ''}">
        <span style="color:${e.kind === 'fault' ? 'var(--orange)' : 'var(--purple)'}">${e.kind === 'fault' ? '⚡' : '⚔'}</span>
        <span class="id">${esc(e.id)}</span>
        <span class="nm">${esc(e.name)} <small>${esc(e.tactic || e.engine)}${e.destructive ? ' · <span style="color:var(--red)">destructive</span>' : ''}${e.status !== 'implemented' ? ' · ' + esc(e.status) : ''}</small></span>
        <span class="last">${last}</span></div>`;
    }).join('');
  }).join('');
}

// ── Not set up here (a greyed tab): what this injector would add ──────────────────────
async function renderSetup(s, override) {
  $('main').hidden = true;
  const box = $('setup');
  box.hidden = false;
  let channel = '';
  try {
    const c = await getJSON('/api/channel');
    channel = (c.exercise_channel || {}).configured ? 'the exercise channel is configured' : 'no exercise channel configured';
  } catch (e) { channel = ''; }
  const why = override ? `this console was started with <code>--sections ${esc(override.join(',') || '…')}</code>, which leaves ${ABOUT.label} out`
    : `no ${ABOUT.label} run, window or campaign in runs/`;
  box.innerHTML = `<h2>${ABOUT.label.toUpperCase()} <small>— ${esc(s.role)} · not set up here</small></h2>
    <div class="line"><span class="k">What it adds</span><span>${esc(ABOUT.adds)}</span></div>
    <div class="line"><span class="k">What it needs</span><span>Glorfindel's watch running — ${ABOUT.label} requires it, and checks it before acting;
      Orodruin, the disposable host the injectors run from, armed; target VMs enrolled
      (<code>eregion-target</code>, <code>eregion-zone</code>); the exercise channel between Orodruin and this host.</span></div>
    <div class="line"><span class="k">How</span><span>${ABOUT.how}</span></div>
    <div class="line"><span class="k">Found here</span><span>${why}${channel ? '; ' + esc(channel) : ''}.<br>
      To show this section anyway: <code>eregion console --sections ${INJECTOR}</code></span></div>`;
}
function renderMain() { $('setup').hidden = true; $('main').hidden = false; }

// ── Fetching ──────────────────────────────────────────────────────────────────────────
const last = {};   // the last JSON text per source: render only on change
async function load(name, url, render) {
  try {
    const data = await getJSON(url);
    if (data && data.error && name !== 'cat') throw new Error(data.error);
    const text = JSON.stringify(data);
    delete S.errors[name];
    if (last[name] === text) return false;
    last[name] = text; S[name] = data;
  } catch (e) {
    S.errors[name] = `${url} — ${e.message}`;
  }
  render();
  return true;
}
async function refreshFast() {
  const changed = await load('ex', `/api/exercises?since=${S.since}&injector=${INJECTOR}`, renderExercises);
  if (changed) renderCatalog();   // "last exercised" follows the windows
}
async function refreshSlow() {
  if (INJECTOR !== 'annatar') return;
  await load('camp', `/api/campaigns?since=${S.campSince}`, renderCampaigns);
  const c = S.focus && S.focus.startsWith('c:') ? S.focus.slice(2) : null;
  if (c && !S.campDetail[c]) loadCampaignDetail(c);
}
async function refreshCatalog() { await load('cat', `/api/catalog?kind=${ABOUT.kind}`, renderCatalog); }

async function loadCampaignDetail(dir) {
  S.campDetail[dir] = 'loading'; renderCampaigns();
  try { S.campDetail[dir] = await getJSON(`/api/campaigns/${encodeURIComponent(dir)}`); }
  catch (e) { S.campDetail[dir] = { error: e.message }; }
  renderCampaigns();
}
async function loadDelivered(runId) {
  S.delivered[runId] = 'loading'; renderExercises();
  try { S.delivered[runId] = await getJSON(`/api/channel/detections/${encodeURIComponent(runId)}`); }
  catch (e) { S.delivered[runId] = { error: e.message }; }
  renderExercises();
}

// ── Events (delegated: no data inside inline handlers) ───────────────────────────────
document.addEventListener('click', ev => {
  const t = ev.target.closest('[data-toggle],[data-delivered],[data-report]');
  if (!t) return;
  if (t.dataset.toggle) {
    const key = t.dataset.toggle;
    S.open.has(key) ? S.open.delete(key) : S.open.add(key);
    if (key.startsWith('c:')) {
      const dir = key.slice(2);
      if (S.open.has(key) && !S.campDetail[dir]) loadCampaignDetail(dir); else renderCampaigns();
    } else renderExercises();
  } else if (t.dataset.delivered) {
    loadDelivered(t.dataset.delivered);
  } else if (t.dataset.report) {
    const dir = t.dataset.report;
    S.showReport.has(dir) ? S.showReport.delete(dir) : S.showReport.add(dir);
    renderCampaigns();
  }
});
function remember(key, value) {
  try { localStorage.setItem(key, value); } catch (_) { /* private mode */ }
}
$('since').addEventListener('change', e => {
  S.since = e.target.value; remember('console.windows.since', S.since); refreshFast();
});
if ($('camp-since')) $('camp-since').addEventListener('change', e => {
  S.campSince = e.target.value; remember('console.campaigns.since', S.campSince); refreshSlow();
});

let started = false;
function start() {
  if (started) return;
  started = true;
  refreshCatalog(); refreshFast(); refreshSlow();
  setInterval(refreshFast, 10000);
  setInterval(refreshSlow, 30000);
  setInterval(refreshCatalog, 300000);
  // Running timers and grace countdowns move without new data.
  setInterval(() => { if (S.ex && (S.ex.exercises || []).some(w => w.state === 'open' || w.state === 'grace')) renderExercises(); }, 5000);
}

(function init() {
  try {
    const s = localStorage.getItem('console.windows.since');
    if (s === '24h' || s === '7d') { S.since = s; $('since').value = s; }
    const c = localStorage.getItem('console.campaigns.since');
    if (c && $('camp-since') && ['7d', '30d', 'all'].includes(c)) { S.campSince = c; $('camp-since').value = c; }
  } catch (_) { /* private mode */ }
  // Active or greyed: /api/sections decides. The page shows the runs as soon as the section
  // is active, and what it would add while it is greyed.
  Console.onSections(d => {
    const s = (d.sections || []).find(x => x.id === INJECTOR);
    if (s && !s.active) { renderSetup(s, d.override); return; }
    renderMain(); start();
  });
})();
