// Dagorlad (docs/design/console.md, §7, phases a to c): the red cards (the catalogue's techniques
// and faults), the blue ones (Glorfindel, the enrolled targets), and the plan of the wires drawn
// between them. The page sends two identifiers per wire, the server judges each one as Orodruin
// would (GET /api/dagorlad/plan) and says what to expect. « Request run » writes a request for
// Orodruin (POST /api/dagorlad/requests, the same two identifiers per wire), and the page shows the
// command that carries it there: nothing is launched from here, no name is typed here, Glorfindel
// is never told. Then each wire is followed live (GET /api/dagorlad/requests/<id>, read only): its
// chronology from the windows, the watch's cycles, the cards and the run's report. The wires stay
// locked until the request is over, then each keeps its last result. Needs console.js and exercises.js.
Console.init('dagorlad');
document.title = 'Eregion — Dagorlad';
const $ = id => document.getElementById(id);
$('page-title').innerHTML = '<b>DAGORLAD</b> <span>— attacks and faults drawn against Glorfindel. ' +
  'This page launches nothing: a request goes to Orodruin by a command you run, and Glorfindel is never told · times UTC</span>';

// ── State ─────────────────────────────────────────────────────────────────────────────
const S = {
  board: null, plan: null, err: '', planErr: '',
  note: '',         // what the last gesture did not do (a pair drawn already)
  wires: [],        // [experiment id, target resource id], in the order drawn — this browser only
  picked: null,     // the red card picked (its index), waiting for a target
  drag: null,       // {i, x, y}: a red card's handle being dragged
  request: null,    // the request written (phase b), until it is over: its wires are locked
  requestErr: '',
  follow: null,     // the request followed (phase c): Orodruin's status, each wire's chronology
  last: null,       // the request over: its view — each of its wires keeps its last result
  lastAt: 0,        // when it was seen over (ms): its reports may still arrive, followed a while
  stop: null,       // « Stop all »: the command, what it stops, what stays in flight
  stopErr: '',
};
const KEY = 'console.dagorlad.wires';
const REQ_KEY = 'console.dagorlad.request';
const REQ_ID = /^r-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$/;
const MAX_WIRES = 100;
const FOLLOW_AFTER_MS = 30 * 60 * 1000;   // a request over is followed this long for its reports
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

function save() {
  try { localStorage.setItem(KEY, JSON.stringify(S.wires)); } catch (_) { /* private mode */ }
}
// The request followed, running or over, kept in this browser (a convenience): a reload finds it.
function saveRequest() {
  try {
    const q = S.request || S.last;
    if (q) localStorage.setItem(REQ_KEY, JSON.stringify(q)); else localStorage.removeItem(REQ_KEY);
  } catch (_) { /* private mode */ }
}
// A wire is drawn once: drawing the same pair again removes nothing (several wires go to one
// target) — the page says so. A wire is removed by its own ✕, on its pill or its plan line.
function addWire(experiment, target, name) {
  S.note = '';
  if (S.request) S.note = `locked: request ${S.request.request} runs — only « Stop all » acts until it is over`;
  else if (S.wires.some(w => w[0] === experiment && same(w[1], target))) S.note = `already drawn: ${experiment} → ${name}`;
  else if (S.wires.length >= MAX_WIRES) S.note = `at most ${MAX_WIRES} wires`;
  else { S.wires.push([experiment, target]); save(); }
  refreshPlan();
}

// ── Actions: each element names its own, the dispatcher calls it from this closed table ──
function _on(event, action, ...args) {
  return `data-on-${event}="${action}"` + (args.length ? ` data-${event}-args="${esc(JSON.stringify(args))}"` : '');
}
let _event = null;
const ACTIONS = {
  pick(i) {
    const r = S.board && S.board.reds[i];
    if (!r || !r.available) return;
    S.picked = S.picked === i ? null : i;
    renderBoard();
  },
  aim(j) {
    const t = S.board && S.board.targets[j];
    const r = S.board && S.picked !== null ? S.board.reds[S.picked] : null;
    if (t && r) addWire(r.id, t.resource_id, t.name);
  },
  grab(i) {
    const r = S.board && S.board.reds[i];
    if (!r || !r.available || !_event) return;
    _event.preventDefault();
    S.drag = { i, x: _event.clientX, y: _event.clientY };
    drawWires();
  },
  drop(j) {
    const t = S.board && S.board.targets[j];
    const r = S.board && S.drag ? S.board.reds[S.drag.i] : null;
    S.drag = null;
    if (t && r) addWire(r.id, t.resource_id, t.name); else drawWires();
  },
  unwire(k) {
    if (S.request || k < 0 || k >= S.wires.length) return;
    S.wires.splice(k, 1);
    S.note = '';
    save(); refreshPlan();
  },
  clear() {
    if (S.request) return;
    S.wires = []; S.picked = null; S.note = ''; S.last = null; S.follow = null;
    save(); saveRequest(); refreshPlan();
  },
  // Phase (b): the request, written by the console in its own directory — never a launch. Over,
  // the same gesture runs the same wires again: a new request.
  request() { if (!S.request) sendRequest(); },
  // A request Orodruin has not heard of (the command not carried): dropped here, nothing else.
  // Once Orodruin runs it, only « Stop all » acts — the console has no way to tell it to stop.
  newPlan() {
    if (!S.request || phaseOf() !== 'written') return;
    S.request = null; S.requestErr = ''; S.follow = null;
    saveRequest(); renderPlan(); drawWires();
  },
  // « Stop all »: the console revokes nothing — it shows Orodruin's emergency stop, to run.
  stopAll() { if (S.stop) { S.stop = null; renderPlan(); } else loadStop(); },
};
const _EVENTS = { click: 'click', pointerdown: 'pointerdown', pointerup: 'pointerup' };
function _dispatch(ev, name) {
  const el = ev.target instanceof Element ? ev.target.closest(`[data-on-${name}]`) : null;
  if (!el) return;
  const action = el.getAttribute(`data-on-${name}`);
  if (!Object.hasOwn(ACTIONS, action)) return;
  let args = [];
  try { args = JSON.parse(el.getAttribute(`data-${name}-args`) || '[]'); } catch (e) { return; }
  // Indexes into the page's own lists: never an object.
  if (!Array.isArray(args) || !args.every(a => a === null || ['string', 'number', 'boolean'].includes(typeof a))) return;
  _event = ev;
  try { ACTIONS[action](...args); } finally { _event = null; }
}
for (const [type, name] of Object.entries(_EVENTS)) document.addEventListener(type, ev => _dispatch(ev, name), true);

// ── Red cards: the catalogue, each with its last proof (the coverage matrix, C1) ───────
const PROOF = {
  proven: ['c-ok', 'proven'], aging: ['c-warn', 'aging'], stale: ['c-bad', 'stale'],
  regressed: ['c-bad', 'REGRESSED'], unproven: ['c-warn', 'no proof'], never: ['', 'never run'],
  unknown: ['c-warn', 'proof unreadable'],
};
function proofChip(p) {
  const [cls, label] = p && Object.hasOwn(PROOF, p.state) ? PROOF[p.state] : PROOF.never;
  const age = p && p.proof_age_s != null && p.state !== 'regressed' ? ` ${dur(Number(p.proof_age_s))}` : '';
  const tip = p && p.error ? p.error : p && p.last_run ? `last run ${p.last_run} · see it in Runs` : 'no run of it on this host';
  return `<span class="chip ${esc(cls)}" title="${esc(tip)}">${esc(label)}${esc(age)}</span>`;
}
function redCard(r, i) {
  const fault = r.kind === 'fault';
  const destr = r.destructive === true ? '<span class="chip c-bad">DESTRUCTIVE · bench, twin</span>'
    : r.destructive === false ? '<span class="chip c-ok">non-destructive</span>'
    : '<span class="chip c-warn">destructive: undeclared</span>';
  const rules = Array.isArray(r.rules) ? r.rules.join(', ') : '';
  const expect = fault ? 'expect: nothing disruptive' : rules ? `detected by ${rules}` : 'no rule: Glorfindel blind';
  const meta = [r.tactic, r.injector, r.engine].filter(Boolean).join(' · ');
  const tip = r.available ? 'Pick it, then one or more targets — or drag its handle onto a target' : r.why;
  return `<button type="button" class="rcard${r.available ? '' : ' off'}${S.picked === i ? ' sel' : ''}" id="red-${i}" ${_on('click', 'pick', i)} title="${esc(tip)}">
    <span><span class="rid${fault ? ' fault' : ''}">${esc(r.id)}</span> <span class="rname">${esc(r.name)}</span></span>
    <span class="meta">${esc(meta)} ${proofChip(r.proof)}</span>
    <span class="rfoot">${destr} <span class="rexp">${esc(r.available ? expect : r.why)}</span></span>
    ${r.available ? `<span class="handle${fault ? ' fault' : ''}" ${_on('pointerdown', 'grab', i)} title="Drag onto a target"></span>` : ''}
  </button>`;
}

// ── Blue cards: Glorfindel, the enrolled targets ──────────────────────────────────────
const ZONE_CLS = { bench: 'c-ok', twin: 'c-blue', production: 'c-bad' };
const MODE_LABEL = { human_only: 'HUMAN-ONLY', non_disruptive: 'NON-DISRUPTIVE' };
function glorfindelCard(g) {
  const w = g.watch || {};
  const live = !g.gate;
  const backends = Array.isArray(g.backends) && g.backends.length ? g.backends.join(', ') : 'no backend';
  return `<div class="gcard">
    <div><b>GLORFINDEL</b> <span class="${live ? 'r-ok' : 'r-bad'}">● ${live ? `watching${Number.isFinite(Number(w.age_s)) ? ` · ${Number(w.age_s)}s ago` : ''}` : 'no live watch'}</span></div>
    <div class="bmeta">${Number(g.rules)} rules${g.client_rules ? ` (${Number(g.client_rules)} yours)` : ''} · ${esc(backends)} · default ${esc(g.default_mode)}${g.read_only ? ' · read-only' : ''}</div>
    <div class="bmeta">never told what the red side plans</div>
    ${g.gate ? `<div class="err">${esc(g.gate)}</div>` : ''}
  </div>`;
}
function blueCard(t, j) {
  const wired = S.wires.some(w => same(w[1], t.resource_id));
  const holds = (Array.isArray(t.holds_now) ? t.holds_now : [])
    .map(h => `<span class="chip c-bad">${esc(String(h).toUpperCase())}</span>`).join(' ');
  const seen = t.seen ? `seen ${ago(t.seen)} ago · ${t.backend}` : 'not seen by the watch now';
  const live = followedOn(t.resource_id);
  return `<button type="button" class="bcard${wired ? ' wired' : ''}${S.picked !== null ? ' armed' : ''}" id="blue-${j}" ${_on('click', 'aim', j)} ${_on('pointerup', 'drop', j)} title="${esc(t.resource_id)}">
    <span class="bname">${esc(t.name)}</span>
    <span class="bchips"><span class="chip ${esc(ZONE_CLS[t.zone] || '')}">${esc(String(t.zone).toUpperCase())}</span>
      <span class="chip${t.mode === 'non_disruptive' ? ' c-warn' : ''}">${esc(MODE_LABEL[t.mode] || t.mode)}</span>${t.read_only ? ' <span class="chip">READ-ONLY</span>' : ''} ${holds}</span>
    <span class="bmeta">${esc(seen)} · ${Number(t.rules)} rules${t.hold ? ` · held: ${esc(t.hold)}` : ''}</span>
    ${live ? `<span class="blive">${esc(live)}</span>` : ''}
  </button>`;
}

function renderBoard() {
  const red = $('red-list'), blue = $('blue-list');
  if (S.err) {
    red.innerHTML = `<div class="empty err">${esc(S.err)}</div>`;
    blue.innerHTML = '';
    return;
  }
  if (!S.board) return;
  const reds = S.board.reds || [], targets = S.board.targets || [];
  $('red-count').textContent = `${reds.filter(r => r.available).length} of ${reds.length} ready`;
  $('blue-count').textContent = `${targets.length} enrolled`;
  const rt = red.scrollTop, bt = blue.scrollTop;
  red.innerHTML = reds.map(redCard).join('') ||
    '<div class="empty">The catalogue is empty.</div>';
  const others = (S.board.other_types || []).map(o =>
    `<div class="ocard">${esc(o.type)} · ${Number(o.implemented)} implemented of ${Number(o.entries)} · no target enrolled</div>`).join('');
  blue.innerHTML = glorfindelCard(S.board.glorfindel || {}) +
    (S.board.targets_error ? `<div class="empty err">${esc(S.board.targets_error)}</div>` : '') +
    (targets.map(blueCard).join('') ||
      '<div class="empty">No enrolled target in the bench: Celebrimbor enrolls its VMs (eregion-target, eregion-zone).</div>') +
    others;
  red.scrollTop = rt; blue.scrollTop = bt;
  drawWires();
}

// ── Wires ─────────────────────────────────────────────────────────────────────────────
// Where a card meets its wire, in the board's coordinates; a card scrolled out of its list
// is held at the list's edge.
function point(el, side, box) {
  const r = el.getBoundingClientRect(), list = el.parentElement.getBoundingClientRect();
  const y = Math.min(Math.max(r.top + r.height / 2, list.top), list.bottom);
  return { x: Math.round((side === 'right' ? r.right : r.left) - box.left), y: Math.round(y - box.top) };
}
function bez(t, a, c1, c2, b) {
  const u = 1 - t;
  return { x: Math.round(u * u * u * a.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x + t * t * t * b.x),
           y: Math.round(u * u * u * a.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t * t * t * b.y) };
}
function verdictOf(w) {
  return ((S.plan && S.plan.wires) || []).find(v => v.experiment === w[0] && same(v.target, w[1])) || null;
}
function wireStyle(red, v) {
  if (!v) return 'w-wait';
  if (v.code) return 'w-refused';
  if (red.kind === 'fault') return 'w-fault';
  return (v.warnings || []).some(x => x.code === 'typed_name') ? 'w-warn' : 'w-ok';
}
function pillText(v) {
  if (!v) return 'judging…';
  if (v.code) return `✕ ${v.code}`;
  const warn = (v.warnings || []).filter(x => x.code !== 'typed_name').map(x => x.code);
  const typed = (v.warnings || []).some(x => x.code === 'typed_name') ? 'type the VM name · ' : '';
  return typed + ((v.expected && v.expected.summary) || 'may run') + (warn.length ? ` · ⚠ ${warn.join(', ')}` : '');
}
function curve(a, b) {
  const dx = Math.max(60, (b.x - a.x) * 0.45);
  return { c1: { x: a.x + dx, y: a.y }, c2: { x: b.x - dx, y: b.y } };
}
function drawWires() {
  const svg = $('wires'), pills = $('pills');
  if (!S.board) { svg.innerHTML = ''; pills.innerHTML = ''; return; }
  const box = $('board').getBoundingClientRect();
  const reds = S.board.reds || [], targets = S.board.targets || [];
  let paths = '', labels = '';
  const placed = [];   // the pills already laid: a new one moves down until it overlaps none
  S.wires.forEach((w, k) => {
    const i = reds.findIndex(r => r.id === w[0]), j = targets.findIndex(t => same(t.resource_id, w[1]));
    if (i < 0 || j < 0 || !$(`red-${i}`) || !$(`blue-${j}`)) return;
    const a = point($(`red-${i}`), 'right', box), b = point($(`blue-${j}`), 'left', box);
    // A wire of the request followed says where it is, then its last result; else its verdict.
    const l = lineOf(w), r = l ? lineResult(l) : null, v = verdictOf(w), c = curve(a, b);
    const style = r ? r.style : wireStyle(reds[i], v), text = r ? r.text : pillText(v);
    const p = bez([0.5, 0.36, 0.64][k % 3], a, c.c1, c.c2, b);
    const half = Math.min(280, text.length * 6 + 18) / 2;
    for (let n = 0; n < 8 && placed.some(q => Math.abs(q.x - p.x) < q.half + half && Math.abs(q.y - p.y) < 19); n++) p.y += 20;
    placed.push({ x: p.x, y: p.y, half });
    paths += `<path class="${esc(style)}" d="M${a.x} ${a.y} C${c.c1.x} ${c.c1.y} ${c.c2.x} ${c.c2.y} ${b.x} ${b.y}"/>`;
    labels += `<div class="pill ${esc(style)}" style="left:${p.x}px;top:${p.y}px" title="${esc(text)}"><span class="pt">${esc(text)}</span>` +
      (S.request ? '' : `<button type="button" class="px" ${_on('click', 'unwire', k)} title="Remove this wire">✕</button>`) + '</div>';
  });
  if (S.drag && $(`red-${S.drag.i}`)) {
    const a = point($(`red-${S.drag.i}`), 'right', box);
    const b = { x: Math.round(S.drag.x - box.left), y: Math.round(S.drag.y - box.top) }, c = curve(a, b);
    paths += `<path class="w-drag" d="M${a.x} ${a.y} C${c.c1.x} ${c.c1.y} ${c.c2.x} ${c.c2.y} ${b.x} ${b.y}"/>`;
  }
  svg.innerHTML = paths;
  pills.innerHTML = labels;
}

// ── The plan ──────────────────────────────────────────────────────────────────────────
const STATUS = { ok: ['c-ok', 'MAY RUN'], warn: ['c-warn', 'MAY RUN · ⚠'], refused: ['c-bad', 'REFUSED'],
                 unknown: ['c-warn', 'MAY RUN · ?'] };
function planRow(v) {
  const k = S.wires.findIndex(w => w[0] === v.experiment && same(w[1], v.target));
  // A fault whose engine's targets this host cannot read: not a warning, an unknown.
  const unread = v.status === 'warn' && (v.warnings || []).every(w => w.code === 'engine_unknown');
  const st = STATUS[unread ? 'unknown' : v.status] || ['', ''];
  const x = v.expected || {};
  const rules = Array.isArray(x.rules) && x.rules.length ? `rule: ${x.rules.join(', ')}` : '';
  const what = v.code
    ? `<span class="r-bad">${esc(v.code)}</span> — ${esc(v.reason)}`
    : `${esc(x.summary || '')}${rules ? ` <span class="meta">· ${esc(rules)}</span>` : ''}<div class="meta">${esc(x.glorfindel || '')}</div>`;
  const warns = (v.warnings || []).map(w => `<div class="warns">⚠ ${esc(w.code)} — ${esc(w.text)}</div>`).join('');
  // A wire of the last request, over: its last result, and its run.
  const l = lineOf([v.experiment, v.target]), r = l ? lineResult(l) : null;
  const last = r ? `<div><span class="${esc(RESULT_CLS[r.style] || '')}">last: ${esc(r.text)}</span>${runLink(l.run)}</div>` : '';
  return `<tr><td class="ord">${v.order ? '#' + Number(v.order) : '—'}</td>
    <td style="white-space:nowrap"><span class="rid">${esc(v.experiment)}</span> → ${esc(v.target_name)}${v.zone ? ` <span class="meta">${esc(v.zone)}</span>` : ''}</td>
    <td><span class="chip ${esc(st[0])}">${esc(st[1])}</span></td>
    <td class="wrap">${what}${warns}${last}</td>
    <td>${k >= 0 && !S.request ? `<button type="button" class="mini" ${_on('click', 'unwire', k)} title="Remove this wire">✕</button>` : ''}</td></tr>`;
}
function renderPlan() {
  const box = $('plan');
  if (S.request) { box.innerHTML = followView(); return; }
  if (!S.wires.length) {
    box.innerHTML = `<div class="plan-head"><b>PLAN</b> <span class="meta">no wire yet</span>${S.note ? ` <span class="r-warn">${esc(S.note)}</span>` : ''}
      <button type="button" class="mini stopbtn" ${_on('click', 'stopAll')} title="Orodruin's emergency stop: the command, what it stops, what stays in flight">Stop all</button></div>
      ${stopBox()}
      <div class="empty">Pick a red card, then one or more targets — or drag a red card's handle onto a target;
      several wires may go to one target, and a wire's ✕ removes it. The server judges each wire as Orodruin would,
      and says what to expect; nothing is launched, nothing is written.</div>`;
    return;
  }
  if (S.planErr) { box.innerHTML = `<div class="err">${esc(S.planErr)}</div>`; return; }
  const p = S.plan;
  if (!p) { box.innerHTML = '<div class="meta">judging the wires…</div>'; return; }
  const t = p.total || {};
  const checks = (p.checks || []).map(c => {
    const [cls, mark] = c.ok === true ? ['r-ok', '✓'] : c.ok === false ? ['r-bad', '✕'] : ['r-warn', '?'];
    return `<span class="${cls}">${mark} ${esc(c.text)}</span>`;
  }).join('');
  const may = Number(t.allowed) > 0 && Number(t.refused) === 0;
  // Over, the same wires run again in one gesture: a new request.
  const again = sameAsLast();
  const ask = `<button type="button" class="mini" ${_on('click', 'request')}${may ? '' : ' disabled'}
      title="${may ? 'Write a request for Orodruin — the page gives the command that carries it' : 'Remove the refused wires first'}">${again ? 'Run again' : 'Request run from Orodruin'}</button>`;
  box.innerHTML = `<div class="plan-head"><b>PLAN</b>
      <span>${Number(t.wires)} wire(s) · ${Number(t.refused)} refused · ~${Math.round(Number(t.estimate_s) / 60)} min · one after the other</span>
      <span class="meta">what Orodruin will check before anything runs — the page launches nothing</span>
      ${ask}
      <button type="button" class="mini" ${_on('click', 'clear')}>Clear wires</button>
      <button type="button" class="mini stopbtn" ${_on('click', 'stopAll')} title="Orodruin's emergency stop: the command, what it stops, what stays in flight">Stop all</button>
      ${S.note ? `<span class="r-warn">${esc(S.note)}</span>` : ''}</div>
    ${stopBox()}
    ${S.requestErr ? `<div class="err">${esc(S.requestErr)}</div>` : ''}
    ${lastLine()}
    <div class="checks">${checks}</div>
    <table class="t">${(p.wires || []).map(planRow).join('')}</table>`;
}

// ── The request followed (phases b, c): the command that carries it, then each wire live ──
// Read from what reaches this host (GET /api/dagorlad/requests/<id>, eregion_console/follow.py):
// the windows, the watch's cycles, the cards, the run's report — a run measured as on the
// overview (BL1, C1). Nothing is written; the watch is told nothing.
const followed = () => S.request || S.last;
const followOf = q => (q && S.follow && S.follow.request === q.request ? S.follow : null);
function phaseOf() {
  const f = followOf(followed());
  return f ? f.phase : S.request ? 'written' : '';
}
// The line of a wire of the request followed — before the first answer, its rank, queued.
function lineOf(w) {
  const q = followed();
  const own = q && (q.wires || []).find(x => x.experiment === w[0] && same(x.target, w[1]));
  if (!own) return null;
  const f = followOf(q);
  const l = f && (f.wires || []).find(x => x.experiment === w[0] && same(x.target, w[1]));
  return l || (S.request ? { rank: own.rank, experiment: own.experiment, target: own.target, target_name: own.target_name,
                             kind: '', state: 'queued', heard: false, code: '', run: '', cards: [], mistaken: [] } : null);
}
// BL1's endings (analysis/containment.py OUTCOMES), as the pill says them.
const OUTCOME = {
  contained_alone: ['w-good', 'contained'], not_holding: ['w-bad', 'contained, then it did not hold'],
  verification_failed: ['w-bad', 'executed, not verified'], action_failed: ['w-bad', 'action failed'],
  held_by_guard: ['w-warn', 'held'], escalated: ['w-warn', 'escalated to a human'],
  not_containing: ['w-warn', 'nothing that contains'], dry_run: ['w-warn', 'dry run'],
  missed: ['w-bad', 'missed'], decision_unknown: ['w-warn', 'decision not found'],
};
const RESULT_CLS = { 'w-good': 'r-ok', 'w-bad': 'r-bad', 'w-refused': 'r-bad', 'w-warn': 'r-warn' };
const LIVE = ['open', 'grace'];
// Where a wire is, then its last result: « #1 ✓ detected +1m47 · contained 2m31 », « #2 ✗ missed ».
function lineResult(l) {
  const n = `#${Number(l.rank)} `;
  const win = l.window ? l.window.state : '';
  if (['refused', 'skipped', 'failed'].includes(l.state))
    return { style: l.state === 'skipped' ? 'w-warn' : 'w-refused', text: `${n}${l.state === 'skipped' ? '' : '✕ '}${l.state}${l.code ? ' · ' + l.code : ''}` };
  if (!l.run) return { style: 'w-wait', text: n + (phaseOf() === 'written' && !l.heard ? 'requested' : 'queued') };
  if (l.kind === 'fault') {
    const done = (l.mistaken || []).find(m => m.executed), seen = (l.mistaken || [])[0];
    if (done) return { style: 'w-bad', text: `${n}✕ ${done.action} executed during a fault` };
    if (seen) return { style: 'w-warn', text: `${n}⚠ ${seen.action} recommended during a fault` };
    if (win === 'open') return { style: 'w-fault', text: `${n}fault running · nothing disruptive so far` };
    const back = l.returned === true ? ` · returned${l.restore_s != null ? ' in ' + dur(Number(l.restore_s)) : ''}`
      : l.returned === false ? ' · its return NOT verified' : '';
    return { style: l.returned === false ? 'w-bad' : 'w-good', text: `${n}nothing disruptive${back}` };
  }
  if (l.outcome === 'missed') return { style: 'w-bad', text: `${n}✗ missed` };
  if (l.detected_at || l.detection === 'detected') {
    const o = OUTCOME[l.outcome] || ['w-ok', ''];
    // Before the run's report, measured from its window: said, on every time (≈).
    const about = l.provisional ? '≈' : '';
    const det = l.detect_s != null ? `✓ detected ${about}+${dur(Number(l.detect_s))}` : '✓ detected';
    const how = l.outcome === 'contained_alone' ? `contained${l.contain_s != null ? ' ' + about + dur(Number(l.contain_s)) : ''}`
      : o[1] + (o[1] && l.outcome_why ? ` (${l.outcome_why})` : '');
    return { style: o[0], text: `${n}${det}${how ? ' · ' + how : ''}` };
  }
  if (win === 'open') return { style: 'w-ok', text: `${n}running · waiting for a detection` };
  if (win === 'grace') return { style: 'w-ok', text: `${n}ended · a detection still counts (grace)` };
  return { style: 'w-warn', text: `${n}no detection seen${l.verdict ? '' : ' · report not here yet'}` };
}
const runLink = run => (run ? ` <a class="runlink" href="/dagorlad?view=runs&run=${encodeURIComponent(run)}" title="Its window, cycles, cards and report in Runs">run ▸</a>` : '');
const STATE_CHIP = { queued: '', running: 'c-blue', launched: 'c-blue', done: 'c-ok', skipped: 'c-warn', refused: 'c-bad', failed: 'c-bad' };
function decisionCell(l) {
  if (l.kind === 'fault') {
    const m = (l.mistaken || []).map(x => `${esc(x.action)} ${esc(pct(x.confidence))} ${x.executed ? 'executed' : 'recommended'} at ${esc(hms(x.at))}`);
    return m.length ? `<span class="r-bad">taken for an attack: ${m.join(', ')}</span>`
      : l.run ? `expects nothing disruptive${l.unchecked ? ` <span class="r-warn">· ${esc(l.unchecked)}</span>` : ''}` : '';
  }
  const d = l.decision;
  if (!d) return '';
  const how = d.executed === true ? (d.verified === true ? 'executed, verified on Azure' : 'executed, not verified')
    : d.guard ? `held: ${d.guard}` : d.status;
  return `${esc(d.action || 'no action')} ${esc(pct(d.confidence))}${how ? ' · ' + esc(how) : ''}${d.mode ? ` <span class="meta">(${esc(d.mode)})</span>` : ''}`;
}
function chronoRow(l) {
  const r = lineResult(l), fault = l.kind === 'fault';
  const win = l.window ? `window ${l.window.state}${l.window.closed_by ? ' · ' + l.window.closed_by : ''}`
    : l.run ? 'window gone from this host' : '';
  const refusal = l.window && l.window.refusal ? `<div class="r-bad">not believed by Glorfindel — ${esc(l.window.refusal)}</div>` : '';
  const t0 = l.t0 ? `T0 ${esc(hms(l.t0))}${l.provisional ? ' (the window\'s start, until its report)' : ''}` : '';
  const cards = l.cards || [], judge = cards.filter(c => c.to_judge).length;
  const v = l.verdict;
  const verdict = v ? `<span class="chip ${esc({ PASS: 'c-ok', FAIL: 'c-bad' }[v.result] || '')}">RUN ${esc(v.result || '?')}</span>` +
      (v.without_glorfindel ? ' <span class="chip">NOT MEASURED</span>' : v.detection ? ` <span class="chip">${esc(String(v.detection).toUpperCase())}</span>` : '')
    : l.run ? '<span class="meta">report not here yet</span>' : '';
  return `<tr><td class="ord">#${Number(l.rank)}</td>
    <td style="white-space:nowrap"><span class="rid${fault ? ' fault' : ''}">${esc(l.experiment || '?')}</span> → ${esc(l.target_name || '?')}</td>
    <td><span class="chip ${esc(STATE_CHIP[l.state] || '')}">${esc(String(l.state).toUpperCase())}${l.code ? ' · ' + esc(l.code) : ''}</span></td>
    <td class="wrap">${l.run ? `<span class="rid">${esc(l.run)}</span>` : ''}<div class="meta">${esc(win)}</div><div class="meta">${t0}</div>${refusal}</td>
    <td class="wrap"><span class="${esc(RESULT_CLS[r.style] || '')}">${esc(r.text.replace(/^#\d+ /, ''))}</span>${l.provisional && l.detected_at ? '<div class="meta">≈ provisional: from the window, until the run\'s report</div>' : ''}<div class="meta">${decisionCell(l)}</div></td>
    <td>${cards.length ? `<a href="/glorfindel" title="TO JUDGE is on Glorfindel's page">${Number(cards.length)} card(s)${judge ? `, ${Number(judge)} to judge` : ''} ▸</a>` : ''}</td>
    <td class="wrap">${verdict}${runLink(l.run)}</td></tr>`;
}
const PHASE = { written: ['c-warn', 'WRITTEN · NOT CARRIED YET'], running: ['c-blue', 'RUNNING'], over: ['c-ok', 'OVER'] };
const OVER_WHY = {
  finished: 'Orodruin finished it', refused: 'Orodruin refused it', stopped: '« Stop all » stopped it',
  silent: 'Orodruin silent longer than it ever is between two wires (35 min), no window of it live',
};
function orodruinLine(f) {
  const st = f && f.status;
  const contract = f && f.orodruin ? ` <span class="meta">· ${esc(f.orodruin.text)}</span>` : '';
  // There but refused: said, and never taken for « not heard yet » (A0).
  if (!st && f && f.status_error) return `<div class="r-warn">${esc(f.status_error)} — the request may be running on Orodruin.${contract}</div>`;
  if (!st) return `<div class="meta">Orodruin: not heard from yet${(f && f.phase === 'running') ? ' — a window of the request is here' : ' — the request runs once you carry it there'}.${contract}</div>`;
  return `<div>Orodruin: <b>${esc(st.state)}</b>${(st.codes || []).length ? ` (${esc(st.codes.join(', '))})` : ''}
    <span class="meta">at ${esc(hms(st.at))}</span>${contract}</div>`;
}
function followView() {
  const q = S.request, f = followOf(q), ph = phaseOf();
  const [pcls, plabel] = PHASE[ph] || ['', ph.toUpperCase()];
  const typed = (q.wires || []).filter(w => w.typed_name);
  const lines = (q.wires || []).map(w => lineOf([w.experiment, w.target])).filter(Boolean);
  const carry = ph !== 'written' ? '' : `<div>On your machine, run: <code>${esc(q.command)}</code>
        <button type="button" class="mini" ${_on('click', 'newPlan')} title="Drop it here — the request stays on this host: carried later, Orodruin would still judge and run it">New plan</button></div>
      <div class="meta">It pulls the request from this host, shows it wire by wire${typed.length ? `, asks you to type the name of ${Number(typed.length)} target(s)` : ''},
        then carries it to Orodruin, which judges it again and runs the wires one after the other. This page never asks for a name.</div>`;
  return `<div class="plan-head"><b>REQUEST</b> <span class="rid">${esc(q.request)}</span>
      <span class="chip ${esc(pcls)}">${esc(plabel)}</span>
      <span class="meta">written ${esc(hms(q.at))} · ${Number(lines.length)} wire(s), one after the other · locked until it is over: only « Stop all » acts</span>
      <button type="button" class="mini stopbtn" ${_on('click', 'stopAll')} title="Orodruin's emergency stop: the command, what it stops, what stays in flight">Stop all</button>
      ${S.note ? `<span class="r-warn">${esc(S.note)}</span>` : ''}</div>
    ${stopBox()}
    ${S.requestErr ? `<div class="err">${esc(S.requestErr)}</div>` : ''}
    <div class="request">${carry}${orodruinLine(f)}
      <div class="meta">Glorfindel is never told: each wire is read from its window, the watch's cycles, the cards and the run's report.</div></div>
    <table class="t chrono">${lines.map(chronoRow).join('')}</table>`;
}
// The last request, over: why, and that its wires keep their result.
function lastLine() {
  if (!S.last) return '';
  const f = followOf(S.last);
  const why = f ? (OVER_WHY[f.why] || f.why) : 'reading it again…';
  return `<div class="meta lastreq">Last request <span class="rid">${esc(S.last.request)}</span>, over: ${esc(why)}.
    Each of its wires keeps its last result${sameAsLast() ? '; « Run again » sends the same wires as a new request' : ''}.</div>`;
}
function sameAsLast() {
  const w = (S.last && S.last.wires) || [];
  return w.length > 0 && w.length === S.wires.length && w.every((x, i) => x.experiment === S.wires[i][0] && same(x.target, S.wires[i][1]));
}
// What the request running does on a target: its wire running, contained, its cards to judge.
// Over, the card says what /api/state says of the VM — never what an old request did to it.
function followedOn(rid) {
  const f = followOf(S.request);
  const lines = ((f && f.wires) || []).filter(l => same(l.target, rid));
  if (!lines.length) return '';
  const now = lines.find(l => l.window && l.window.state === 'open');
  const held = lines.find(l => l.outcome === 'contained_alone');
  const judge = lines.reduce((k, l) => k + (l.cards || []).filter(c => c.to_judge).length, 0);
  return [now ? `wire #${now.rank} runs on it` : '', held ? `contained by Glorfindel, verified (wire #${held.rank})` : '',
          judge ? `${judge} card(s) to judge` : ''].filter(Boolean).join(' · ');
}
function stopBox() {
  if (S.stopErr) return `<div class="err">${esc(S.stopErr)}</div>`;
  const s = S.stop;
  if (!s) return '';
  const row = w => `<li><span class="rid">${esc(w.run_id)}</span> ${esc(w.injector)} · ${esc(w.experiment)} → ${esc((w.targets || []).join(', '))}${w.request ? ` <span class="meta">${esc(w.request)}</span>` : ''}</li>`;
  return `<div class="request stop">
      <div><b>STOP ALL</b> <span class="meta">${esc(s.never)}</span>
        <button type="button" class="mini" ${_on('click', 'stopAll')}>Close</button></div>
      <div>On your machine, run: <code>${esc(s.command)}</code> — it revokes Orodruin's identity, cancels the chaos, stops its VM, closes the windows.</div>
      <div>It will stop ${(s.stops || []).length ? '' : '<span class="meta">no open window on this host</span>'}<ul>${(s.stops || []).map(row).join('')}</ul></div>
      ${(s.grace || []).length ? `<div class="meta">Already ended, still labelling their targets (grace):</div><ul>${s.grace.map(row).join('')}</ul>` : ''}
      <div class="meta">What stays in flight:</div><ul>${(s.in_flight || []).map(t => `<li class="meta">${esc(t)}</li>`).join('')}</ul></div>`;
}
async function loadStop() {
  S.stopErr = '';
  try {
    const d = await getJSON('/api/dagorlad/stop');
    if (d.error) throw new Error(d.error);
    S.stop = d;
  } catch (e) {
    S.stopErr = `/api/dagorlad/stop — ${e.message}`;
  }
  renderPlan();
}
// The request followed, read again: running, until it is over — then its wires unlock, each
// keeping its last result, and it is read a while longer (its reports come after its runs).
// A request kept in this browser that is not over locks its wires again.
async function refreshFollow() {
  const q = followed();
  if (!q || (!S.request && Date.now() - S.lastAt > FOLLOW_AFTER_MS)) return;
  try {
    const d = await getJSON('/api/dagorlad/requests/' + encodeURIComponent(q.request));
    if (followed() !== q || d.request !== q.request || d.error) return;
    S.follow = d;
    if (S.request && d.phase === 'over') {
      S.last = S.request; S.request = null; S.lastAt = Date.now();
    } else if (!S.request && d.phase !== 'over') {
      S.request = S.last; S.last = null;
      S.wires = (S.request.wires || []).map(w => [w.experiment, w.target]); save();
    }
  } catch (_) { return; }
  saveRequest();
  renderBoard(); renderPlan();   // the blue cards say what the request does on their target
}
async function sendRequest() {
  S.requestErr = '';
  const body = { wires: S.wires.map(w => ({ experiment: w[0], target: w[1] })) };
  try {
    const r = await fetch('/api/dagorlad/requests', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                                     body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok || d.error) throw new Error(d.error || `HTTP ${r.status}`);
    S.request = d; S.last = null; S.follow = null; S.note = '';
    saveRequest();
  } catch (e) {
    S.requestErr = `/api/dagorlad/requests — ${e.message}`;
  }
  renderPlan(); drawWires();
  refreshFollow();
}
// A request kept by this browser: its id, its command, its wires — of their shape, or nothing.
function storedRequest() {
  try {
    const q = JSON.parse(localStorage.getItem(REQ_KEY) || 'null');
    const ok = q && typeof q === 'object' && REQ_ID.test(String(q.request)) && typeof q.command === 'string'
      && Array.isArray(q.wires) && q.wires.length > 0 && q.wires.length <= MAX_WIRES
      && q.wires.every(w => w && typeof w.experiment === 'string' && typeof w.target === 'string');
    return ok ? q : null;
  } catch (_) { return null; }
}

// ── Fetching ──────────────────────────────────────────────────────────────────────────
async function loadBoard() {
  try {
    const d = await getJSON('/api/dagorlad/board');
    if (d.error) throw new Error(d.error);
    S.board = d; S.err = '';
  } catch (e) {
    S.err = `/api/dagorlad/board — ${e.message}`;
  }
  renderBoard();
}
let planSeq = 0;
async function refreshPlan() {
  const seq = ++planSeq;
  S.planErr = '';                          // the last plan stays shown until the new one comes
  renderBoard(); renderPlan();
  if (!S.wires.length) return;
  const query = S.wires.map(w => 'wire=' + encodeURIComponent(`${w[0]}@${w[1]}`)).join('&');
  try {
    const d = await getJSON('/api/dagorlad/plan?' + query);
    if (seq !== planSeq) return;           // a newer plan was asked for
    if (d.error) throw new Error(d.error);
    S.plan = d;
  } catch (e) {
    if (seq !== planSeq) return;
    S.planErr = `/api/dagorlad/plan — ${e.message}`;
  }
  renderPlan(); drawWires();
}

(function init() {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || '[]');
    if (Array.isArray(saved)) {
      S.wires = saved.filter(w => Array.isArray(w) && w.length === 2 && w.every(x => typeof x === 'string'))
        .slice(0, MAX_WIRES);
    }
  } catch (_) { /* private mode, or something else there */ }
  // The request followed before the reload: read again — still running, its wires lock again.
  S.last = storedRequest();
  S.lastAt = S.last ? Date.now() : 0;
  loadBoard().then(refreshPlan).then(refreshFollow);
  setInterval(() => loadBoard().then(refreshPlan), 30000);
  setInterval(refreshFollow, 10000);
  window.addEventListener('resize', drawWires);
  $('red-list').addEventListener('scroll', drawWires, { passive: true });
  $('blue-list').addEventListener('scroll', drawWires, { passive: true });
  document.addEventListener('pointermove', ev => {
    if (!S.drag) return;
    S.drag.x = ev.clientX; S.drag.y = ev.clientY;
    drawWires();
  });
  // A drop outside a target: the capture listener above found no action, the drag ends here.
  document.addEventListener('pointerup', () => { if (S.drag) { S.drag = null; drawWires(); } });
})();
