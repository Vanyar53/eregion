// Dagorlad (docs/design/console.md, §7, phase a): the red cards (the catalogue's techniques and
// faults), the blue ones (Glorfindel, the enrolled targets), and the plan of the wires drawn
// between them. Read only: the page sends two identifiers per wire, the server judges each one as
// Orodruin would (GET /api/dagorlad/plan) and says what to expect; nothing is launched, nothing
// is written, Glorfindel is never told. Needs console.js and exercises.js.
Console.init('dagorlad');
document.title = 'Eregion — Dagorlad';
const $ = id => document.getElementById(id);
$('page-title').innerHTML = '<b>DAGORLAD</b> <span>— attacks and faults drawn against Glorfindel. ' +
  'Plan only: this page launches nothing, and Glorfindel is never told · times UTC</span>';

// ── State ─────────────────────────────────────────────────────────────────────────────
const S = {
  board: null, plan: null, err: '', planErr: '',
  wires: [],        // [experiment id, target resource id], in the order drawn — this browser only
  picked: null,     // the red card picked (its index), waiting for a target
  drag: null,       // {i, x, y}: a red card's handle being dragged
};
const KEY = 'console.dagorlad.wires';
const MAX_WIRES = 100;
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

function save() {
  try { localStorage.setItem(KEY, JSON.stringify(S.wires)); } catch (_) { /* private mode */ }
}
function addWire(experiment, target) {
  if (S.wires.length >= MAX_WIRES || S.wires.some(w => w[0] === experiment && same(w[1], target))) return;
  S.wires.push([experiment, target]);
  save(); refreshPlan();
}
function toggleWire(experiment, target) {
  const k = S.wires.findIndex(w => w[0] === experiment && same(w[1], target));
  if (k < 0) { addWire(experiment, target); return; }
  S.wires.splice(k, 1);
  save(); refreshPlan();
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
  toggle(j) {
    const t = S.board && S.board.targets[j];
    const r = S.board && S.picked !== null ? S.board.reds[S.picked] : null;
    if (t && r) toggleWire(r.id, t.resource_id);
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
    if (t && r) addWire(r.id, t.resource_id); else drawWires();
  },
  unwire(k) {
    if (k < 0 || k >= S.wires.length) return;
    S.wires.splice(k, 1);
    save(); refreshPlan();
  },
  clear() { S.wires = []; S.picked = null; save(); refreshPlan(); },
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

// ── Red cards: the catalogue ──────────────────────────────────────────────────────────
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
    <span class="meta">${esc(meta)}</span>
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
    <div><b>GLORFINDEL</b> <span class="${live ? 'r-ok' : 'r-bad'}">● ${live ? `watching · ${Number(w.age_s)}s ago` : 'no live watch'}</span></div>
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
  return `<button type="button" class="bcard${wired ? ' wired' : ''}${S.picked !== null ? ' armed' : ''}" id="blue-${j}" ${_on('click', 'toggle', j)} ${_on('pointerup', 'drop', j)} title="${esc(t.resource_id)}">
    <span class="bname">${esc(t.name)}</span>
    <span class="bchips"><span class="chip ${esc(ZONE_CLS[t.zone] || '')}">${esc(String(t.zone).toUpperCase())}</span>
      <span class="chip${t.mode === 'non_disruptive' ? ' c-warn' : ''}">${esc(MODE_LABEL[t.mode] || t.mode)}</span>${t.read_only ? ' <span class="chip">READ-ONLY</span>' : ''} ${holds}</span>
    <span class="bmeta">${esc(seen)} · ${Number(t.rules)} rules${t.hold ? ` · held: ${esc(t.hold)}` : ''}</span>
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
    const v = verdictOf(w), style = wireStyle(reds[i], v), c = curve(a, b), text = pillText(v);
    const p = bez([0.5, 0.36, 0.64][k % 3], a, c.c1, c.c2, b);
    const half = Math.min(280, text.length * 6 + 18) / 2;
    for (let n = 0; n < 8 && placed.some(q => Math.abs(q.x - p.x) < q.half + half && Math.abs(q.y - p.y) < 19); n++) p.y += 20;
    placed.push({ x: p.x, y: p.y, half });
    paths += `<path class="${style}" d="M${a.x} ${a.y} C${c.c1.x} ${c.c1.y} ${c.c2.x} ${c.c2.y} ${b.x} ${b.y}"/>`;
    labels += `<div class="pill ${style}" style="left:${p.x}px;top:${p.y}px" title="${esc(text)}">${esc(text)}</div>`;
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
const STATUS = { ok: ['c-ok', 'MAY RUN'], warn: ['c-warn', 'MAY RUN · ⚠'], refused: ['c-bad', 'REFUSED'] };
function planRow(v) {
  const k = S.wires.findIndex(w => w[0] === v.experiment && same(w[1], v.target));
  const st = STATUS[v.status] || ['', ''];
  const x = v.expected || {};
  const rules = Array.isArray(x.rules) && x.rules.length ? `rule: ${x.rules.join(', ')}` : '';
  const what = v.code
    ? `<span class="r-bad">${esc(v.code)}</span> — ${esc(v.reason)}`
    : `${esc(x.summary || '')}${rules ? ` <span class="meta">· ${esc(rules)}</span>` : ''}<div class="meta">${esc(x.glorfindel || '')}</div>`;
  const warns = (v.warnings || []).map(w => `<div class="warns">⚠ ${esc(w.code)} — ${esc(w.text)}</div>`).join('');
  return `<tr><td class="ord">${v.order ? '#' + Number(v.order) : '—'}</td>
    <td style="white-space:nowrap"><span class="rid">${esc(v.experiment)}</span> → ${esc(v.target_name)}${v.zone ? ` <span class="meta">${esc(v.zone)}</span>` : ''}</td>
    <td><span class="chip ${esc(st[0])}">${esc(st[1])}</span></td>
    <td class="wrap">${what}${warns}</td>
    <td>${k >= 0 ? `<button type="button" class="mini" ${_on('click', 'unwire', k)} title="Remove this wire">✕</button>` : ''}</td></tr>`;
}
function renderPlan() {
  const box = $('plan');
  if (!S.wires.length) {
    box.innerHTML = `<div class="plan-head"><b>PLAN</b> <span class="meta">no wire yet · phase (a): a plan only</span></div>
      <div class="empty">Pick a red card, then one or more targets — or drag a red card's handle onto a target.
      The server judges each wire as Orodruin would, and says what to expect; nothing is launched, nothing is written.</div>`;
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
  box.innerHTML = `<div class="plan-head"><b>PLAN</b>
      <span>${Number(t.wires)} wire(s) · ${Number(t.refused)} refused · ~${Math.round(Number(t.estimate_s) / 60)} min · one after the other</span>
      <span class="meta">what Orodruin will check before anything runs — phase (a): nothing is launched</span>
      <button type="button" class="mini" ${_on('click', 'clear')}>Clear wires</button></div>
    <div class="checks">${checks}</div>
    <table class="t">${(p.wires || []).map(planRow).join('')}</table>`;
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
  loadBoard().then(refreshPlan);
  setInterval(() => loadBoard().then(refreshPlan), 30000);
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
