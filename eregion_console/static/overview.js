Console.init('overview');

const D = { sections: null, judge: null, report: null, ex: null, camp: null, chan: null };
const ROLE_ROW = {
  annatar: { absent: 'no attack has tested Glorfindel here' },
  gothmog: { absent: 'no fault has tested Glorfindel here' },
};

function glorfindelRow(s) {
  const lines = [];
  const n = D.judge ? D.judge.length : null;
  lines.push(`<div class="line">
    <a href="/glorfindel" class="big ${n ? 'warn' : 'ok'}">${n == null ? '…' : n ? `${n} to judge ▸` : 'nothing to judge'}</a>
    <span class="dim">${D.sections && D.sections.read_only ? 'mode <b style="color:var(--blue)">OBSERVE-ONLY</b> · human-only' : 'each VM acts per its mode (Glorfindel, Config)'}</span>
  </div>`);
  if (s && s.setup && !s.setup.configured)
    lines.push(`<div class="line warn"><span>not configured yet on this host — no glorfindel-config.yaml and no watch heartbeat: start with <code>glorfindel watch</code> (<a href="/glorfindel">Glorfindel ▸</a>)</span></div>`);
  return lines.join('');
}

function lastRun(injector) {
  const ws = ((D.ex && D.ex.exercises) || []).filter(w => w.injector === injector);
  return ws.length ? ws[0] : null;
}

function runLine(w) {
  const r = response(w);
  return `<div class="line"><span class="k">last run</span>
    <a href="/runs/${encodeURIComponent(w.run_id)}">${esc(w.experiment)}</a>
    <span class="dim">${ago(w.start)} ago</span>
    <span class="r-${r.cls}">${w.kind === 'fault' ? '⚡' : '⚔'} ${esc(r.text)}</span>
    ${runChip(w)}</div>`;
}

function campaignLine() {
  const c = ((D.camp && D.camp.campaigns) || []).find(x => !x.error);
  if (!c) return '';
  const sc = c.scenarios || [], ex = sc.filter(s => s.status === 'executed');
  const n = k => ex.filter(s => (s.detection || 'unknown') === k).length;
  // V1: a campaign run --without-glorfindel measured nothing, by choice — not « unknown ».
  const counts = c.without_glorfindel ? `${ex.length}/${sc.length} executed · <span class="dim">not measured, by choice (--without-glorfindel)</span>` : null;
  return `<div class="line"><span class="k">last campaign</span>
    <a href="/annatar?campaign=${encodeURIComponent(c.dir)}">${esc(c.campaign_id || c.dir)}</a>
    <span class="dim">${hms(c.created_at)}</span>
    <span>${counts || `${ex.length}/${sc.length} executed · <span class="ok">${n('detected')} detected</span>${n('missed') ? ` · <span class="bad">${n('missed')} missed</span>` : ''}${n('unknown') ? ` · <span class="warn">${n('unknown')} unknown</span>` : ''}`}</span></div>`;
}

function injectorRow(s) {
  if (!s.active)
    return `<div class="line dim"><span>not set up — ${ROLE_ROW[s.id].absent} (<a href="/${encodeURIComponent(s.id)}">what it adds ▸</a>)</span></div>`;
  const w = lastRun(s.id);
  const lines = [w ? runLine(w) : `<div class="line dim"><span>no ${esc(s.label)} window in the last 7 days (<a href="/${encodeURIComponent(s.id)}">${esc(s.label)} ▸</a>)</span></div>`];
  if (s.id === 'annatar') lines.push(campaignLine());
  return lines.join('');
}

function channelsRow() {
  const c = D.chan;
  if (!c) return '<div class="line dim">…</div>';
  const ec = c.exercise_channel || {}, rc = c.return_channel || {};
  const live = c.live_windows || [];
  let beat = '<span class="dim">return channel not configured — runs read the local watch files</span>';
  if (rc.configured) beat = rc.error ? `<span class="bad" title="${esc(rc.error)}">return channel unreadable</span>`
    : `<span class="${rc.alive ? 'ok' : 'warn'}">published beat ${dur(rc.age_s)} ago</span>${rc.alive ? '' : ' <span class="warn">— a run reads it as no watch</span>'}`;
  const unlisted = rc.unlisted_windows || [];
  return `<div class="line">
    <span>${ec.configured ? '<span class="ok">exercise channel on</span>' : '<span class="dim">local only (no exercise channel)</span>'}${ec.newest_window_at ? ` <span class="dim">· newest window ${ago(ec.newest_window_at)} ago</span>` : ''}</span>
    <span><span class="k">live windows</span> ${live.length ? live.map(esc).join(', ') : '<span class="dim">none</span>'}</span>
    <span>${beat}</span>
    ${unlisted.length ? `<span class="warn" title="A run of these windows cannot conclude to a miss yet">⚠ not listed: ${unlisted.map(esc).join(', ')}</span>` : ''}
  </div>`;
}

// ── The five indicators ──────────────────────────────────────────────────────────────
const box = (lbl, val, sub, cls = '', title = '') =>
  `<div class="ind ${cls}" title="${esc(title)}"><div class="lbl">${lbl}</div><div class="val">${val}</div><div class="sub">${sub}</div></div>`;
const pc = r => (r == null ? '—' : Math.round(r * 100) + '%');

function indicators() {
  const i = D.ind;
  if (!i) return '';
  const days = Number(i.window_days), c = i.contain, a = i.alone, w = i.wrong, cov = i.coverage, lp = i.last_proof;
  const timed = c.detected
    ? `detect ${dur(c.detect_s)}${c.decide_s != null ? ' · decide ' + dur(c.decide_s) : ''} <span title="medians">(median, ${esc(c.detected)} detected attack${c.detected > 1 ? 's' : ''}, ${days} d)</span>`
    : `no detected attack in ${days} d`;
  const contain = box('TIME TO CONTAIN', c.contain_s != null ? dur(c.contain_s) : '— nothing contained alone',
    timed, '', 'From the attack to the verified action — only what Glorfindel contained alone. Detect: from the attack to the detection the run counted; decide: to the recommendation (run reports and the watch\'s cycles, ' + days + ' days).');
  const alone = box('CONTAINED ALONE', a.of ? `${esc(a.contained)} of ${esc(a.of)}` : '—',
    a.of ? `shadow: ${esc(a.shadow)} of ${esc(a.of)} would have been` : `no detected attack in ${days} d`, '',
    `Real: isolations and blocks executed and verified alone. Shadow: the detected attacks on which Glorfindel recommended to isolate or to block at or above the confidence gate (${a.threshold == null ? 'unreadable: every action held' : Math.round(a.threshold * 100) + '%'}), not judged wrong — what it would have contained, had it been allowed to act (${days} days).`);
  const w30 = w.days_30, w7 = w.days_7;
  const wrong = box('WRONG DISRUPTIVE', w30.judged ? `${pc(w30.rate)} of ${esc(w30.judged)} judged` : '— none judged',
    `real traffic, ${days} d · 7 d: ${w7.judged ? pc(w7.rate) + ' of ' + esc(w7.judged) : 'none judged'}`,
    w30.wrong ? 'warn' : '', 'Isolations and blocks judged wrong, among those judged (right or wrong), on real traffic — exercise cards left out (glorfindel report). The last 7 days, those of the Monday summary, aside.');
  const coverage = box(`COVERAGE · ${days} d`, `${esc(cov.implemented_detected)} / ${esc(cov.implemented)} implemented`,
    `${esc(cov.catalog_detected)} / ${esc(cov.catalog)} of the catalogue · faults: ${cov.faults ? esc(cov.faults) + ' run' + (cov.faults > 1 ? 's' : '') + ', ' + esc(cov.faults_pass) + ' PASS' : 'none'}`,
    '', 'Techniques detected by an attack run of the last ' + days + ' days, over those the bench can play (implemented), then over the whole catalogue, planned ones included. Faults aside.');
  const age = lp ? lp.age_s / 86400 : null;
  const stale = (i.stalest || []).map(s => `${s.ttp}: ${s.at ? ago(s.at) + ' ago' : 'not in ' + days + ' d'}`).join(' · ');
  const proof = box('LAST PROOF', lp ? `${ago(lp.at)} ago · ${esc(lp.ttp)}` : `none in ${days} d`,
    lp ? (age < 21 ? '✓ under 30 days' : age <= 30 ? '⚠ nearly 30 days' : '✗ over 30 days') + ` · <a href="/runs/${encodeURIComponent(lp.run_id)}">run ▸</a>` : 'no attack detected with a decision',
    !lp || age > 30 ? 'bad' : age >= 21 ? 'warn' : 'ok',
    'The most recent attack detected with a decision of Glorfindel attached (detection and response). Each technique, the stalest first: ' + stale);
  return contain + alone + wrong + coverage + proof;
}

function render() {
  const sections = (D.sections && D.sections.sections) || [];
  if (!sections.length) return;
  document.getElementById('ind').innerHTML = indicators();
  document.getElementById('observe-banner').hidden = !(D.sections && D.sections.read_only);
  const injectorsOn = sections.some(s => !s.always && s.active);
  const rows = sections.map(s => {
    const body = s.id === 'glorfindel' ? glorfindelRow(s) : injectorRow(s);
    return `<div class="row s-${esc(s.id)}${s.active ? '' : ' greyed'}" title="${esc(s.label)} — ${esc(s.role)}">
      <div class="name"><a href="/${esc(s.id)}">${esc(s.label.toUpperCase())}</a></div>
      <div class="lines">${body}</div></div>`;
  });
  if (injectorsOn) rows.push(`<div class="row"><div class="name dim">CHANNELS</div><div class="lines">${channelsRow()}</div></div>`);
  else rows.push(`<div class="row"><div class="name dim">PROOF</div><div class="lines"><div class="line dim">none yet: Glorfindel's detection and response are unproven on this infrastructure — Annatar and Gothmog prove it</div></div></div>`);
  document.getElementById('ov').innerHTML = rows.join('');
}

async function refresh() {
  const get = (url) => getJSON(url).catch(() => null);
  const injectorsOn = ((D.sections && D.sections.sections) || []).some(s => !s.always && s.active);
  const [judge, ind, ex, camp, chan] = await Promise.all([
    get('/api/to-judge?since=7d'), get('/api/indicators'),
    injectorsOn ? get('/api/exercises?since=7d') : null,
    injectorsOn ? get('/api/campaigns?since=30d') : null,
    injectorsOn ? get('/api/channel') : null,
  ]);
  if (judge && Array.isArray(judge.cards)) { D.judge = judge.cards; Console.setJudgeCount(judge.cards.length); }
  if (ind && ind.window_days) D.ind = ind;
  if (ex && !ex.error) D.ex = ex;
  if (camp && !camp.error) D.camp = camp;
  if (chan && !chan.error) D.chan = chan;
  render();
}

let started = false;
Console.onSections(d => {
  D.sections = d;
  render();
  if (!started) { started = true; refresh(); setInterval(refresh, 30000); }
});
