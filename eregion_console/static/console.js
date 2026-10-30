// The console's shared header (docs/design/console.md): EREGION, then the tabs — Overview,
// Glorfindel always, Dagorlad (Annatar's and Gothmog's runs, §7) greyed while neither injector is
// set up (/api/sections) —, then on the right
// the watch's beat, the return channel when an injector is active, Config, and the clock in
// UTC, like every time shown in the console. The same on every page: what belongs to one page
// (the live feed's dot) stays in that page. Each page calls Console.init(<its tab>) first.
const Console = (() => {
  const TABS = [
    { id: 'overview',   label: 'Overview',   href: '/',           role: 'Eregion at a glance' },
    { id: 'glorfindel', label: 'Glorfindel', href: '/glorfindel' },
    { id: 'dagorlad',   label: 'Dagorlad',   href: '/dagorlad',   role: 'attacks and faults drawn against Glorfindel, and their runs' },
  ];
  // On the right, where the War Room had it (Jonathan, 26/10).
  const CONFIG = { id: 'config', label: '⚙ Config', href: '/config', role: 'how Glorfindel and this console are set' };
  let active = null, sections = null, judge = null;
  const listeners = [];

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g,
      c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  const $ = id => document.getElementById(id);
  const section = id => ((sections && sections.sections) || []).find(s => s.id === id);
  const injectorActive = () => ['annatar', 'gothmog'].some(id => (section(id) || {}).active);

  function tab(t) {
    const s = section(t.id);
    // Dagorlad holds both injectors: greyed only once the sections say neither is set up here.
    const greyed = t.id === 'dagorlad' ? Boolean(sections) && !injectorActive() : Boolean(s && !s.active);
    const title = s ? `${s.label} — ${s.role}${greyed ? ' · not set up here: what it would add' : ''}`
      : `${t.label.replace('⚙ ', '')} — ${t.role}${greyed ? ' · neither Annatar nor Gothmog is set up here' : ''}`;
    const badge = t.id === 'glorfindel' && judge ? `<span class="badge" title="Cards to judge (7 days)">${judge}</span>` : '';
    return `<a class="tab${t.id === active ? ' active' : ''}${greyed ? ' greyed' : ''}" href="${t.href}" title="${esc(title)}">${esc(t.label)}${badge}</a>`;
  }

  function renderTabs() {
    const nav = $('c-nav'), cfg = $('c-config');
    if (nav) nav.innerHTML = TABS.map(tab).join('');
    if (cfg) cfg.innerHTML = tab(CONFIG);
  }

  // What this console runs, beside the logo: the deployed tag, else the version and the commit.
  function renderVersion() {
    const el = $('c-version'), v = sections && sections.version;
    if (!el || !v) return;
    el.textContent = v.label;
    el.title = [v.ref && `deployed tag ${v.ref}`, v.revision && `${v.source === 'checkout' ? 'checkout' : 'deployed'} commit ${v.revision}`,
                v.package && `package ${v.package}`].filter(Boolean).join(' · ');
  }

  async function getJSON(url) {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  async function refreshSections() {
    try {
      const d = await getJSON('/api/sections');
      if (d.error) throw new Error(d.error);
      sections = d;
    } catch (e) { return; }
    renderTabs();
    renderVersion();
    listeners.forEach(cb => { try { cb(sections); } catch (_) { /* a page's own error */ } });
    refreshChannel();
  }

  async function refreshWatch() {
    const dot = $('c-watch-dot'), label = $('c-watch-label');
    try {
      const w = await getJSON('/api/watch/status');
      const color = { running: 'var(--green)', stale: 'var(--orange)', stopped: 'var(--red)' }[w.status] || 'var(--dim)';
      dot.style.color = color; label.style.color = color;
      label.textContent = w.status === 'running' ? `watch · ${w.age_s}s ago`
        : w.status === 'stale' ? `watch stale · ${Math.round((w.age_s || 0) / 60)}m ago` : `watch ${w.status || 'unknown'}`;
    } catch (e) { label.textContent = 'watch unknown'; }
  }

  // The heartbeat the watch publishes, what a run on Orodruin reads: only with an injector.
  async function refreshChannel() {
    const box = $('c-rc');
    if (!box) return;
    if (!injectorActive()) { box.hidden = true; return; }
    box.hidden = false;
    try {
      const rc = (await getJSON('/api/channel')).return_channel || {};
      let color = 'var(--dim)', text = 'return channel off';
      if (rc.configured) {
        if (rc.error) { color = 'var(--red)'; text = 'return channel unreadable'; }
        else { color = rc.alive ? 'var(--green)' : 'var(--yellow)'; text = `return channel · ${rc.age_s}s ago`; }
      }
      $('c-rc-dot').style.color = color;
      $('c-rc-label').textContent = text;
      box.title = rc.alive === false ? 'A run on Orodruin reads this as no watch' : 'The heartbeat the watch publishes — what a run on Orodruin reads';
    } catch (e) { $('c-rc-label').textContent = 'return channel ?'; }
  }

  async function refreshJudge() {
    try {
      const q = await getJSON('/api/to-judge?since=7d');
      if (Array.isArray(q.cards)) setJudgeCount(q.cards.length);
    } catch (e) { /* the badge stays as it was */ }
  }

  function setJudgeCount(n) {
    const count = Number(n) || 0;       // a count, whoever gives it (#257)
    if (judge === count) return;
    judge = count;
    renderTabs();
  }

  function tick() {
    const c = $('c-clock');
    if (c) c.textContent = new Date().toISOString().slice(11, 19) + ' UTC';
  }

  // UTC, like the clock: HH:MM:SS today, else MM-DD HH:MM.
  function hms(v) {
    const d = v === null || v === undefined || v === '' ? null
      : new Date(typeof v === 'number' ? v * 1000 : v);
    if (!d || isNaN(d)) return '—';
    const iso = d.toISOString();
    return iso.slice(0, 10) === new Date().toISOString().slice(0, 10)
      ? iso.slice(11, 19) : `${iso.slice(5, 10)} ${iso.slice(11, 16)}`;
  }

  function init(page, opts = {}) {
    active = page;
    const h = $('console-header');
    h.classList.add('console');
    h.innerHTML = `<a class="logo" href="/" title="Eregion — Glorfindel defends, Annatar and Gothmog prove it">EREGION</a>
      <span id="c-version" class="ver"></span>
      <nav id="c-nav"></nav>
      <span class="spacer"></span>
      <span class="hstat" title="The watch's heartbeat (~/.glorfindel/watch_heartbeat)"><span id="c-watch-dot" class="dot">●</span> <span id="c-watch-label">watch…</span></span>
      <span class="hstat" id="c-rc" hidden><span class="sep">│</span> <span id="c-rc-dot" class="dot">●</span> <span id="c-rc-label">return channel…</span></span>
      <nav id="c-config"></nav>
      <span id="c-clock"></span>`;
    renderTabs();
    tick(); setInterval(tick, 1000);
    refreshSections(); setInterval(refreshSections, 30000);
    refreshWatch(); setInterval(refreshWatch, 15000);
    if (opts.judge !== false) { refreshJudge(); setInterval(refreshJudge, 30000); }
  }

  // A page that needs the sections (a greyed page, the overview, the config) subscribes.
  function onSections(cb) {
    listeners.push(cb);
    if (sections) cb(sections);
  }

  return { init, onSections, setJudgeCount, hms, esc, section };
})();
