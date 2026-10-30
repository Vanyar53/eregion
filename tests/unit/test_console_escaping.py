"""#254, #257 — the console writes nothing from the outside raw into its pages, and runs no
script but its own files.

A card, a rule, a feed entry, an error: text from Azure (a resource's or an Entra application's
name), from the model, from a rule — written raw into innerHTML, it runs in the operator's
console and can call its routes. scripts/console_escaping.py follows what each `${…}` of an
HTML template, and each value given to innerHTML, can hold, and refuses what the CSP's
`script-src 'self'` blocks (#257: an inline handler or script) or what it does not follow; this
file holds the console to it, and holds the reader to what it must find, on small pages written
here.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("console_escaping", ROOT / "scripts" / "console_escaping.py")
ce = sys.modules[_spec.name] = importlib.util.module_from_spec(_spec)    # its dataclasses look it up
_spec.loader.exec_module(ce)

STATIC = ROOT / "eregion_console" / "static"

# The page's escapes, as glorfindel.js writes them.
PRELUDE = """
function _attr(s) { return String(s ?? '').replace(/&/g, '&amp;'); }
const TABLE = [{ label: 'NSG' }, { label: 'Backup' }];
const LABELS = { isolate_vm: 'Isolate' };
const el = document.getElementById('x');
"""


def _findings(tmp_path: Path, script: str, markup: str = "") -> list:
    """What the reader finds on a page loading `script` (a file, as the console's pages do)."""
    (tmp_path / "page.js").write_text(PRELUDE + script)
    (tmp_path / "page.html").write_text(f'<html><body>{markup}<script src="/static/page.js"></script></body></html>')
    return ce.Unit("page.html", tmp_path).findings()


def _raw(tmp_path: Path, script: str) -> list[str]:
    """The ${…} (or innerHTML values) the reader finds raw on a page holding `script`."""
    return sorted(f.sink for f in _findings(tmp_path, script) if f.origin)


def _refused(tmp_path: Path, script: str, markup: str = "") -> list[str]:
    """What the reader refuses wherever it is written (#257)."""
    return sorted(f.why.split(" (")[0] for f in _findings(tmp_path, script, markup) if not f.origin)


def test_nothing_from_the_outside_is_written_raw_into_the_console():
    """Every page of the console: a field of what the server sent, a callback's argument, an
    error, the address bar — escaped wherever it lands."""
    found = ce.check()
    assert not found, "written raw into the console:\n" + "\n".join(map(str, found))


def test_the_allowances_name_their_reason():
    """What the reader cannot follow and the page built is listed with why — none today."""
    for (file, sink), why in ce.ALLOWED.items():
        assert (STATIC / file).exists() and sink and len(why) > 20, (file, sink)


# --- the escapes themselves -----------------------------------------------------------

def _function(text: str, name: str) -> str:
    m = re.search(rf"function {name}\(s\) {{\n?(.*?)\n?\s*}}\n", text, re.S)
    assert m, name
    return " ".join(m.group(1).split())


def test_attr_escapes_what_html_gives_a_meaning_to_and_takes_any_value():
    """`_attr` is glorfindel.html's escape: a number, null or an object is text too (#254: a
    step that was not a string raised and the card's window no longer opened)."""
    body = _function((STATIC / "glorfindel.js").read_text(), "_attr")
    assert body.startswith("return String(s ?? '')"), body
    for char, entity in (("&", "&amp;"), ('"', "&quot;"), ("'", "&#39;"), ("<", "&lt;"), (">", "&gt;")):
        assert f".replace(/{char}/g, '{entity}')" in body, char
    assert body.index("/&/g") < body.index('/"/g'), "& first, or the other entities are escaped again"


def test_an_elements_action_and_its_arguments_are_attributes_escaped_like_any_other():
    """#257: no on… handler; `_on` writes the action's name and its arguments as JSON, escaped."""
    js = (STATIC / "glorfindel.js").read_text()
    assert "function _on(event, action, ...args) {\n  return `data-on-${event}=\"${action}\"` + (args.length ? " \
           "` data-${event}-args=\"${_attr(JSON.stringify(args))}\"` : '');\n}" in js


def test_the_page_dispatches_to_a_closed_table_from_the_nearest_element():
    """One listener per event, in the capture phase; the nearest element with an action takes
    the event (a button inside a card does not open the card); a name not in ACTIONS does
    nothing — never window[name], never code from an attribute."""
    js = (STATIC / "glorfindel.js").read_text()
    assert "ev.target instanceof Element ? ev.target.closest(`[data-on-${name}]`) : null;" in js
    assert "if (!Object.hasOwn(ACTIONS, action)) return;" in js
    assert "try { ACTIONS[action](...args); } finally { _event = _target = null; }" in js
    assert "document.addEventListener(type, ev => _dispatch(ev, name), true);" in js
    # names, ids, indexes, flags — never an object (a scope that would skip its window)
    assert "if (!Array.isArray(args) || !args.every(a => a === null || ['string', 'number', 'boolean']" \
           ".includes(typeof a))) return;" in js
    # a mode only from the page's own <select>, never from an element that carries a value
    assert "    if (!(_target instanceof HTMLSelectElement)) return;\n    if (_target.value === 'non_disruptive')" in js
    assert "defaultMode() { if (_target instanceof HTMLSelectElement) setDefaultMode(_target.value); }," in js
    assert "window[" not in js and "eval(" not in js and "new Function" not in js


def test_every_action_the_pages_name_is_in_the_table():
    """A data-on-* naming no action is a button that does nothing: each one is in ACTIONS."""
    js = (STATIC / "glorfindel.js").read_text()
    table = js[js.index("const ACTIONS = {"):js.index("\n};", js.index("const ACTIONS = {"))]
    named = set(re.findall(r"\b(\w+)(?=[,\n]|\()", table))
    used = set(re.findall(r"_on\('[a-z]+', '(\w+)'", js))
    used |= set(re.findall(r'data-on-[a-z]+="(\w+)"', (STATIC / "glorfindel.html").read_text()))
    assert used and used <= named, sorted(used - named)


def test_scripts_come_from_the_consoles_files_only():
    """#257: the CSP refuses inline scripts and handlers, javascript: URLs and eval; no page has
    one left (the reader refuses them too, in the scripts' templates and strings)."""
    import eregion_console.api as api
    directives = dict(d.strip().split(" ", 1) for d in api._CSP.split(";"))
    assert directives["script-src"] == "'self'" and directives["object-src"] == "'none'"
    pages = {page: (STATIC / page).read_text() for page in ("glorfindel.html", "overview.html", "injector.html", "dagorlad.html")}
    pages["the token page"] = api._TOKEN_PAGE
    for page, html in pages.items():
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), page
        assert not re.search(r"(?<![\w-])on[a-z]+\s*=", html), page


def test_the_shared_escape_of_the_other_pages():
    js = (STATIC / "console.js").read_text()
    assert "return String(s ?? '').replace(/[&<>\"']/g," in js
    assert "{ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]" in js


@pytest.mark.parametrize("page", ["glorfindel.html", "overview.html", "injector.html", "dagorlad.html"])
def test_the_reader_reads_every_interpolation_of_the_scripts(page):
    """S6 of #256's review: as many ${…} read as the files hold, counted apart — a template the
    tokenizer skipped (a regex taken for a division…) would hide its writes."""
    unit = ce.Unit(page)
    for file, n in unit.interpolations.items():
        assert n == len(re.findall(r"\$\{", (STATIC / file).read_text())), file
    assert unit.templates and unit.sinks, page


# --- what the reader must find ------------------------------------------------------------

def test_a_field_of_what_the_server_sent_is_raw_unless_escaped(tmp_path):
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<b>${e.reason}</b><i>${_attr(e.reason)}</i><u>${e.list.filter(Boolean).length}</u>`;
}""")
    assert found == ["e.reason"]


def test_a_length_is_a_number_only_on_what_the_page_built(tmp_path):
    """S4: `{length: "<img onerror>"}` from the server is an object with a length."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  const mine = ['a', 'b'];
  el.innerHTML = `<b>${e.list.length}</b><i>${Number(e.list.length)}</i><u>${mine.length}</u>`
    + `<s>${Object.keys(e).length}</s><q>${(e.list || []).length}</q>`;
}""")
    assert found == ["(e.list || []).length", "e.list.length"]


def test_a_fallback_to_the_raw_value_is_raw(tmp_path):
    """The labels' `|| e.action` (#254): a known label, else the raw name."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<b>${LABELS[e.action] || e.action}</b><i>${LABELS[e.action] || '?'}</i>`;
}""")
    assert found == ["LABELS[e.action] || e.action"]


def test_each_branch_is_followed_and_a_condition_is_not_written(tmp_path):
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<b>${e.ok ? 'fine' : e.why}</b><i>${e.ok && 'fine'}</i><s>${e.n > 1 ? 's' : ''}</s>`;
}""")
    assert found == ["e.ok ? 'fine' : e.why"]


def test_a_variable_is_followed_to_its_declaration_and_its_assignments(tmp_path):
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  let label = 'none';
  if (e.ok) label = `${e.action} held`;
  const safe = 'fixed';
  el.innerHTML = `<b>${label}</b><i>${safe}</i>`;
}""")
    assert found == ["label"]


def test_a_parameter_is_followed_to_the_arguments_of_its_calls(tmp_path):
    """The page's own helpers are clean when every call gives them the page's text."""
    found = _raw(tmp_path, """
function chip(t) { return `<b>${t}</b>`; }
function tag(t) { return `<i>${t}</i>`; }
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = chip('ok') + chip(e.name) + tag('fine') + tag(_attr(e.name));
}""")
    assert found == ["t"]


def test_a_callbacks_argument_holds_its_arrays_items(tmp_path):
    """`items.map(x => …)`: x is an item of what the server sent; of a page table, clean. A
    callback whose array is unseen (a promise's) holds the outside."""
    found = _raw(tmp_path, """
async function load() {
  const items = await (await fetch('/api/x')).json();
  el.innerHTML = items.map(x => `<li>${x.name}</li>`).join('') + TABLE.map((g, i) => `<li data-i="${i}">${g.label}</li>`).join('');
  fetch('/api/y').then(r => r.json()).then(d => { el.innerHTML = `<p>${d.title}</p>`; });
}""")
    assert found == ["d.title", "x.name"]


def test_what_is_put_into_a_map_comes_out_of_it(tmp_path):
    """`_groupEscs`: cards set into a Map, its values rendered — the onclick of the cards."""
    found = _raw(tmp_path, """
async function load() {
  const escs = await (await fetch('/api/x')).json();
  const map = new Map();
  escs.forEach(e => { const k = 'all'; if (!map.has(k)) map.set(k, []); map.get(k).push(e); });
  el.innerHTML = [...map.values()].map(g => `<b>${g[0].id}</b>`).join('');
}""")
    assert found == ["g[0].id"]


def test_a_count_by_reduce_is_a_number_a_join_by_reduce_is_not(tmp_path):
    found = _raw(tmp_path, """
async function load() {
  const rows = await (await fetch('/api/x')).json();
  const n = rows.reduce((a, r) => a + (r.ok ? 1 : 0), 0);
  const names = rows.reduce((a, r) => a + r.name, '');
  el.innerHTML = `<b>${n}</b><i>${names}</i>`;
}""")
    assert found == ["names"]


def test_a_field_of_an_object_the_page_wrote_is_read_by_its_key(tmp_path):
    """exercises.js `response(w)`: its `cls` a literal, its `text` made of the window."""
    found = _raw(tmp_path, """
function resp(w) { return w.ok ? { cls: 'ok', text: w.why } : { cls: 'bad', text: 'none' }; }
async function load() {
  const w = await (await fetch('/api/x')).json();
  const r = resp(w);
  el.innerHTML = `<b class="r-${r.cls}">${r.text}</b>`;
}""")
    assert found == ["r.text"]


def test_an_inline_handler_or_script_is_refused_whatever_its_escape(tmp_path):
    """#257: script-src 'self' blocks them; an element names its action instead (data-on-*). S3
    of #256's review (an escape between quotes in a handler) has nowhere left to be."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<button onclick="go('${_attr(e.id)}')">a</button><b data-on-click="go">${_attr(e.id)}</b>`;
}""")
    assert found == ["_attr(e.id)"]
    assert _refused(tmp_path, """
el.innerHTML = `<button onclick="go()">a</button>` + '<img src=x onerror=alert(1)>' + '<script>x()</script>'
  + `<a href="javascript:go()">b</a>`;""", markup='<div onmouseover="x()"><script>y()</script></div>') == [
        "a javascript: URL", "an inline handler", "an inline handler", "an inline handler",
        "an inline script", "an inline script"]


def test_the_start_of_a_url_and_an_unquoted_attribute(tmp_path):
    """An escaped `javascript:` is still one; after a leading "/" too (S8: `/${x}` with x =
    `/host` is another site); an attribute without quotes ends at a space."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<a href="${_attr(e.url)}">a</a><a href="/runs/${encodeURIComponent(e.id)}">b</a>`
    + `<a href="/${_attr(e.id)}">c</a><a href="/${encodeURIComponent(e.id)}">d</a>`
    + `<div class=${_attr(e.cls)}>e</div><div class="${_attr(e.cls)}">f</div>`;
}""")
    assert found == ["_attr(e.cls)", "_attr(e.id)", "_attr(e.url)"]


def test_a_concatenation_is_read_like_a_template(tmp_path):
    """S1: the place of a value is read from the strings before it, in `+` as in `${…}`."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = '<a href="' + _attr(e.url) + '">a</a>';
  el.innerHTML = '<b title="' + _attr(e.t) + '">' + _attr(e.t) + '</b>';
  el.innerHTML = '<i class=' + _attr(e.c) + '>';
}""")
    assert found == ["'<a href=\"' + _attr(e.url) + '\">a</a>'", "'<i class=' + _attr(e.c) + '>'"]


def test_srcdoc_takes_no_value(tmp_path):
    """S5: what srcdoc holds is read as a page — escaped or not."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<iframe srcdoc="${_attr(e.page)}"></iframe><b style="color:${_attr(e.c)}">x</b>`;
}""")
    assert found == ["_attr(e.page)"]


def test_the_apis_that_write_markup_or_code_elsewhere_are_refused(tmp_path):
    """S2: what the reader does not follow is not written at all."""
    assert _refused(tmp_path, """
document.write('<b>' + x);
el['innerHTML'] = x;
Object.assign(el, { innerHTML: x });
document.createRange().createContextualFragment(x);
new DOMParser().parseFromString(x, 'text/html');
el.setAttribute('onclick', x); el.setAttribute(name, x); el.setAttribute('href', x);
el.setAttribute('data-vm', x);
link.href = x;
setTimeout('go()', 10); setTimeout(() => go(), 10);
eval(x); new Function(x);""") == sorted([
        "document.write", "innerHTML by its name in brackets", "innerHTML in an object",
        "createContextualFragment", "DOMParser", "parseFromString",
        "setAttribute of a handler, a URL, an action or a name not written in the page",
        "setAttribute of a handler, a URL, an action or a name not written in the page",
        "setAttribute of a handler, a URL, an action or a name not written in the page",
        ".href =", "setTimeout given what may be a string", "eval", "new Function"])


def test_an_action_is_a_name_the_page_wrote_never_a_value(tmp_path):
    """#257's review: the action of a data-on-* comes from the page — never from a card, escaped
    or not (an injected name could call any action of the table)."""
    found = _raw(tmp_path, """
function _on(event, action, ...args) {
  return `data-on-${event}="${action}"` + (args.length ? ` data-${event}-args="${_attr(JSON.stringify(args))}"` : '');
}
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<b data-on-click="${_attr(e.action)}">a</b>`;
  el.innerHTML = `<b ${_on('click', _attr(e.action))}>b</b>`;
  el.innerHTML = `<b ${_on('click', 'showEscModal', e.vm, e.id)}>c</b>`;
}""")
    assert found == ["_attr(e.action)", "action"]
    assert _refused(tmp_path, """
el.setAttribute('data-on-click', x); el.dataset.onClick = x; el.dataset['onClick'] = x;
el.setAttribute('data-vm', x);""") == [
        "an action set from a value", "an action set from a value",
        "setAttribute of a handler, a URL, an action or a name not written in the page"]


def test_what_writes_elsewhere_is_refused_navigation_and_timers_too(tmp_path):
    """The rest of #257's review: setAttributeNS, a navigation, a timer given a value, a meta tag
    written by a script."""
    assert _refused(tmp_path, """
el.setAttributeNS(null, 'href', x);
location.assign(x); window.location = x; location.href = x;
setTimeout(e.code, 1); setTimeout(refresh, 10); setInterval(() => go(), 10); setTimeout(function () {}, 1);
el.innerHTML = '<meta http-equiv="refresh" content="0">';""") == sorted([
        "setAttributeNS", "a navigation the reader does not follow", "a navigation the reader does not follow",
        "a navigation the reader does not follow", ".href =", "setTimeout given what may be a string",
        "a meta tag written by a script"])


def test_a_const_string_before_a_value_says_where_it_lands(tmp_path):
    """A prefix held in a const is text: `const pre = '<a href="'; pre + _attr(u)`."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  const pre = '<a href="';
  el.innerHTML = pre + _attr(e.u) + '">a</a>';
  el.innerHTML = `${pre}${_attr(e.v)}">b</a>`;
  el.innerHTML = `<object data="${_attr(e.w)}"></object>`;
}""")
    assert found == ["_attr(e.v)", "_attr(e.w)", "pre + _attr(e.u) + '\">a</a>'"]


def test_a_name_bound_again_is_followed_and_its_length_is_no_number(tmp_path):
    """S4 after the review: a let can be rebound by a destructuring or a for…of — what it then
    holds is followed, and its .length is a number only on a const the page built."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  let a = []; [a] = [e.list]; el.innerHTML = `<b>${a.length}</b>`;
  let b = []; for (b of e.lists) {} el.innerHTML = `<i>${b.length}</i>`;
  let c = []; ({ c } = e); el.innerHTML = `<u>${c.length}</u>`;
  const d = ['x']; el.innerHTML = `<s>${d.length}</s>`;
}""")
    assert found == ["a.length", "b.length", "c.length"]


def test_a_function_an_object_hands_out_is_called_with_what_it_is_not_shown(tmp_path):
    """ACTIONS: the page's events call its functions with the arguments an element carries —
    data from the server."""
    found = _raw(tmp_path, """
function show(name) { el.innerHTML = `<b>${name}</b>`; }
function quiet(name) { el.innerHTML = `<b>${_attr(name)}</b>`; }
const ACTIONS = { show, quiet };""")
    assert found == ["name"]


def test_an_escape_is_known_by_its_declaration_not_its_name(tmp_path):
    """glorfindel.html has a local `esc` that is a card: calling it escapes nothing."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  const _attr = e.helper;
  el.innerHTML = `<b>${_attr(e.name)}</b>`;
}""")
    assert found == ["_attr(e.name)"]


def test_a_value_given_to_innerhtml_an_error_and_the_address_bar(tmp_path):
    found = _raw(tmp_path, """
async function load() {
  try { el.innerHTML = (await (await fetch('/api/x')).json()).message; }
  catch (err) { el.innerHTML = `<b>${err.message}</b>`; }
  el.innerHTML = `<i>${location.hash}</i>`;
}""")
    assert found == ["(await (await fetch('/api/x')).json()).message", "err.message", "location.hash"]


def test_a_replace_keeping_only_safe_characters_cleans(tmp_path):
    """injector.html `rowId`: whatever is not [A-Za-z0-9._-] becomes `_`."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<b id="row-${e.k.replace(/[^A-Za-z0-9._-]/g, '_')}">${e.k.replace(/x/g, '_')}</b>`;
}""")
    assert found == ["e.k.replace(/x/g, '_')"]


@pytest.mark.parametrize("page", ["glorfindel.html", "overview.html", "injector.html", "dagorlad.html"])
def test_the_reader_reads_every_template_of_the_page(page):
    """No template is skipped: the reader sees as many HTML templates as the file has."""
    unit = ce.Unit(page)
    assert len(unit.templates) > 10
    assert unit.sinks, page
