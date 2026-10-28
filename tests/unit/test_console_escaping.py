"""#254 — the console writes nothing from the outside raw into its pages.

A card, a rule, a feed entry, an error: text from Azure (a resource's or an Entra application's
name), from the model, from a rule — written raw into innerHTML, it runs in the operator's
console and can call its routes. scripts/console_escaping.py follows what each `${…}` of an
HTML template, and each value given to innerHTML, can hold; this file holds the console to it,
and holds the reader to what it must find, on small pages written here.
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

# The page's escapes, as glorfindel.html writes them.
PRELUDE = """
function _attr(s) { return String(s ?? '').replace(/&/g, '&amp;'); }
function _js(s) { return _attr(JSON.stringify(String(s ?? ''))); }
const TABLE = [{ label: 'NSG' }, { label: 'Backup' }];
const LABELS = { isolate_vm: 'Isolate' };
const el = document.getElementById('x');
"""


def _raw(tmp_path: Path, script: str) -> list[str]:
    """The ${…} (or innerHTML values) the reader finds raw on a page holding `script`."""
    (tmp_path / "page.html").write_text(f"<html><body><script>{PRELUDE}{script}</script></body></html>")
    return sorted(f.sink for f in ce.Unit("page.html", tmp_path).findings())


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
    body = _function((STATIC / "glorfindel.html").read_text(), "_attr")
    assert body.startswith("return String(s ?? '')"), body
    for char, entity in (("&", "&amp;"), ('"', "&quot;"), ("'", "&#39;"), ("<", "&lt;"), (">", "&gt;")):
        assert f".replace(/{char}/g, '{entity}')" in body, char
    assert body.index("/&/g") < body.index('/"/g'), "& first, or the other entities are escaped again"


def test_js_makes_a_javascript_string_of_a_handlers_argument():
    """In an on… attribute the browser decodes `&#39;` before the handler runs: the value goes in
    as a JSON string, then escaped for the attribute."""
    body = _function((STATIC / "glorfindel.html").read_text(), "_js")
    assert body == "return _attr(JSON.stringify(String(s ?? '')));", body


def test_the_shared_escape_of_the_other_pages():
    js = (STATIC / "console.js").read_text()
    assert "return String(s ?? '').replace(/[&<>\"']/g," in js
    assert "{ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]" in js


def test_no_page_writes_a_handler_argument_between_quotes():
    """`onclick="f('${x}')"`: the reader would refuse it — said here plainly too."""
    for page in ("glorfindel.html", "overview.html", "injector.html"):
        text = (STATIC / page).read_text()
        for attr in re.finditer(r'\bon[a-z]+="[^"]*"', text):
            assert not re.search(r"'\$\{[^}]*\}'", attr.group(0)), (page, attr.group(0)[:120])


# --- what the reader must find ------------------------------------------------------------

def test_a_field_of_what_the_server_sent_is_raw_unless_escaped(tmp_path):
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<b>${e.reason}</b><i>${_attr(e.reason)}</i><u>${e.list.length}</u>`;
}""")
    assert found == ["e.reason"]


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
  escs.forEach(e => { if (!map.has(e.vm)) map.set(e.vm, []); map.get(e.vm).push(e); });
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


def test_an_argument_of_a_handler_is_a_javascript_string(tmp_path):
    """HTML escaping is undone by the browser before the handler runs."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<button onclick="go('${_attr(e.id)}')">a</button>`
    + `<button onclick="go(${_js(e.id)})">b</button>`
    + e.list.map((x, i) => `<button onclick="pick(${i})">${_attr(x)}</button>`).join('');
}""")
    assert found == ["_attr(e.id)"]


def test_the_start_of_a_url_and_an_unquoted_attribute(tmp_path):
    """An escaped `javascript:` is still one; an attribute without quotes ends at a space."""
    found = _raw(tmp_path, """
async function load() {
  const e = await (await fetch('/api/x')).json();
  el.innerHTML = `<a href="${_attr(e.url)}">a</a><a href="/runs/${encodeURIComponent(e.id)}">b</a>`
    + `<div class=${_attr(e.cls)}>c</div><div class="${_attr(e.cls)}">d</div>`;
}""")
    assert found == ["_attr(e.cls)", "_attr(e.url)"]


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


@pytest.mark.parametrize("page", ["glorfindel.html", "overview.html", "injector.html"])
def test_the_reader_reads_every_template_of_the_page(page):
    """No template is skipped: the reader sees as many HTML templates as the file has."""
    unit = ce.Unit(page)
    assert len(unit.templates) > 10
    assert unit.sinks, page
