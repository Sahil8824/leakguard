// UI layer only: reads input, calls the scanner, renders results with textContent-safe DOM APIs.
import { describeDfa, recognize, tokenize } from './dfa-engine.js';
import { scanFiles, validateFile, LIMITS, SUPPORTED_EXTENSIONS, RULES } from './scanner.js';
import { toJSON, toCSV } from './report.js';

const $ = (id) => document.getElementById(id);
const DEMO_FILES = ['examples/vulnerable-demo.java', 'examples/safe-demo.java', 'examples/demo-config.env.example'];
const app = { result: null, selected: [], busy: false, mode: null, last: 'Not run' };

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') el.className = v; else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
  }
  el.append(...kids); // strings become text nodes, never HTML
  return el;
}
const setStatus = (text, kind = 'info') => { $('status').textContent = text; $('status').dataset.kind = kind; };

function refreshControls() {
  const b = app.busy;
  $('btnScan').disabled = b || $('editor').value.trim() === '';
  $('btnScanFiles').disabled = b || app.selected.length === 0;
  $('btnDemo').disabled = $('btnClear').disabled = b;
  $('btnJson').disabled = $('btnCsv').disabled = b || !app.result;
}

function renderDashboard() {
  const s = app.result?.summary;
  $('statFiles').textContent = s?.filesScanned ?? 0;
  $('statFindings').textContent = s?.totalFindings ?? 0;
  $('statHigh').textContent = s?.highSeverity ?? 0;
  $('statWith').textContent = s?.filesWithFindings ?? 0;
  $('statLast').textContent = app.last;
}

function renderFindings() {
  const sev = $('fSeverity').value, rule = $('fRule').value;
  const rows = (app.result?.findings ?? []).filter((f) => (!sev || f.severity === sev) && (!rule || f.ruleId === rule));
  const body = $('findings');
  body.replaceChildren();
  if (!rows.length) {
    body.append(h('tr', {}, h('td', { colspan: '7' }, app.result ? 'No potential findings match the filters.' : 'Run a scan to see findings.')));
    return;
  }
  for (const f of rows) {
    body.append(h('tr', {}, h('td', {}, h('span', { class: `sev ${f.severity.toLowerCase()}` }, f.severity)),
      h('td', {}, h('button', { class: 'link', type: 'button', onclick: () => showDetail(f) }, f.ruleId)),
      h('td', {}, f.type), h('td', {}, f.file), h('td', {}, `${f.line}:${f.column}`), h('td', {}, f.reason), h('td', {}, f.remediation)));
  }
}

function showDetail(f) {
  const dl = h('dl', {});
  const add = (k, v) => dl.append(h('dt', {}, k), h('dd', {}, v));
  add('What', `${f.type} (${f.ruleId}, ${f.severity})`);
  add('Where', `${f.file}, line ${f.line}, column ${f.column}`);
  add('Why it matched', f.reason);
  add('Detection kind', f.heuristic ? 'Heuristic (name + value characteristics)' : 'Pattern-specific (documented format)');
  add('Masked value', f.maskedValue);
  add('How to fix', f.remediation);
  add('Possible false positive', f.falsePositiveNote);
  $('detail').replaceChildren(h('h3', {}, 'Finding details'), dl, h('p', {}, 'Sanitized preview:'), h('pre', {}, f.preview),
    h('button', { type: 'button', onclick: () => runScan(app.mode ?? 'code') }, 'Rescan after editing'));
}

async function readSelected() {
  const files = [], skipped = [];
  for (const e of app.selected) {
    const v = validateFile(e);
    if (/(^|\/)(node_modules|\.git)\//.test(e.name)) { skipped.push(`${e.name}: ignored directory`); continue; }
    if (!v.ok) { skipped.push(`${e.name}: ${v.reason}`); continue; }
    if (files.length >= LIMITS.maxFiles) { skipped.push(`${e.name}: exceeds ${LIMITS.maxFiles}-file limit`); continue; }
    try {
      const text = await e.read();
      if (text.includes('\u0000')) skipped.push(`${e.name}: looks binary`); else files.push({ name: e.name, text });
    } catch { skipped.push(`${e.name}: unreadable`); }
  }
  return { files, skipped };
}

async function runScan(mode) {
  if (app.busy) return;
  app.busy = true; refreshControls(); setStatus('Scanning…');
  try {
    await new Promise((r) => setTimeout(r, 0)); // let the loading state paint
    let files, skipped = [];
    if (mode === 'code') {
      const name = $('fileName').value.trim() || 'pasted-code.txt', text = $('editor').value;
      const v = validateFile({ name, size: new Blob([text]).size });
      if (!v.ok) throw new Error(`${name}: ${v.reason}`);
      files = [{ name, text }];
    } else {
      ({ files, skipped } = await readSelected());
      if (!files.length) throw new Error('none of the selected files could be scanned (see list below).');
    }
    app.result = scanFiles(files); app.mode = mode;
    app.last = skipped.length ? `Done, ${skipped.length} skipped` : 'Completed';
    const n = app.result.summary.totalFindings;
    setStatus(`Scan complete: ${n} potential finding${n === 1 ? '' : 's'} in ${app.result.summary.filesScanned} file(s).`, 'ok');
    showSkipped(skipped);
  } catch (err) {
    app.result = null; app.last = 'Failed';
    setStatus(`Scan failed: ${err.message}`, 'error');
  } finally {
    app.busy = false; renderAll();
  }
}

function showSkipped(list) {
  const ul = $('skipped');
  ul.replaceChildren(...list.map((t) => h('li', {}, t)));
  ul.hidden = list.length === 0;
}
function renderSelected() { $('fileList').replaceChildren(...app.selected.map((e) => h('li', {}, e.name))); }
function renderAll() { renderDashboard(); renderFindings(); refreshControls(); }

function pick(input) {
  app.selected = [...input.files].map((f) => ({ name: f.webkitRelativePath || f.name, size: f.size, read: () => f.text() }));
  renderSelected(); showSkipped([]); setStatus(`${app.selected.length} file(s) selected.`); refreshControls();
}

async function loadDemo() {
  app.busy = true; refreshControls();
  try {
    const texts = await Promise.all(DEMO_FILES.map(async (p) => {
      const r = await fetch(p);
      if (!r.ok) throw new Error(p);
      return r.text();
    }));
    app.selected = DEMO_FILES.map((p, i) => ({ name: p.split('/').pop(), size: texts[i].length, read: async () => texts[i] }));
    $('editor').value = texts[0]; $('fileName').value = 'vulnerable-demo.java';
    renderSelected(); setStatus('Demo loaded (fictional data). Use Scan Code or Scan Selected Files.', 'ok');
  } catch (e) {
    setStatus(`Could not load demo files (${e.message}). Serve the folder over HTTP; opening index.html directly will not work.`, 'error');
  } finally { app.busy = false; refreshControls(); }
}

function clearAll() {
  $('editor').value = ''; $('fileInput').value = ''; $('dirInput').value = '';
  app.selected = []; app.result = null; app.mode = null; app.last = 'Not run';
  renderSelected(); showSkipped([]); $('detail').replaceChildren(h('p', { class: 'hint' }, 'Select a rule ID in the table to see details.'));
  setStatus('Cleared.'); renderAll();
}

function exportReport(kind) {
  if (!app.result) return setStatus('Nothing to export: run a scan first.', 'error');
  const json = kind === 'json';
  const url = URL.createObjectURL(new Blob([json ? toJSON(app.result) : toCSV(app.result)], { type: json ? 'application/json' : 'text/csv' }));
  const a = h('a', { href: url, download: `leakguard-report.${kind}` });
  document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

// ---- DFA visualizer: renders the real tables exported by dfa-engine.js ----
const dfa = describeDfa();
function renderMatrix(used = new Set(), current = null) {
  const head = h('tr', {}, h('th', {}, 'State'), ...dfa.classes.map((c) => h('th', {}, c)));
  const rows = dfa.states.map((s) => h('tr', {}, h('th', { class: s.name === current ? 'cur' : '' }, `${s.id} ${s.name}${s.accepting ? ' ✓' : ''}${s.name === dfa.start ? ' →' : ''}`),
    ...dfa.classes.map((c) => { const to = dfa.transitions[s.name][c]; return h('td', { class: used.has(`${s.name}|${c}`) ? 'used' : '' }, to ?? '·'); })));
  $('dfaMatrix').replaceChildren(head, ...rows);
}
function runDfa() {
  const input = $('dfaInput').value, r = recognize(input);
  const used = new Set(r.steps.map((s) => `${s.from}|${s.symbolClass}`));
  const rows = r.steps.map((s, i) => h('tr', {}, h('td', {}, String(i + 1)), h('td', {}, JSON.stringify(s.char)), h('td', {}, s.symbolClass), h('td', {}, `${s.from} → ${s.to}`)));
  $('dfaTrace').replaceChildren(h('tr', {}, h('th', {}, '#'), h('th', {}, 'Symbol'), h('th', {}, 'Class'), h('th', {}, 'δ(from, class) = to')), ...rows);
  const verdict = h('span', { class: r.accepted ? 'acc' : 'bad' }, r.accepted ? 'ACCEPTED' : 'REJECTED');
  $('dfaResult').replaceChildren(verdict, ` — final state ${r.finalState}${r.accepted ? ` (token ${dfa.states.find((s) => s.name === r.finalState).accepting})` : ''}`,
    r.rejectedAt ? ` — no transition from ${r.rejectedAt.state} on ${r.rejectedAt.symbolClass} (${JSON.stringify(r.rejectedAt.char)})` : (r.accepted ? '' : ' — input ended in a non-accepting state'));
  $('dfaTokens').textContent = `Tokenizer view: ${tokenize(input).filter((t) => t.type !== 'WHITESPACE').map((t) => t.type).join(' ') || '(no tokens)'}`;
  renderMatrix(used, r.finalState);
}

function init() {
  $('limits').textContent = `Limits: ${LIMITS.maxFiles} files, ${LIMITS.maxFileBytes / 1024} KB each. Types: ${SUPPORTED_EXTENSIONS.map((e) => `.${e}`).join(' ')}`;
  for (const [id, r] of Object.entries(RULES)) $('fRule').append(h('option', { value: id }, `${id} ${r.type}`));
  $('dfaInfo').textContent = `Initial state: ${dfa.start} (q0). Accepting states: ${dfa.states.filter((s) => s.accepting).map((s) => s.name).join(', ')}. Missing transition = dead state (reject).`;
  for (const s of ['API_KEY', '"demo_secret_123456"', '"say \\"hi\\""', '/* note */', '// note', '42', '"unterminated'])
    $('dfaSamples').append(h('button', { type: 'button', onclick: () => { $('dfaInput').value = s; runDfa(); } }, s));
  $('btnScan').addEventListener('click', () => runScan('code'));
  $('btnScanFiles').addEventListener('click', () => runScan('files'));
  $('btnDemo').addEventListener('click', loadDemo);
  $('btnClear').addEventListener('click', clearAll);
  $('btnJson').addEventListener('click', () => exportReport('json'));
  $('btnCsv').addEventListener('click', () => exportReport('csv'));
  $('btnDfa').addEventListener('click', runDfa);
  $('editor').addEventListener('input', refreshControls);
  $('fileInput').addEventListener('change', (e) => pick(e.target));
  $('dirInput').addEventListener('change', (e) => pick(e.target));
  $('fSeverity').addEventListener('change', renderFindings);
  $('fRule').addEventListener('change', renderFindings);
  renderAll(); runDfa();
}
init();
