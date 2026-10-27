// Scanner rules: consume DFA tokens and apply contextual rules. Never stores raw secret values in findings.
import { tokenize } from './dfa-engine.js';

export const LIMITS = Object.freeze({ maxFiles: 200, maxFileBytes: 512 * 1024 });
export const SUPPORTED_EXTENSIONS = ['java', 'js', 'ts', 'py', 'json', 'yml', 'yaml', 'properties', 'env', 'xml', 'txt', 'example'];
const RAW_VALUE_EXTENSIONS = new Set(['env', 'properties', 'yml', 'yaml', 'txt', 'example']); // unquoted values allowed
const SEVERITY_ORDER = { High: 0, Medium: 1, Low: 2 };

export const RULES = Object.freeze({
  LG001: { type: 'Sensitive name with hardcoded value', heuristic: true,
    remediation: 'Move the value to an environment variable or secret manager, rotate it if it was ever real, and remove it from history.',
    falsePositive: 'Test data, non-secret identifiers, or custom placeholders can look like credentials.' },
  LG002: { type: 'High-entropy credential-like string', heuristic: true,
    remediation: 'If this is a credential, move it out of source code and rotate it.',
    falsePositive: 'Random-looking IDs, hashes in other encodings, or encoded data are common false positives.' },
  LG003: { type: 'Provider-specific token pattern', heuristic: false,
    remediation: 'Revoke the token at the provider immediately, issue a new one, and load it from a secret store.',
    falsePositive: 'Documentation samples or revoked tokens can match the documented format.' },
  LG004: { type: 'Private key block header', heuristic: false,
    remediation: 'Remove the key from the repository, treat it as compromised, regenerate it, and store it outside source control.',
    falsePositive: 'Public test keys or documentation snippets may include the same header.' },
});

// Provider formats: AWS key-ID prefixes, GitHub token prefixes, Google API key prefix (all vendor-documented), PEM header (RFC 7468).
const PROVIDER_PATTERNS = [
  { ruleId: 'LG003', label: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { ruleId: 'LG003', label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { ruleId: 'LG003', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { ruleId: 'LG004', label: 'PEM private key header', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g, fixedMask: '[PRIVATE KEY HEADER]' },
];
const SENSITIVE_NAME_PARTS = ['apikey', 'secretkey', 'secret', 'password', 'passwd', 'pwd', 'accesstoken', 'authtoken',
  'token', 'privatekey', 'clientsecret', 'accesskey'];
const NON_SECRET_SUFFIX = /(?:url|path|file|length|label|field|prompt|placeholder|regex|pattern|header|endpoint|type|name|tokeniz\w*)$/;
const PLACEHOLDER = /^(?:<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|\$[A-Za-z_]+|x{3,}|\*{3,}|\.{3,}|change[_-]?me|replace[_-]?me|your[\w .-]*|example\w*|placeholder\w*|todo|tbd|null|none|undefined|dummy|test|password|secret|token|api[_-]?key|enter.*|insert.*|redacted.*)$/i;
const ENV_LOOKUP = /^(?:process\.env|os\.environ|System\.getenv|getenv)/i;

export const getExtension = (name) => String(name).toLowerCase().split('.').pop();

export function validateFile({ name, size }) {
  if (!SUPPORTED_EXTENSIONS.includes(getExtension(name))) return { ok: false, reason: 'unsupported file type' };
  if (size === 0) return { ok: false, reason: 'file is empty' };
  if (size > LIMITS.maxFileBytes) return { ok: false, reason: `larger than ${LIMITS.maxFileBytes / 1024} KB limit` };
  return { ok: true };
}

export const shannonEntropy = (s) => {
  const counts = {};
  for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
  return -Object.values(counts).reduce((sum, n) => sum + (n / s.length) * Math.log2(n / s.length), 0);
};
export const maskValue = (value) => `[MASKED:${value.length} chars]`;
const normalizeName = (n) => n.toLowerCase().replace(/[^a-z0-9]/g, '');
export function isSensitiveName(name) {
  const n = normalizeName(name);
  return !NON_SECRET_SUFFIX.test(n) && SENSITIVE_NAME_PARTS.some((p) => n.includes(p));
}

/** Value heuristics for LG001. Returns null (no finding) or { severity, reason }. */
export function evaluateValue(value, name) {
  const v = value.trim();
  if (v.length < 6 || PLACEHOLDER.test(v) || ENV_LOOKUP.test(v) || /\s/.test(v)) return null;
  if (v.startsWith('/') || /^https?:\/\/[^@\s]*$/i.test(v) || normalizeName(v) === normalizeName(name)) return null;
  const mixed = /[A-Za-z]/.test(v) && /\d/.test(v);
  const severity = v.length >= 8 && (mixed || shannonEntropy(v) > 3.5) ? 'High' : 'Medium';
  return { severity, reason: `Variable "${name}" looks sensitive and is assigned a ${v.length}-character non-placeholder literal.` };
}

/** Scan one text. Returns { file, status, error?, findings }. */
export function scanSource(file, text) {
  if (typeof text !== 'string') return { file, status: 'error', error: 'Input is not text.', findings: [] };
  if (text.trim() === '') return { file, status: 'empty', findings: [] };
  const tokens = tokenize(text);
  const lines = text.split('\n');
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') lineStarts.push(i + 1);
  const locate = (off) => { let l = 0; while (l + 1 < lineStarts.length && lineStarts[l + 1] <= off) l++; return { line: l + 1, column: off - lineStarts[l] + 1 }; };
  const comments = tokens.filter((t) => t.type === 'LINE_COMMENT' || t.type === 'BLOCK_COMMENT');
  const inComment = (off) => comments.some((c) => off >= c.start && off < c.end);
  const sig = tokens.filter((t) => !['WHITESPACE', 'NEWLINE', 'LINE_COMMENT', 'BLOCK_COMMENT'].includes(t.type));
  const rawAllowed = RAW_VALUE_EXTENSIONS.has(getExtension(file));
  const hits = []; // { ruleId, start, end, severity, reason, mask }
  const overlaps = (s, e) => hits.some((h) => s < h.end && e > h.start);

  for (const p of PROVIDER_PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      if (inComment(m.index) || (p.label.startsWith('AWS') && m[0].endsWith('EXAMPLE'))) continue;
      hits.push({ ruleId: p.ruleId, start: m.index, end: m.index + m[0].length, severity: 'High',
        reason: `Matches the documented ${p.label} format.`, mask: p.fixedMask ?? maskValue(m[0]) });
    }
  }

  sig.forEach((a, k) => {
    if (a.type !== 'ASSIGN' || k === 0) return;
    const before = text[a.start - 1] ?? '', after = text[a.end] ?? '';
    if (after === '=' || after === '>' || /[=!<>:+\-*/]/.test(before)) return; // ==, =>, +=, := ...
    let prev = sig[k - 1], nameStart = prev.start, name;
    if (prev.text === ']' && sig[k - 2]?.type === 'STRING') prev = sig[k - 2]; // obj["password"] = ...
    if (prev.type === 'STRING') name = prev.text.slice(1, -1); // JSON / bracket key
    else if (prev.type === 'IDENTIFIER') {
      for (let j = k - 1; j > 0; j--) { // join dotted/dashed keys: db.password, my-api-key
        const p = sig[j - 1];
        if (p.end === sig[j].start && (p.type === 'IDENTIFIER' || (p.type === 'PUNCT' && (p.text === '.' || p.text === '-')))) nameStart = p.start; else break;
      }
      name = text.slice(nameStart, prev.end);
    } else return;
    if (!isSensitiveName(name)) return;
    const nxt = sig[k + 1];
    if (!nxt) return;
    let value, vStart;
    if (nxt.type === 'STRING') { value = nxt.text.slice(1, -1); vStart = nxt.start + 1; }
    else if (rawAllowed && nxt.line === a.line) {
      const lineEnd = text.indexOf('\n', a.end), rest = text.slice(a.end, lineEnd < 0 ? undefined : lineEnd).replace(/\r$/, '').replace(/\s+#.*$/, '');
      value = rest.trim(); vStart = a.end + (rest.length - rest.trimStart().length);
    } else return;
    const verdict = evaluateValue(value, name);
    if (verdict && !overlaps(vStart, vStart + value.length)) hits.push({ ruleId: 'LG001', start: vStart, end: vStart + value.length, ...verdict, mask: maskValue(value) });
  });

  for (const t of sig) {
    if (t.type !== 'STRING') continue;
    const inner = t.text.slice(1, -1);
    if (inner.length < 24 || !/^[A-Za-z0-9+/=_-]+$/.test(inner) || /^[0-9a-f]+$/i.test(inner) || !/\d/.test(inner) || !/[A-Za-z]/.test(inner)) continue;
    if (shannonEntropy(inner) < 3.8 || PLACEHOLDER.test(inner) || overlaps(t.start, t.end)) continue;
    hits.push({ ruleId: 'LG002', start: t.start + 1, end: t.end - 1, severity: 'Medium',
      reason: `String literal of ${inner.length} characters with high character entropy (heuristic).`, mask: maskValue(inner) });
  }

  const located = hits.map((h) => ({ ...h, ...locate(h.start) }));
  const preview = (line) => { // mask every hit on this line, right to left so columns stay valid
    let s = (lines[line - 1] ?? '').replace(/\r$/, '');
    for (const h of located.filter((x) => x.line === line).sort((a, b) => b.column - a.column)) s = s.slice(0, h.column - 1) + h.mask + s.slice(h.column - 1 + (h.end - h.start));
    return s.length > 200 ? `${s.slice(0, 200)}…` : s;
  };
  const findings = located.map((h) => ({
    ruleId: h.ruleId, severity: h.severity, type: RULES[h.ruleId].type, file, line: h.line, column: h.column,
    maskedValue: h.mask, reason: h.reason, remediation: RULES[h.ruleId].remediation, heuristic: RULES[h.ruleId].heuristic,
    falsePositiveNote: RULES[h.ruleId].falsePositive, preview: preview(h.line),
  })).sort((x, y) => x.file.localeCompare(y.file) || x.line - y.line || x.column - y.column || SEVERITY_ORDER[x.severity] - SEVERITY_ORDER[y.severity]);
  return { file, status: 'ok', findings };
}

/** Scan [{ name, text }]. Applies the file-count limit and builds the summary. */
export function scanFiles(files) {
  if (!Array.isArray(files)) return { summary: summarize([], 0), findings: [], files: [] };
  const results = files.slice(0, LIMITS.maxFiles).map((f) => scanSource(f?.name ?? 'unnamed', f?.text));
  return { summary: summarize(results, Math.max(0, files.length - LIMITS.maxFiles)), findings: results.flatMap((r) => r.findings), files: results };
}
function summarize(results, excess) {
  const findings = results.flatMap((r) => r.findings);
  return { filesScanned: results.filter((r) => r.status !== 'error').length, totalFindings: findings.length,
    highSeverity: findings.filter((f) => f.severity === 'High').length,
    filesWithFindings: results.filter((r) => r.findings.length).length, filesNotScannedOverLimit: excess };
}
