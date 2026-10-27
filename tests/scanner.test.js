import test from 'node:test';
import assert from 'node:assert/strict';
import { scanSource, scanFiles, validateFile, evaluateValue, isSensitiveName, LIMITS } from '../js/scanner.js';
import { toJSON, toCSV, csvCell } from '../js/report.js';

const SECRET = 'demo_secret_123456'; // fictional fixture
const scan = (code, name = 'T.java') => scanSource(name, code).findings;

test('detects a fictional hardcoded secret with location', () => {
  const f = scan(`String API_KEY = "${SECRET}";`);
  assert.equal(f.length, 1);
  assert.equal(f[0].ruleId, 'LG001');
  assert.equal(f[0].severity, 'High');
  assert.deepEqual([f[0].line, f[0].column], [1, 19]);
});
test('detects case and naming variations', () => {
  for (const name of ['apiKey', 'Api_Key', 'client_secret', 'PRIVATE_KEY', 'db.password', 'accessToken'])
    assert.equal(scan(`${name} = "${SECRET}"`, 'a.js').length, 1, name);
});
test('detects JSON and YAML style assignments', () => {
  assert.equal(scan(`{"password": "${SECRET}"}`, 'a.json').length, 1);
  assert.equal(scan(`password: "${SECRET}"`, 'a.yml').length, 1);
});
test('detects unquoted values in env files, ignoring trailing comments', () => {
  const f = scan(`DB_PASSWORD=${SECRET} # note`, 'a.env');
  assert.equal(f.length, 1);
  assert.equal(f[0].maskedValue, `[MASKED:${SECRET.length} chars]`);
});
test('no finding for unrelated ordinary assignments', () => {
  assert.equal(scan('String name = "alexander_the_great_1";\nint port = 8080;').length, 0);
});
test('placeholders, empty and env lookups are not flagged', () => {
  for (const v of ['"changeme"', '"<your-key>"', '"${API_KEY}"', '"your_api_key_here"', '""', '"password"', 'System.getenv("API_KEY")'])
    assert.equal(scan(`String API_KEY = ${v};`).length, 0, v);
});
test('matches inside line and block comments are suppressed', () => {
  assert.equal(scan(`// API_KEY = "${SECRET}"`).length, 0);
  assert.equal(scan(`/* API_KEY = "${SECRET}" */`).length, 0);
  assert.equal(scan(`# API_KEY=${SECRET}`, 'a.env').length, 0);
});
test('invalid and empty input is handled', () => {
  assert.equal(scanSource('a.js', null).status, 'error');
  assert.equal(scanSource('a.js', '   \n').status, 'empty');
  assert.deepEqual(scanFiles(undefined).findings, []);
});
test('file validation: type, empty, oversize; file-count limit is enforced', () => {
  assert.equal(validateFile({ name: 'x.exe', size: 5 }).ok, false);
  assert.equal(validateFile({ name: 'x.js', size: 0 }).ok, false);
  assert.equal(validateFile({ name: 'x.js', size: LIMITS.maxFileBytes + 1 }).ok, false);
  assert.equal(validateFile({ name: '.env', size: 10 }).ok, true);
  const many = Array.from({ length: LIMITS.maxFiles + 3 }, (_, i) => ({ name: `f${i}.js`, text: 'x' }));
  assert.equal(scanFiles(many).summary.filesNotScannedOverLimit, 3);
});
test('provider patterns: fictional AWS/GitHub-shaped tokens and PEM header', () => {
  const aws = 'AKIA' + 'ABCDEFGHIJKLMNOP', gh = 'ghp_' + 'a1B2c3D4e5F6'.repeat(3);
  const f = scan(`a = "${aws}"\nb = "${gh}"\nk = "-----BEGIN RSA PRIVATE KEY-----"`, 'a.py');
  assert.deepEqual(f.map((x) => x.ruleId), ['LG003', 'LG003', 'LG004']);
  assert.equal(scan('k = "AKIAIOSFODNN7EXAMPLE"', 'a.py').length, 0); // AWS documentation sample
});
test('high-entropy string rule (LG002) fires once and is not double-reported', () => {
  const f = scan('String blob = "Zx9Qw3Lp8Vb2Nm7Kd4Hs6Jt1Rg5Yf0Ca";');
  assert.deepEqual(f.map((x) => x.ruleId), ['LG002']);
});
test('reports and previews never contain the raw secret', () => {
  const result = scanFiles([{ name: 'a.java', text: `String API_KEY = "${SECRET}";` }]);
  assert.equal(result.summary.totalFindings, 1);
  for (const out of [toJSON(result), toCSV(result), JSON.stringify(result.findings)]) assert.ok(!out.includes(SECRET));
  assert.ok(result.findings[0].preview.includes('[MASKED:'));
});
test('CSV escaping and formula-injection guard', () => {
  assert.equal(csvCell('=1+1'), `"'=1+1"`);
  assert.equal(csvCell('a"b,c'), '"a""b,c"');
  assert.equal(csvCell('@x'), `"'@x"`);
});
test('regression: known false positives stay quiet', () => {
  assert.equal(scan('int passwordLength = 12;').length, 0);
  assert.equal(scan('String PASSWORD_LABEL = "Enter your password";').length, 0);
  assert.equal(scan('String tokenizerName = "whitespace_tokenizer_01";').length, 0);
  assert.equal(scan(`if (apiKey == "${SECRET}") {}`).length, 0); // comparison, not assignment
  assert.equal(scan(`String sha = "${'a1'.repeat(32)}";`).length, 0);
  assert.equal(isSensitiveName('passwordLength'), false);
  assert.equal(evaluateValue('short', 'password'), null);
});
test('regression: documented false negatives (known limitations)', () => {
  assert.equal(scan('const API_KEY = `demo_secret_123456`;', 'a.js').length, 0); // template literals unsupported
  assert.equal(scan('String PASSWORD = "demo_secret" + "_123456";').length, 1); // only first fragment evaluated
});
