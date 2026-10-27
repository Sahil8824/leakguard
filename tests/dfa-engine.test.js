import test from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, recognize, classify, delta, TRANSITIONS, ACCEPTING } from '../js/dfa-engine.js';

const types = (src) => tokenize(src).filter((t) => t.type !== 'WHITESPACE').map((t) => t.type);

test('recognizes identifiers and assignment operators', () => {
  assert.deepEqual(types('API_KEY = x1'), ['IDENTIFIER', 'ASSIGN', 'IDENTIFIER']);
});
test('recognizes numbers and punctuation', () => {
  assert.deepEqual(types('n=42;'), ['IDENTIFIER', 'ASSIGN', 'NUMBER', 'PUNCT']);
});
test('recognizes quoted strings with both quote kinds', () => {
  const t = tokenize(`"abc" 'def'`).filter((x) => x.type === 'STRING');
  assert.deepEqual(t.map((x) => x.text), ['"abc"', "'def'"]);
});
test('handles escaped quotes inside strings', () => {
  const t = tokenize('"a\\"b" x').filter((x) => x.type === 'STRING');
  assert.equal(t.length, 1);
  assert.equal(t[0].text, '"a\\"b"');
});
test('tracks line and column (1-based), including across block comments', () => {
  const t = tokenize('a\n  bb /* x\ny */ c').filter((x) => x.type === 'IDENTIFIER');
  assert.deepEqual(t.map((x) => [x.text, x.line, x.column]), [['a', 1, 1], ['bb', 2, 3], ['c', 3, 6]]);
});
test('recognizes line (// and #) and block comments as single tokens', () => {
  assert.deepEqual(types('// hi = "x"\n# yo\n/* a\nb */'), ['LINE_COMMENT', 'NEWLINE', 'LINE_COMMENT', 'NEWLINE', 'BLOCK_COMMENT']);
});
test('unterminated string is reported, not silently accepted', () => {
  assert.equal(tokenize('"abc\nx').find((t) => t.text === '"abc').type, 'UNTERMINATED_STRING');
});
test('empty input gives no tokens; non-string input throws', () => {
  assert.deepEqual(tokenize(''), []);
  assert.throws(() => tokenize(null), TypeError);
});
test('recognize: accepts a string lexeme and records the transition trace', () => {
  const r = recognize('"a"');
  assert.equal(r.accepted, true);
  assert.equal(r.finalState, 'DQ_END');
  assert.deepEqual(r.steps.map((s) => s.to), ['DQ_BODY', 'DQ_BODY', 'DQ_END']);
});
test('recognize: rejects empty input, incomplete strings and dead transitions', () => {
  assert.equal(recognize('').accepted, false);
  assert.equal(recognize('"abc').accepted, false);
  const r = recognize('ab cd');
  assert.equal(r.accepted, false);
  assert.equal(r.rejectedAt.index, 2);
});
test('transition function is deterministic and defined for every accepting state', () => {
  assert.equal(classify('_'), 'LETTER');
  assert.equal(delta('IDENT', 'DIGIT'), 'IDENT');
  assert.equal(delta('IDENT', 'DQUOTE'), null);
  for (const s of Object.keys(ACCEPTING)) assert.ok(s in TRANSITIONS);
});
