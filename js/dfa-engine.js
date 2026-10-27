// LeakGuard DFA lexer: M = (Q, Sigma, delta, q0, F). Sigma is partitioned into character classes;
// delta is the explicit TRANSITIONS table. A missing entry means the dead (reject) state.
export const CLASS = Object.freeze({
  LETTER: 'LETTER', DIGIT: 'DIGIT', DQUOTE: 'DQUOTE', SQUOTE: 'SQUOTE', BACKSLASH: 'BACKSLASH',
  SLASH: 'SLASH', STAR: 'STAR', HASH: 'HASH', EQUALS: 'EQUALS', COLON: 'COLON',
  NEWLINE: 'NEWLINE', SPACE: 'SPACE', OTHER: 'OTHER',
});
const ALL = Object.values(CLASS);

export function classify(ch) {
  if (ch === '\n') return CLASS.NEWLINE;
  if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\f' || ch === '\v') return CLASS.SPACE;
  if (/[\p{L}_$]/u.test(ch)) return CLASS.LETTER;
  if (ch >= '0' && ch <= '9') return CLASS.DIGIT;
  const map = { '"': 'DQUOTE', "'": 'SQUOTE', '\\': 'BACKSLASH', '/': 'SLASH', '*': 'STAR', '#': 'HASH', '=': 'EQUALS', ':': 'COLON' };
  return CLASS[map[ch]] ?? CLASS.OTHER;
}

export const START_STATE = 'START';
export const STATE_NAMES = ['START', 'IDENT', 'NUMBER', 'WS', 'NEWLINE', 'ASSIGN', 'PUNCT', 'SLASH', 'LINE_COMMENT',
  'BLOCK_COMMENT', 'BLOCK_STAR', 'BLOCK_END', 'DQ_BODY', 'DQ_ESC', 'DQ_END', 'SQ_BODY', 'SQ_ESC', 'SQ_END'];
// Accepting states F and the token type each one yields.
export const ACCEPTING = Object.freeze({
  IDENT: 'IDENTIFIER', NUMBER: 'NUMBER', WS: 'WHITESPACE', NEWLINE: 'NEWLINE', ASSIGN: 'ASSIGN', PUNCT: 'PUNCT',
  SLASH: 'PUNCT', LINE_COMMENT: 'LINE_COMMENT', BLOCK_END: 'BLOCK_COMMENT', DQ_END: 'STRING', SQ_END: 'STRING',
});

const except = (skip, to) => Object.fromEntries(ALL.filter((c) => !skip.includes(c)).map((c) => [c, to]));
const quoted = (body, esc, end, quote) => ({
  [body]: { ...except(['NEWLINE', quote, 'BACKSLASH'], body), [quote]: end, BACKSLASH: esc },
  [esc]: except(['NEWLINE'], body), [end]: {},
});

export const TRANSITIONS = Object.freeze({
  START: { LETTER: 'IDENT', DIGIT: 'NUMBER', DQUOTE: 'DQ_BODY', SQUOTE: 'SQ_BODY', SLASH: 'SLASH', HASH: 'LINE_COMMENT',
    EQUALS: 'ASSIGN', COLON: 'ASSIGN', NEWLINE: 'NEWLINE', SPACE: 'WS', BACKSLASH: 'PUNCT', STAR: 'PUNCT', OTHER: 'PUNCT' },
  IDENT: { LETTER: 'IDENT', DIGIT: 'IDENT' },
  NUMBER: { DIGIT: 'NUMBER' },
  WS: { SPACE: 'WS' }, NEWLINE: {}, ASSIGN: {}, PUNCT: {},
  SLASH: { SLASH: 'LINE_COMMENT', STAR: 'BLOCK_COMMENT' },
  LINE_COMMENT: except(['NEWLINE'], 'LINE_COMMENT'),
  BLOCK_COMMENT: { ...except(['STAR'], 'BLOCK_COMMENT'), STAR: 'BLOCK_STAR' },
  BLOCK_STAR: { ...except(['STAR', 'SLASH'], 'BLOCK_COMMENT'), STAR: 'BLOCK_STAR', SLASH: 'BLOCK_END' },
  BLOCK_END: {},
  ...quoted('DQ_BODY', 'DQ_ESC', 'DQ_END', 'DQUOTE'),
  ...quoted('SQ_BODY', 'SQ_ESC', 'SQ_END', 'SQUOTE'),
});

/** delta(state, class) -> next state, or null (dead state). */
export const delta = (state, cls) => TRANSITIONS[state]?.[cls] ?? null;

/** Unterminated block comments run to EOF and are still treated as comments; other leftovers are errors. */
const leftoverType = (s) => ACCEPTING[s] ?? (s === 'BLOCK_COMMENT' || s === 'BLOCK_STAR' ? 'BLOCK_COMMENT' : 'UNTERMINATED_STRING');

/** Maximal-munch tokenizer driven by delta. Tracks 1-based line/column. */
export function tokenize(source, { trace = false } = {}) {
  if (typeof source !== 'string') throw new TypeError('tokenize expects a string');
  const tokens = [], steps = [];
  let state = START_STATE, start = 0, line = 1, col = 1, tLine = 1, tCol = 1, i = 0;
  const emit = (end) => {
    tokens.push({ type: leftoverType(state), text: source.slice(start, end), start, end, line: tLine, column: tCol });
    state = START_STATE;
  };
  while (i < source.length) {
    const ch = source[i], cls = classify(ch);
    if (state === START_STATE) { start = i; tLine = line; tCol = col; }
    const next = delta(state, cls);
    if (next === null) { emit(i); continue; } // token ended; reprocess ch from START
    if (trace) steps.push({ index: i, char: ch, symbolClass: cls, from: state, to: next });
    state = next;
    if (ch === '\n') { line++; col = 1; } else col++;
    i++;
  }
  if (state !== START_STATE) emit(source.length);
  return trace ? { tokens, steps } : tokens;
}

/** Run the DFA over one whole lexeme and report acceptance plus the transition trace. */
export function recognize(input) {
  if (typeof input !== 'string') throw new TypeError('recognize expects a string');
  let state = START_STATE;
  const steps = [];
  for (let i = 0; i < input.length; i++) {
    const symbolClass = classify(input[i]), next = delta(state, symbolClass);
    if (next === null) return { accepted: false, finalState: state, steps, rejectedAt: { index: i, char: input[i], symbolClass, state } };
    steps.push({ index: i, char: input[i], symbolClass, from: state, to: next });
    state = next;
  }
  return { accepted: state in ACCEPTING, finalState: state, steps, rejectedAt: null };
}

/** Data for the visualizer, taken from the same tables the lexer uses. */
export function describeDfa() {
  return { states: STATE_NAMES.map((name, n) => ({ id: `q${n}`, name, accepting: ACCEPTING[name] ?? null })),
    start: START_STATE, classes: ALL, transitions: TRANSITIONS };
}
