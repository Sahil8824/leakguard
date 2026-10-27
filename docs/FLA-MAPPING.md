# FLA Mapping

## Formal model
M = (Q, Σ, δ, q0, F), a deterministic finite automaton.
- **Σ**: Unicode characters, partitioned into classes: LETTER, DIGIT, DQUOTE, SQUOTE, BACKSLASH, SLASH, STAR, HASH, EQUALS, COLON, NEWLINE, SPACE, OTHER (`classify`).
- **Q** (18): START, IDENT, NUMBER, WS, NEWLINE, ASSIGN, PUNCT, SLASH, LINE_COMMENT, BLOCK_COMMENT, BLOCK_STAR, BLOCK_END, DQ_BODY, DQ_ESC, DQ_END, SQ_BODY, SQ_ESC, SQ_END.
- **q0** = START. **F** = IDENT, NUMBER, WS, NEWLINE, ASSIGN, PUNCT, SLASH, LINE_COMMENT, BLOCK_END, DQ_END, SQ_END.
- **δ**: the `TRANSITIONS` table in `js/dfa-engine.js`; a missing entry is the dead state. Example: δ(DQ_BODY, BACKSLASH) = DQ_ESC, δ(DQ_ESC, any but newline) = DQ_BODY, δ(DQ_BODY, DQUOTE) = DQ_END, which handles escaped quotes.

## Lexical recognition
`recognize(lexeme)` runs one lexeme through δ and reports acceptance (final state in F) with a trace; the visualizer shows exactly this. `tokenize(source)` repeats the DFA from START: when δ has no move, the current token is emitted if the state is accepting, and the character is reprocessed (maximal munch). Unterminated strings become `UNTERMINATED_STRING`; an unterminated block comment is treated as a comment to end of file (a practical deviation from strict acceptance).

## Tokens plus context
A DFA only classifies lexemes. The scanner adds context: `IDENTIFIER ASSIGN STRING` with a sensitive name and a credential-like value. That context check (names, placeholders, entropy) is ordinary program logic, not a regular language. Provider patterns use regular expressions as a supplement; they do not replace the DFA.

## Academic vs practical
Real languages have nested and context-sensitive syntax (beyond regular languages); LeakGuard handles only a lexical subset. It is not an enterprise secret scanner: no verification of live credentials, no git history scan, limited formats.
