# LeakGuard — Project Report

## Abstract
LeakGuard is a browser-based tool that flags potential hardcoded credentials using a DFA-based lexer and contextual rules.

## Introduction
Accidentally committed credentials are a common security problem. LeakGuard applies finite automata to a practical developer task, locally.

## Problem statement
Provide a private, dependency-free pre-commit check that explains its findings.

## Objectives
Implement a real DFA lexer; detect suspicious assignments with few false positives; mask secrets everywhere; demonstrate the automaton visually; test automatically.

## Theoretical background
Regular languages, DFAs M=(Q,Σ,δ,q0,F), lexical analysis and maximal munch (Aho et al., *Compilers*; Hopcroft, Motwani, Ullman, *Introduction to Automata Theory, Languages, and Computation*; Sipser, *Introduction to the Theory of Computation*). See `docs/FLA-MAPPING.md`.

## System architecture
`dfa-engine.js` (lexer) → `scanner.js` (rules) → `report.js` (export); `app.js` (UI) calls these and holds no detection logic.

## DFA design
18 states, 13 character classes, explicit transition table; see `docs/FLA-MAPPING.md`.

## Implementation
Rules LG001–LG004 combine tokens, name checks, placeholder/env-lookup exceptions, entropy, and comment suppression. Findings store only masked values; previews are sanitized. UI uses safe DOM APIs. CSV cells are escaped and guarded against formula injection.

## Testing methodology and actual results
Node's built-in runner (`npm test`), 26 tests across `tests/dfa-engine.test.js` and `tests/scanner.test.js` covering tokens, escapes, positions, comments, detection, case variants, placeholders, invalid input, masked reports, and regressions. Result of the run made when this package was produced: **26 passed, 0 failed, 0 skipped.** `node --check` passed for all JS files. Manual browser testing and automated UI tests were **not** performed.

## Limitations
Lexical subset only; template strings, concatenation, multi-line values, and `//` in unquoted values are mishandled; heuristics yield false positives and false negatives; no live-credential verification.

## Conclusion
LeakGuard shows how a DFA underlies practical tooling while being honest about the limits of a lexical approach.

## References
Aho, Lam, Sethi, Ullman, *Compilers: Principles, Techniques, and Tools*. Hopcroft, Motwani, Ullman, *Introduction to Automata Theory, Languages, and Computation*. Sipser, *Introduction to the Theory of Computation*. Node.js `node:test` documentation. RFC 7468 (PEM). GitHub and AWS documentation on token/key formats.
