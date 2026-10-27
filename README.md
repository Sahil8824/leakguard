# LeakGuard — FLA-Based Local Secret Detection Scanner

LeakGuard finds *possible* hardcoded credentials in source and config files before you commit them. A hand-written DFA lexer (Formal Languages & Automata Theory) tokenizes the input; contextual rules decide what is suspicious. Everything runs in the browser.

## Problem statement
Developers accidentally commit API keys and passwords. LeakGuard gives a quick, private, local pre-commit check and shows the automaton behind it.

## Features
Dashboard with live counts; paste, multi-file and folder input; demo loader; severity/type filters; detail view with masked preview, fix advice and false-positive notes; DFA visualizer (real transition table + trace); sanitized JSON/CSV export (formula-injection safe).

## Technologies
HTML5, CSS3, vanilla JavaScript (ES modules), Node.js built-in test runner. No dependencies, no build step.

## Folder structure
```
index.html  css/styles.css  js/{app,dfa-engine,scanner,report}.js
tests/{dfa-engine,scanner}.test.js  examples/  docs/FLA-MAPPING.md
README.md PROJECT_REPORT.md PROJECT_PROMPT.md LICENSE package.json .gitignore
```

## Requirements
A modern browser; Node.js 18+ for tests; Python 3 (or VS Code Live Server) to serve files over HTTP. ES modules do not load from `file://`.

## Run locally (VS Code, Windows)
1. Open the `leakguard` folder in VS Code (File > Open Folder).
2. Open a terminal (Ctrl+`) and run `python -m http.server 8080` (or install the *Live Server* extension and click "Go Live").
3. Visit http://localhost:8080.

## Run tests
`npm test` (runs `node --test`; no install needed).

## How the DFA engine works
`js/dfa-engine.js` groups characters into classes (LETTER, DIGIT, DQUOTE, …) and defines an explicit `TRANSITIONS` table over 18 named states. `tokenize` feeds characters through `delta`, emitting a token when the next character has no transition (maximal munch) and tracking line/column. Recognized: identifiers, `=`/`:` assignment, `"…"`/`'…'` strings with backslash escapes, numbers, punctuation, `//`, `#` and `/* */` comments. See `docs/FLA-MAPPING.md`.

## How the scanner works
`js/scanner.js` drops whitespace/comments, finds `name = value` patterns from tokens, checks the name (e.g. `apiKey`, `db.password`), then the value (length, placeholder list, env lookups, entropy). Rules: **LG001** sensitive name + literal, **LG002** high-entropy string, **LG003** provider token formats (AWS key ID, GitHub token, Google API key; supplementary regex), **LG004** PEM private-key header. Matches inside comments are skipped.

## Example
Input `String API_KEY = "demo_secret_123456";` gives `LG001 High 1:19`, preview `String API_KEY = "[MASKED:18 chars]";`.

## Security and privacy
Local processing only; no network calls, analytics or storage of code; input is never executed; untrusted text is rendered with `textContent`; secrets are masked in UI and exports; fixtures are fictional.

## Limits
200 files, 512 KB per file; types `.java .js .ts .py .json .yml .yaml .properties .env .xml .txt` and `.example`. Folder scans skip `node_modules` and `.git`.

## Limitations
Lexical subset only, not a parser. Template/backtick strings, multi-line constructs, string concatenation, and `//` inside unquoted YAML/env values are not handled correctly. Expect false positives and false negatives; it is not a replacement for enterprise scanners. Browser testing has not been performed by the author of this package.

## Future enhancements
Backtick strings, entropy tuning, rule config, SARIF export, more providers.

## Screenshots
Run the app, scan the demo, take screenshots (Win+Shift+S), save them in `docs/screenshots/`, and link them here: `![Dashboard](docs/screenshots/dashboard.png)`. Add only genuine screenshots.

## GitHub upload
```
git init
git add .
git commit -m "Initial commit: LeakGuard"
git branch -M main
git remote add origin https://github.com/<you>/leakguard.git
git push -u origin main
```
## GitHub Pages
Repository > Settings > Pages > Source: *Deploy from a branch* > `main` / `/ (root)` > Save. The site appears at `https://<you>.github.io/leakguard/`. Paths are relative, so no changes are needed.
