# trojan-source-check

A CI scanner for the Trojan Source attacks. It reads source files as raw
text and flags the characters behind CVE-2021-42574 (bidirectional
control characters that make code display differently from how it
compiles), CVE-2021-42694 (mixed-script identifiers used in homoglyph
attacks), and invisible zero-width characters that can hide tokens.

Pure Python standard library. No language parsing, no dependencies.

## The problem

In November 2021, Boucher and Anderson at the University of Cambridge
published Trojan Source: Unicode control characters embedded in comments
and strings can reorder source code visually, so a human reviewer sees
one program while the compiler builds another. Their defense guidance is
that toolchains should "throw errors or warnings for unterminated
bidirectional control characters in comments or string literals, and for
identifiers with mixed-script confusable characters." Most editors still
render these characters invisibly. trojan-source-check is that warning,
dropped into CI.

## Usage

```bash
python3 trojan_source_check.py src/
python3 trojan_source_check.py app.py lib/util.py --fail-on-warning
python3 trojan_source_check.py . --format json
```

Directories are walked recursively (`.git`, `node_modules`,
`__pycache__` and friends are skipped). Binary and non-UTF-8 files are
skipped and reported, not scanned.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean (warnings only when `--fail-on-warning` is off) |
| 1 | Findings present (errors, or warnings with `--fail-on-warning`) |
| 2 | Input problem: an unreadable path |

Example output:

```
app.py:2:16 [error] bidi-control: U+202E RIGHT-TO-LEFT OVERRIDE can visually reorder source code; the Trojan Source attack (CVE-2021-42574) uses these to make code display differently from how it compiles.
trojan-source-check: 1 error(s), 0 warning(s)
```

## Rules

| Rule | Severity | Trigger | Grounding |
|---|---|---|---|
| `bidi-control` | error | any of the 9 explicit directional formatting characters: LRE/RLE/PDF/LRO/RLO (U+202A-U+202E) and LRI/RLI/FSI/PDI (U+2066-U+2069) | CVE-2021-42574; character semantics from Unicode UAX #9 |
| `mixed-script-identifier` | warning | an identifier-like token mixing Latin letters with Cyrillic or Greek ones | CVE-2021-42694 homoglyph attack (heuristic detector, see below) |
| `zero-width-char` | warning | U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER, U+00AD SOFT HYPHEN, or U+FEFF anywhere except the very start of a file | invisible in most editors; can hide tokens or form look-alike identifiers |

Honesty notes:

- `bidi-control` is stricter than the paper's minimum guidance: the paper
  asks compilers to warn on *unterminated* bidi controls inside
  comments/strings; this scanner flags every occurrence, because any of
  these characters in source code deserves a human look.
- `mixed-script-identifier` is a heuristic, stated as such in its
  message. It only flags the attack's shape (Latin mixed with
  Cyrillic/Greek); pure single-script non-Latin identifiers are not
  flagged, and rare false positives are possible in multilingual code.
- The scanner reads raw text, not language tokens: a Cyrillic letter
  inside a string literal is scanned the same as one inside an
  identifier.

## Options

```
--ignore RULE            suppress a rule by name (repeatable)
--fail-on-warning        exit 1 when only warnings are present
--format text|json       output format (default: text)
```

## Sources

- Trojan Source: Invisible Vulnerabilities, Boucher & Anderson,
  University of Cambridge (attack description, CVE-2021-42574 and
  CVE-2021-42694, defense guidance):
  https://www.trojansource.codes/
- Unicode Standard Annex #9, Unicode Bidirectional Algorithm (character
  names and semantics): https://www.unicode.org/reports/tr9/

## Development

42 tests, all fabricated source strings, no network:

```bash
python3 -m unittest -v
```

CI runs the suite on Ubuntu and Windows with Python 3.9 and 3.13.

## License

MIT - see LICENSE.
