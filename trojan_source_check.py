#!/usr/bin/env python3
"""trojan-source-check - scan source files for invisible and deceptive
Unicode.

Flags the characters behind the Trojan Source attacks: bidirectional
control characters that reorder code visually (CVE-2021-42574),
mixed-script identifiers used in homoglyph attacks (CVE-2021-42694), and
invisible zero-width characters that can hide tokens or form look-alike
identifiers.

Pure standard library. Works on any text file; no language parsing.

Sources:
- Trojan Source (Boucher & Anderson, University of Cambridge):
  https://www.trojansource.codes/
- Unicode Standard Annex #9, Unicode Bidirectional Algorithm:
  https://www.unicode.org/reports/tr9/
"""

import argparse
import json
import os
import sys
import unicodedata

# Explicit directional embedding/override and isolate formatting
# characters (UAX #9, tables 4 and 5a).
BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# Invisible characters that carry no glyph in code review.
ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u00ad": "SOFT HYPHEN",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
}

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__"}
BINARY_SNIFF = 8000


class Finding:
    def __init__(self, path, line, col, rule, severity, message):
        self.path = path
        self.line = line
        self.col = col
        self.rule = rule
        self.severity = severity  # "error" or "warning"
        self.message = message

    def as_dict(self):
        return {
            "file": self.path,
            "line": self.line,
            "column": self.col,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


def _codepoint(ch):
    return "U+%04X" % ord(ch)


def _script(ch):
    """Coarse script detection from the Unicode character name."""
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script + " "):
            return script
    return None


def _is_ident_char(ch):
    if ch == "_":
        return True
    return unicodedata.category(ch)[0] in ("L", "N")


def check_text(text, path):
    findings = []

    def emit(line, col, rule, severity, message):
        findings.append(Finding(path, line, col, rule, severity, message))

    for lineno, line in enumerate(text.split("\n"), 1):
        for col, ch in enumerate(line, 1):
            if ch in BIDI_CONTROLS:
                emit(lineno, col, "bidi-control", "error",
                     "%s %s can visually reorder source code; the Trojan "
                     "Source attack (CVE-2021-42574) uses these to make "
                     "code display differently from how it compiles." % (
                         _codepoint(ch), BIDI_CONTROLS[ch]))
            elif ch in ZERO_WIDTH:
                if ch == "\ufeff" and lineno == 1 and col == 1:
                    continue  # a leading BOM is common and benign
                emit(lineno, col, "zero-width-char", "warning",
                     "%s %s is invisible in most editors and can hide "
                     "tokens or form look-alike identifiers." % (
                         _codepoint(ch), ZERO_WIDTH[ch]))

        # mixed-script identifiers (CVE-2021-42694 homoglyph attack)
        token = []
        token_col = 1
        for col, ch in enumerate(line, 1):
            if _is_ident_char(ch):
                if not token:
                    token_col = col
                token.append(ch)
                continue
            _check_token(token, lineno, token_col, emit)
            token = []
        _check_token(token, lineno, token_col, emit)

    return findings


def _check_token(token, lineno, col, emit):
    """Flag identifiers mixing Latin letters with Cyrillic or Greek ones.

    Heuristic: the homoglyph attack defines an identifier that looks like
    a familiar Latin name but substitutes Cyrillic/Greek look-alikes, so
    mixing Latin with either script in one identifier is the suspicious
    shape. Pure single-script and non-Latin identifiers are not flagged.
    """
    if len(token) < 2:
        return
    scripts = set()
    for ch in token:
        s = _script(ch)
        if s:
            scripts.add(s)
    if "LATIN" in scripts and len(scripts) > 1:
        others = sorted(scripts - {"LATIN"})
        emit(lineno, col, "mixed-script-identifier", "warning",
             "identifier %r mixes Latin with %s letters; Trojan Source "
             "homoglyph attacks (CVE-2021-42694) use look-alike letters "
             "from another script." % ("".join(token), " and ".join(others)))


def read_source(path):
    """Return decoded text, or None for binary/non-UTF-8 files."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:BINARY_SNIFF]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def iter_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    yield os.path.join(root, name)
        else:
            yield path


def format_text(results, skipped_binary):
    lines = []
    errors = warnings = 0
    for path, findings in results:
        for f in findings:
            lines.append("%s:%d:%d [%s] %s: %s" % (
                f.path, f.line, f.col, f.severity, f.rule, f.message))
            if f.severity == "error":
                errors += 1
            else:
                warnings += 1
    if errors or warnings:
        lines.append("trojan-source-check: %d error(s), %d warning(s)" % (
            errors, warnings))
    else:
        lines.append("trojan-source-check: clean")
    if skipped_binary:
        lines.append("(%d binary or non-UTF-8 file(s) skipped)" %
                     skipped_binary)
    return "\n".join(lines), errors, warnings


def format_json(results, errors, warnings, skipped_binary):
    return json.dumps({
        "findings": [f.as_dict() for _, fs in results for f in fs],
        "summary": {"files": len(results), "errors": errors,
                    "warnings": warnings,
                    "skipped_binary": skipped_binary},
    }, indent=2)


def build_parser():
    p = argparse.ArgumentParser(
        prog="trojan-source-check",
        description="Scan source files for bidi control characters, "
                    "zero-width characters, and mixed-script identifiers "
                    "(Trojan Source: CVE-2021-42574 / CVE-2021-42694).")
    p.add_argument("paths", nargs="+",
                   help="files or directories (directories are walked "
                        "recursively; .git/node_modules etc. skipped)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="suppress a rule by name (repeatable)")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    ignore = set(args.ignore)
    results = []
    skipped_binary = 0
    for path in iter_files(args.paths):
        try:
            text = read_source(path)
        except OSError as exc:
            print("trojan-source-check: cannot read %s: %s" % (path, exc),
                  file=sys.stderr)
            return 2
        if text is None:
            skipped_binary += 1
            continue
        findings = [f for f in check_text(text, path)
                    if f.rule not in ignore]
        results.append((path, findings))

    text_out, errors, warnings = format_text(results, skipped_binary)
    if args.format == "json":
        print(format_json(results, errors, warnings, skipped_binary))
    else:
        print(text_out)
    if errors:
        return 1
    if args.fail_on_warning and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
