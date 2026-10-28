import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import trojan_source_check as ts


def lint(text):
    return ts.check_text(text, "f.py")


def rules(findings):
    return [f.rule for f in findings]


class BidiControlTests(unittest.TestCase):
    def test_rlo_error(self):
        f = lint("x = 1 \u202e")
        self.assertEqual(f[0].rule, "bidi-control")
        self.assertEqual(f[0].severity, "error")
        self.assertIn("U+202E", f[0].message)
        self.assertIn("RIGHT-TO-LEFT OVERRIDE", f[0].message)

    def test_all_nine_flagged(self):
        for ch in ts.BIDI_CONTROLS:
            self.assertIn("bidi-control", rules(lint("a" + ch + "b")),
                          msg="missing %04X" % ord(ch))

    def test_flagged_even_inside_comment(self):
        # the attack lives in comments/strings, so context gives no pass
        self.assertIn("bidi-control", rules(lint("# note \u202d x")))

    def test_flagged_inside_string(self):
        self.assertIn("bidi-control", rules(lint("s = 'a\u202ab'")))

    def test_positions(self):
        f = lint("ab\ncd\u202e")
        self.assertEqual((f[0].line, f[0].col), (2, 3))

    def test_multiple_on_one_line(self):
        f = lint("\u202e x \u202d")
        self.assertEqual(len([x for x in f if x.rule == "bidi-control"]), 2)

    def test_clean_ascii(self):
        self.assertEqual(lint("def main():\n    return 42\n"), [])


class ZeroWidthTests(unittest.TestCase):
    def test_zwsp(self):
        f = lint("a\u200bb")
        self.assertEqual(f[0].rule, "zero-width-char")
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("U+200B", f[0].message)

    def test_all_zero_width_flagged(self):
        for ch in ts.ZERO_WIDTH:
            if ch == "\ufeff":
                continue  # BOM has its own leading-position rule
            self.assertIn("zero-width-char", rules(lint("a" + ch)),
                          msg="missing %04X" % ord(ch))

    def test_soft_hyphen(self):
        self.assertIn("zero-width-char", rules(lint("re\u00adturn x")))

    def test_leading_bom_allowed(self):
        self.assertEqual(lint("\ufeffx = 1\n"), [])

    def test_bom_elsewhere_flagged(self):
        self.assertIn("zero-width-char", rules(lint("x = \ufeff1")))
        self.assertIn("zero-width-char", rules(lint("x = 1\n\ufeffy = 2")))

    def test_zw_position(self):
        f = lint("ab\u200b")
        self.assertEqual((f[0].line, f[0].col), (1, 3))


class MixedScriptTests(unittest.TestCase):
    def test_cyrillic_a_in_latin_identifier(self):
        f = lint("\u0430dmin = True")  # Cyrillic а + Latin dmin
        self.assertEqual(f[0].rule, "mixed-script-identifier")
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("CVE-2021-42694", f[0].message)

    def test_greek_in_latin_identifier(self):
        f = lint("p\u0430ssword = 1")  # Cyrillic а inside
        self.assertIn("mixed-script-identifier", rules(f))

    def test_pure_latin_clean(self):
        self.assertEqual(lint("admin_password = 1\n"), [])

    def test_pure_cyrillic_not_flagged(self):
        # single-script non-Latin identifiers are not the attack shape
        self.assertEqual(lint("\u0430\u0431\u0432 = 1\n"), [])

    def test_greek_only_not_flagged(self):
        self.assertEqual(lint("\u03b1\u03b2 = 1\n"), [])

    def test_digits_and_underscore_ok(self):
        self.assertEqual(lint("user_name_2 = 1\n"), [])

    def test_number_prefixed_token(self):
        self.assertEqual(lint("x2_y = 1\n"), [])

    def test_single_char_latin_clean(self):
        self.assertEqual(lint("x = 1\n"), [])

    def test_token_col(self):
        f = lint("a = \u0430bc")
        self.assertEqual(f[0].col, 5)

    def test_keyword_mixed_flagged(self):
        f = lint("def get\u0430dmin():")  # Cyrillic а in function name
        self.assertIn("mixed-script-identifier", rules(f))

    def test_two_tokens_each_checked(self):
        f = lint("\u0430bc = \u03b1de")  # Cyrillic-led = Greek-led
        self.assertEqual(
            len([x for x in f if x.rule == "mixed-script-identifier"]), 2)

    def test_string_content_also_scanned(self):
        # we scan raw text, not language tokens - documented behavior
        f = lint("s = '\u0430bc'")
        self.assertIn("mixed-script-identifier", rules(f))


class IoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode) as fh:
            fh.write(data)
        return path

    def test_binary_skipped(self):
        self.assertIsNone(ts.read_source(self.write("b.bin", b"a\x00b")))

    def test_non_utf8_skipped(self):
        self.assertIsNone(ts.read_source(self.write("c.txt", b"\xff\xfe\x00")))

    def test_utf8_read(self):
        self.assertEqual(ts.read_source(self.write("t.txt", "héllo")), "héllo")

    def test_iter_files_single(self):
        p = self.write("a.py", "x")
        self.assertEqual(list(ts.iter_files([p])), [p])

    def test_iter_files_walks_dirs(self):
        self.write("pkg/a.py", "x")
        self.write("pkg/sub/b.py", "y")
        found = list(ts.iter_files([os.path.join(self.dir, "pkg")]))
        self.assertEqual(len(found), 2)

    def test_iter_files_skips_git(self):
        self.write("r/.git/config", "x")
        self.write("r/a.py", "y")
        found = list(ts.iter_files([os.path.join(self.dir, "r")]))
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].endswith("a.py"))

    def test_iter_files_skips_node_modules(self):
        self.write("p/node_modules/x.js", "x")
        self.write("p/a.js", "y")
        found = list(ts.iter_files([os.path.join(self.dir, "p")]))
        self.assertEqual(len(found), 1)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ts.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        p = self.write("a.py", "x = 1\n")
        code, out, _ = self.run_cli([p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_error_exit_1(self):
        p = self.write("a.py", "x = 1 \u202e\n")
        code, out, _ = self.run_cli([p])
        self.assertEqual(code, 1)
        self.assertIn("1 error(s)", out)

    def test_warning_only_exit_0(self):
        p = self.write("a.py", "x = 1\u200b\n")
        code, _, _ = self.run_cli([p])
        self.assertEqual(code, 0)

    def test_fail_on_warning_exit_1(self):
        p = self.write("a.py", "x = 1\u200b\n")
        code, _, _ = self.run_cli([p, "--fail-on-warning"])
        self.assertEqual(code, 1)

    def test_missing_file_exit_2(self):
        code, _, err = self.run_cli([os.path.join(self.dir, "no.py")])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_ignore_flag(self):
        p = self.write("a.py", "x = 1 \u202e\n")
        code, out, _ = self.run_cli([p, "--ignore", "bidi-control"])
        self.assertEqual(code, 0)
        self.assertNotIn("bidi-control", out)

    def test_output_shape(self):
        p = self.write("a.py", "ab\ncd\u202e\n")
        _, out, _ = self.run_cli([p])
        self.assertIn("%s:2:3 [error] bidi-control" % p, out)

    def test_json_output(self):
        p = self.write("a.py", "x = 1 \u202e\n")
        code, out, _ = self.run_cli([p, "--format", "json"])
        parsed = json.loads(out)
        self.assertEqual(parsed["summary"]["errors"], 1)
        self.assertEqual(parsed["findings"][0]["rule"], "bidi-control")
        self.assertEqual(parsed["findings"][0]["column"], 7)

    def test_binary_skip_reported(self):
        p = os.path.join(self.dir, "b.bin")
        with open(p, "wb") as fh:
            fh.write(b"a\x00b")
        code, out, _ = self.run_cli([p])
        self.assertEqual(code, 0)
        self.assertIn("1 binary or non-UTF-8 file(s) skipped", out)

    def test_directory_scan(self):
        self.write("src/a.py", "x = 1\n")
        self.write("src/b.py", "y = 2 \u202e\n")
        code, out, _ = self.run_cli([os.path.join(self.dir, "src")])
        self.assertEqual(code, 1)
        self.assertIn("b.py:1:7", out)


if __name__ == "__main__":
    unittest.main()
