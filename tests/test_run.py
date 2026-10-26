import contextlib
import io
import json
import os
import subprocess
import sys
import time
import unittest
from unittest import mock

import run

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "AIzaSyFAKE-secret-key-1234567890"


def factory_ok(cues):
    return lambda: (lambda prompt: json.dumps({"cues": cues}))


class KeyHandlingTests(unittest.TestCase):
    def test_read_key_strips_spaces_and_quotes(self):
        self.assertEqual(run.read_key("K", {"K": '  "abc123"  '}), "abc123")
        self.assertEqual(run.read_key("K", {"K": "'abc'"}), "abc")

    def test_missing_or_blank_key_is_none(self):
        self.assertIsNone(run.read_key("K", {}))
        self.assertIsNone(run.read_key("K", {"K": "   "}))

    def test_scrub_removes_secret(self):
        self.assertNotIn(KEY, run.scrub(f"bad key {KEY} rejected", [KEY]))

    def test_describe_key_never_shows_whole_key(self):
        self.assertNotIn(KEY, run.describe_key(KEY))


class CheckGeminiTests(unittest.TestCase):
    def test_success(self):
        ok, msg = run.check_gemini(KEY, factory_ok([{"type": "urgency", "text": "within 24 hours"}]))
        self.assertTrue(ok)
        self.assertIn("Gemini works", msg)

    def test_missing_sdk_gives_install_hint(self):
        def boom():
            raise ImportError("no module")
        ok, msg = run.check_gemini(KEY, boom)
        self.assertFalse(ok)
        self.assertIn("pip install google-genai", msg)

    def test_errors_never_leak_the_key_and_give_hints(self):
        for text, hint in ((f"403 PERMISSION_DENIED api key {KEY} invalid", "key looks wrong"),
                           ("404 model not found", "GEMINI_MODEL"),
                           ("429 quota exceeded", "quota"),
                           ("ConnectError: [Errno -2] Name or service not known", "internet connection")):
            def factory(text=text):
                def call(prompt):
                    raise RuntimeError(text)
                return call
            ok, msg = run.check_gemini(KEY, factory)
            self.assertFalse(ok)
            self.assertNotIn(KEY, msg)
            self.assertIn(hint, msg)

    def test_timeout(self):
        def factory():
            def call(prompt):
                time.sleep(0.5)
                return "{}"
            return call
        ok, msg = run.check_gemini(KEY, factory, timeout_s=0.05)
        self.assertFalse(ok)
        self.assertIn("No answer", msg)

    def test_garbage_reply_is_failure(self):
        ok, _ = run.check_gemini(KEY, lambda: (lambda prompt: "not json"))
        self.assertFalse(ok)


class MainTests(unittest.TestCase):
    def run_main(self, argv, env):
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out):
            code = run.main(argv)
        return code, out.getvalue()

    def test_no_key_check_mode_explains_how_to_set_it(self):
        code, out = self.run_main(["--check"], {})
        self.assertEqual(code, 1)
        self.assertIn("GEMINI_API_KEY is not set", out)
        self.assertIn("setx", out)

    def test_require_gemini_refuses_to_start_without_key(self):
        code, out = self.run_main(["--require-gemini"], {})
        self.assertEqual(code, 1)
        self.assertIn("Stopping", out)

    def test_working_key_check_exits_zero_and_hides_key(self):
        with mock.patch.object(run, "check_gemini", return_value=(True, "Gemini works: test")):
            code, out = self.run_main(["--check"], {"GEMINI_API_KEY": f' "{KEY}" '})
        self.assertEqual(code, 0)
        self.assertNotIn(KEY, out)

    def test_failing_key_check_exits_one(self):
        with mock.patch.object(run, "check_gemini", return_value=(False, "bad")):
            code, _ = self.run_main(["--check"], {"GEMINI_API_KEY": KEY})
        self.assertEqual(code, 1)

    def test_starts_server_with_gemini_when_key_works(self):
        with mock.patch.object(run, "check_gemini", return_value=(True, "ok")), \
             mock.patch("app.serve") as serve, \
             mock.patch.object(run.gl, "make_gemini_call", return_value=lambda p: "{}"):
            code, _ = self.run_main(["--port", "8123"], {"GEMINI_API_KEY": KEY})
        self.assertEqual(code, 0)
        call, _rep, port = serve.call_args[0]
        self.assertTrue(callable(call))
        self.assertEqual(port, 8123)

    def test_starts_rules_only_when_no_key(self):
        with mock.patch("app.serve") as serve:
            code, out = self.run_main([], {})
        self.assertEqual(code, 0)
        self.assertIsNone(serve.call_args[0][0])
        self.assertIn("rules-only", out)


class SubprocessTests(unittest.TestCase):
    def test_real_process_with_fake_key_fails_cleanly_without_leaking(self):
        env = dict(os.environ, GEMINI_API_KEY=KEY)
        proc = subprocess.run([sys.executable, "run.py", "--check"], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn(KEY, proc.stdout + proc.stderr)
        self.assertIn("FAILED", proc.stdout)


if __name__ == "__main__":
    unittest.main()
