import base64
import io
import json
import threading
import unittest
import urllib.request
from functools import partial
from http.server import ThreadingHTTPServer

import app
import checks

try:
    import qrcode
    HAVE_QR = True
    import cv2  # noqa: F401
except ImportError:
    HAVE_QR = False


def qr_b64(text):
    buf = io.BytesIO()
    qrcode.make(text).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


class HandleTests(unittest.TestCase):
    def test_scam_text_returns_trace_summary_and_draft(self):
        status, body = app.handle({"text": "MyBank: account frozen. Verify within 24 hours at https://mybank-secure.example/v",
                                   "channel": "sms", "language": "en", "answers": {"asked_for_secret": False}})
        self.assertEqual(status, 200)
        self.assertEqual(body["result_code"], "likely_scam")
        self.assertIsNotNone(body["report_draft"])
        self.assertIn("NOT acting", body["family_summary"])
        self.assertTrue(all(c["status"] in {"ok", "failed", "skipped"} for c in body["trace"]["checks"]))

    def test_unclear_message_asks_then_finalises(self):
        payload = {"text": "see https://totally-new-site.example/x", "channel": "whatsapp"}
        status, first = app.handle(payload)
        self.assertEqual((status, first["status"]), (200, "needs_answer"))
        status, final = app.handle(dict(payload, answers={"asked_for_secret": True}))
        self.assertEqual(final["status"], "final")

    def test_already_acted_shows_997(self):
        _, body = app.handle({"text": "hi", "channel": "whatsapp", "already_acted": True})
        self.assertTrue(body["call_997"])
        self.assertTrue(any("997" in a for a in body["actions"]))

    def test_bad_inputs(self):
        self.assertEqual(app.handle("nope")[0], 400)
        self.assertEqual(app.handle({"text": "  "})[0], 400)
        self.assertEqual(app.handle({"text": "hi", "channel": "telegram"})[0], 400)
        self.assertEqual(app.handle({"image_b64": "@@not base64@@"})[0], 400)

    def test_malay_summary(self):
        _, body = app.handle({"text": "hi", "channel": "whatsapp", "language": "ms"})
        self.assertIn("Semakan penipuan", body["family_summary"])

    @unittest.skipUnless(HAVE_QR, "qr libraries not installed")
    def test_qr_image_is_decoded_and_checked(self):
        status, body = app.handle({"image_b64": qr_b64("https://maybank2u-secure.example/login")})
        self.assertEqual(status, 200)
        self.assertIn("qr_decode", [c["tool"] for c in body["trace"]["checks"]])
        self.assertIn(body.get("result_code") or body["provisional"]["result_code"], {"likely_scam", "verify_first"})

    @unittest.skipUnless(HAVE_QR, "qr libraries not installed")
    def test_image_without_qr_is_a_clear_error(self):
        buf = io.BytesIO()
        import PIL.Image
        PIL.Image.new("RGB", (80, 80), "white").save(buf, format="PNG")
        status, body = app.handle({"image_b64": base64.b64encode(buf.getvalue()).decode()})
        self.assertEqual(status, 422)
        self.assertIn("no_qr_found", body["error"])


class HttpSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), partial(app.Handler))
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_page_and_api_over_real_http(self):
        base = f"http://127.0.0.1:{self.port}"
        page = urllib.request.urlopen(base + "/").read().decode()
        self.assertIn("Scam check", page)
        req = urllib.request.Request(base + "/api/assess", data=json.dumps(
            {"text": "Your OTP is 482913. Do not share it.", "channel": "sms"}).encode(),
            headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req)
        self.assertIn("default-src 'none'", resp.headers["Content-Security-Policy"])
        self.assertEqual(json.loads(resp.read())["status"], "final")

    def test_bad_json_is_400_not_a_crash(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/assess", data=b"{nope",
                                     headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
