import base64
import io
import json
import threading
import unittest
import unittest.mock
import urllib.request

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

    def test_already_acted_on_scam_shows_997(self):
        _, body = app.handle({"text": "MyBank: account frozen. Verify within 24 hours at https://mybank-secure.example/v",
                              "channel": "sms", "already_acted": True, "answers": {"asked_for_secret": False}})
        self.assertEqual(body["result_code"], "likely_scam")
        self.assertTrue(body["call_997"])
        self.assertTrue(any("call the National Scam Response Centre on 997" in a for a in body["actions"]))

    def test_already_acted_on_safe_message_is_calm(self):
        for language, label in (("en", "Likely Safe"), ("ms", "Kemungkinan Selamat")):
            _, body = app.handle({"text": "Hi, see you at the group meeting tomorrow at 10am.", "channel": "whatsapp",
                                  "language": language, "already_acted": True})
            self.assertEqual(body["result"], label)
            self.assertFalse(body["call_997"])
            self.assertIsNone(body["report_draft"])
            self.assertEqual(len([a for a in body["actions"] if "997" in a]), 1)  # only "no need to call 997"
            self.assertFalse(any("Scam Response Centre" in a or "Respons Scam" in a for a in body["actions"]))

    def test_already_acted_on_verify_first_still_shows_997(self):
        _, body = app.handle({"text": "Hello see https://totally-new-site.example/x", "channel": "whatsapp",
                              "already_acted": True, "answers": {"asked_for_secret": False}})
        self.assertEqual(body["result_code"], "verify_first")
        self.assertTrue(body["call_997"])

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
        self.assertEqual(body["reason"], "no_qr_found")
        self.assertIn("No QR code was found", body["error"])

    def test_missing_qr_support_says_how_to_fix_it(self):
        image = base64.b64encode(b"\x89PNG fake").decode()
        with unittest.mock.patch.object(checks, "decode_qr", return_value=(None, "qr_support_not_installed")):
            for language, words in (("en", "not set up on this computer"), ("ms", "belum disediakan")):
                status, body = app.handle({"image_b64": image, "language": language})
                self.assertEqual((status, body["reason"]), (422, "qr_support_not_installed"))
                self.assertIn(words, body["error"])
                self.assertIn("pip install opencv-python-headless numpy", body["error"])
                self.assertFalse(body["error"].startswith("qr_support"))


class LimitsAndSummaryTests(unittest.TestCase):
    PADDED = ("Hello " * 700) + "MyBank: account frozen, verify now https://mybank-secure.co/verify"

    def test_padding_cannot_hide_a_link(self):
        status, body = app.handle({"text": self.PADDED, "channel": "sms", "answers": {"asked_for_secret": False}})
        self.assertEqual(status, 200)
        self.assertEqual(body["result_code"], "likely_scam")

    def test_too_long_text_is_refused_not_cut(self):
        status, body = app.handle({"text": "x " * app.MAX_TEXT, "channel": "sms"})
        self.assertEqual(status, 413)
        self.assertIn("too long", body["error"])

    def test_safe_summary_does_not_tell_family_to_panic(self):
        _, body = app.handle({"text": "Hi, see you at the group meeting tomorrow at 10am.", "channel": "whatsapp"})
        self.assertEqual(body["result"], "Likely Safe")
        self.assertIn("no strong warning signs", body["family_summary"])
        self.assertIn("a WhatsApp message", body["family_summary"])
        self.assertNotIn("NOT acting", body["family_summary"])


class FamilySummaryTests(unittest.TestCase):
    DOC = "Hey, can you check this document for me? https://short.example/a8K2"

    def test_unchecked_link_gives_a_real_reason_and_verify_advice(self):
        _, body = app.handle({"text": self.DOC, "channel": "whatsapp", "answers": {"asked_for_secret": False}})
        summary = body["family_summary"]
        self.assertEqual(body["result_code"], "verify_first")
        self.assertNotIn("Why: -", summary)
        self.assertIn("- It has a link that could not be checked", summary)
        self.assertIn("until I have checked it", summary)
        self.assertIn("number you already have", summary)
        self.assertIn("cannot be clicked by mistake", summary)

    def test_question_still_open_uses_the_provisional_result(self):
        _, body = app.handle({"text": self.DOC, "channel": "whatsapp"})
        self.assertEqual(body["status"], "needs_answer")
        self.assertIn("could not be checked", body["family_summary"])

    def test_yes_answer_becomes_the_first_reason(self):
        _, body = app.handle({"text": self.DOC, "channel": "whatsapp", "answers": {"asked_for_secret": True}})
        lines = body["family_summary"].splitlines()
        self.assertEqual(lines[lines.index("Why:") + 1], "- The sender asked for an OTP/TAC, password or money transfer")

    def test_flagged_link_says_so(self):
        flagged = lambda urls: {"tool": "url_reputation", "status": "ok", "result": "flagged"}
        _, body = app.handle({"text": "Hello see https://totally-new-site.example/x", "channel": "whatsapp",
                              "answers": {"asked_for_secret": False}}, reputation=flagged)
        self.assertEqual(body["result_code"], "likely_scam")
        self.assertIn("Google Safe Browsing", body["family_summary"])

    def test_malay_reasons(self):
        _, body = app.handle({"text": self.DOC, "channel": "whatsapp", "language": "ms",
                              "answers": {"asked_for_secret": False}})
        self.assertIn("Sebab:\n- Ia mengandungi pautan yang tidak dapat disemak", body["family_summary"])
        self.assertIn("nombor yang anda sudah ada", body["family_summary"])

    def test_at_most_three_reasons(self):
        _, body = app.handle({"text": "MyBank: account frozen. Act now within 24 hours at https://mybank-secure.example/v "
                                      "and send your OTP. Call 012-345 6789 to cancel.", "channel": "sms",
                              "answers": {"asked_for_secret": True}})
        self.assertEqual(sum(1 for line in body["family_summary"].splitlines() if line.startswith("- ")), 3)


class HighlightTests(unittest.TestCase):
    SCAM = "MyBank: Your account has been frozen. Verify within 24 hours at https://mybank-secure.co/verify"

    def test_warning_words_are_marked_where_they_appear(self):
        _, body = app.handle({"text": self.SCAM, "channel": "sms", "answers": {"asked_for_secret": False}})
        segments = body["trace"]["segments"]
        self.assertEqual("".join(piece for piece, _ in segments), body["trace"]["redacted_text"])
        marked = {piece: kind for piece, kind in segments if kind}
        self.assertEqual(marked["within 24 hours"], "urgency")
        self.assertEqual(marked["account has been frozen"], "fear")
        self.assertEqual(marked["hxxps://mybank-secure[.]co/verify"], "link_in_bank_message")
        self.assertEqual(marked["MyBank"], "claims_authority")

    def test_every_cue_comes_with_its_reason(self):
        _, body = app.handle({"text": self.SCAM, "channel": "sms", "language": "ms", "answers": {"asked_for_secret": False}})
        self.assertTrue(all(c["why"] for c in body["trace"]["cues"]))
        self.assertIn("Mendesak anda bertindak", [c["why"] for c in body["trace"]["cues"] if c["type"] == "urgency"][0])

    def test_overlapping_quotes_never_nest(self):
        cues = [{"type": "link_shortener", "text": "bit[.]ly"}, {"type": "link_in_bank_message", "text": "hxxps://bit[.]ly/x"}]
        self.assertEqual(app.highlight_segments("see hxxps://bit[.]ly/x now", cues),
                         [["see ", None], ["hxxps://bit[.]ly/x", "link_in_bank_message"], [" now", None]])

    def test_case_insensitive_and_repeated(self):
        segments = app.highlight_segments("URGENT! act now, urgent", [{"type": "urgency", "text": "urgent"}])
        self.assertEqual([p for p, kind in segments if kind], ["URGENT", "urgent"])

    def test_quotes_not_in_the_text_are_ignored(self):
        cues = [{"type": "hidden_text", "text": "(hidden characters)"}, {"type": "fear", "text": ""}]
        self.assertEqual(app.highlight_segments("Pay now", cues), [["Pay now", None]])

    def test_clean_message_is_one_plain_piece(self):
        _, body = app.handle({"text": "Hi, see you at the group meeting tomorrow at 10am.", "channel": "whatsapp"})
        self.assertEqual(body["trace"]["segments"], [["Hi, see you at the group meeting tomorrow at 10am.", None]])


class ReasonsTests(unittest.TestCase):
    def test_reasons_explain_a_result_with_no_warning_words(self):
        _, body = app.handle({"text": "Hey, can you check this document for me? https://short.example/a8K2",
                              "channel": "whatsapp", "answers": {"asked_for_secret": False}})
        self.assertEqual(body["result_code"], "verify_first")
        self.assertEqual(body["trace"]["cues"], [])
        self.assertTrue(body["reasons"][0].startswith("It has a link that could not be checked"))

    def test_safe_result_has_no_reasons(self):
        _, body = app.handle({"text": "Hi, see you at the group meeting tomorrow at 10am.", "channel": "whatsapp"})
        self.assertEqual(body["reasons"], [])

    def test_reasons_follow_the_reply_language(self):
        _, body = app.handle({"text": "Hey, can you check this document for me? https://short.example/a8K2",
                              "channel": "whatsapp", "language": "ms", "answers": {"asked_for_secret": False}})
        self.assertTrue(body["reasons"][0].startswith("Ia mengandungi pautan"))


class HttpSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.make_server(port=0)
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

    def test_oversized_upload_gets_a_readable_413(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/assess", data=b"x" * (app.MAX_BODY + 1),
                                     headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 413)
        self.assertIn("too large", json.loads(ctx.exception.read())["error"])

    def test_second_server_cannot_share_the_port(self):
        with self.assertRaises(OSError):
            app.make_server(port=self.port)


if __name__ == "__main__":
    unittest.main()
