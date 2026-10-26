"""Local demo server for the scam checker. Standard library only.

    python app.py                       # http://127.0.0.1:8000  (rules only)
    GEMINI_API_KEY=...  python app.py   # adds Gemini cue extraction
    SAFE_BROWSING_KEY=... python app.py # adds Google Safe Browsing link check

Binds to 127.0.0.1 only. Message text is never logged or stored. The agent only PREPARES advice,
a family summary and a report draft; the person sends everything themselves.
"""
import base64
import binascii
import json
import os
import re
import socket
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import agent_workflow as aw
import checks
import gemini_layer as gl

ROOT = Path(__file__).parent
MAX_BODY = 3_000_000   # the page shrinks photos before upload, so real requests stay far below this
MAX_DRAIN = 32_000_000  # an oversized body up to this size is read and discarded so the browser gets the error
MAX_TEXT = 20_000      # longer text is refused, never cut: a cut could hide the link at the end

SUMMARY = {
    "en": {"head": "Scam check: {label}. I got {channel} and {stance}.",
           "stance": {"likely_scam": "I am NOT acting on it",
                      "verify_first": "I am NOT acting on it until I have checked it"},
           "why": "Why:",
           "advice": {"likely_scam": "Please do not click links, call numbers in it, or send money. "
                                     "If someone already got tricked, call 997 and the bank straight away.",
                      "verify_first": "If you get one like it, do not click the link or reply. Check with the person "
                                      "or organisation directly, using a number you already have, not one in the message."},
           "safe": ("Scam check: {label}. I got {channel} and the checks found no strong warning signs.\n"
                    "This is not a guarantee. Never share an OTP/TAC or password, and if it later asks for "
                    "money or a call, check with the organisation's official number first."),
           "message": "Message (personal details removed): {text}",
           "defanged": "(Links are written as hxxps:// and [.] so they cannot be clicked by mistake.)"},
    "ms": {"head": "Semakan penipuan: {label}. Saya terima {channel} dan {stance}.",
           "stance": {"likely_scam": "saya TIDAK akan bertindak",
                      "verify_first": "saya TIDAK akan bertindak sehingga saya menyemaknya"},
           "why": "Sebab:",
           "advice": {"likely_scam": "Jangan klik pautan, telefon nombor dalam mesej, atau hantar wang. "
                                     "Jika ada yang sudah tertipu, hubungi 997 dan bank dengan segera.",
                      "verify_first": "Jika anda terima mesej seperti ini, jangan klik pautan atau balas. Semak terus "
                                      "dengan orang atau organisasi itu melalui nombor yang anda sudah ada, bukan nombor dalam mesej."},
           "safe": ("Semakan penipuan: {label}. Saya terima {channel} dan semakan tidak menemui tanda amaran yang kuat.\n"
                    "Ini bukan jaminan. Jangan kongsi OTP/TAC atau kata laluan, dan jika ia kemudian meminta wang "
                    "atau panggilan, sahkan dahulu melalui nombor rasmi organisasi."),
           "message": "Mesej (butiran peribadi dibuang): {text}",
           "defanged": "(Pautan ditulis sebagai hxxps:// dan [.] supaya tidak boleh diklik secara tidak sengaja.)"},
}
QR_ERRORS = {
    "en": {"qr_support_not_installed": "QR photos are not set up on this computer. Paste the link instead, or install QR "
                                       "support (pip install opencv-python-headless numpy) and restart the app.",
           "unreadable_image": "That file could not be opened as an image. Try a screenshot saved as PNG or JPG, "
                               "or paste the link instead.",
           "no_qr_found": "No QR code was found in that image. Crop it so the QR code fills most of the picture, "
                          "or paste the link instead."},
    "ms": {"qr_support_not_installed": "Foto QR belum disediakan pada komputer ini. Tampal pautan, atau pasang sokongan QR "
                                       "(pip install opencv-python-headless numpy) dan mulakan semula aplikasi.",
           "unreadable_image": "Fail itu tidak dapat dibuka sebagai imej. Cuba tangkapan skrin dalam format PNG atau JPG, "
                               "atau tampal pautan.",
           "no_qr_found": "Tiada kod QR ditemui dalam imej itu. Potong imej supaya kod QR memenuhi sebahagian besar "
                          "gambar, atau tampal pautan."},
}
CHANNEL_NAMES = {
    "en": {"sms": "an SMS", "whatsapp": "a WhatsApp message", "email": "an email", "url": "a link", "qr": "a QR code"},
    "ms": {"sms": "SMS", "whatsapp": "mesej WhatsApp", "email": "e-mel", "url": "pautan", "qr": "kod QR"},
}
# Reasons for "Why" when the warning comes from a check that could not run rather than from words in the
# message (a link nobody could check is "unknown, not safe"), so the family summary never says "Why: -".
CHECK_WHY = {
    "en": {"reported": "The sender asked for an OTP/TAC, password or money transfer",
           "url_flagged": "The link is on Google Safe Browsing's list of dangerous sites",
           "url_reputation": "It has a link that could not be checked against a scam list, so it is treated as unknown, not safe",
           "gemini_cues": "The AI check could not run, so the result stays cautious",
           "phone_lookup": "It has a phone number that cannot be verified",
           "other": "Not every check could confirm that it is safe"},
    "ms": {"reported": "Penghantar meminta OTP/TAC, kata laluan atau pindahan wang",
           "url_flagged": "Pautan itu disenaraikan sebagai berbahaya oleh Google Safe Browsing",
           "url_reputation": "Ia mengandungi pautan yang tidak dapat disemak dalam senarai penipuan, jadi dianggap tidak diketahui, bukan selamat",
           "gemini_cues": "Semakan AI tidak dapat dijalankan, jadi keputusan kekal berhati-hati",
           "phone_lookup": "Ia mengandungi nombor telefon yang tidak dapat disahkan",
           "other": "Tidak semua semakan dapat mengesahkan ia selamat"},
}


def summary_reasons(rec, shown, lang, limit=3):
    why, checks = CHECK_WHY[lang], rec["checks_run"]
    reasons = [why["reported"]] if shown.get("reported_request") else []
    reasons += [why["url_flagged"] for c in checks
                if c["tool"] == "url_reputation" and c["status"] == "ok" and c.get("result") == "flagged"]
    reasons += [c["why"] for c in rec["cues"] if c.get("why")]
    reasons += [why.get(c["tool"], why["other"]) for c in checks if c["status"] != "ok"]
    return list(dict.fromkeys(reasons))[:limit] or [why["other"]]


def family_summary(rec, shown):
    lang = rec["language"] if rec["language"] in SUMMARY else "en"
    t, code = SUMMARY[lang], shown["result_code"]
    channel = CHANNEL_NAMES[lang].get(rec["channel"], rec["channel"])
    if code == "likely_safe":
        lines = [t["safe"].format(label=shown["result"], channel=channel)]
    else:
        lines = [t["head"].format(label=shown["result"], channel=channel, stance=t["stance"][code]), t["why"]]
        lines += [f"- {reason}" for reason in summary_reasons(rec, shown, lang)]
        lines.append(t["advice"][code])
    lines.append(t["message"].format(text=rec["redacted_text"]))
    if "hxxp" in rec["redacted_text"] or "[.]" in rec["redacted_text"]:
        lines.append(t["defanged"])
    return "\n".join(lines)


def highlight_segments(text, cues):
    """Split the masked message into [piece, cue type or None] pieces, so the page can mark each warning
    sign exactly where it appears. Pieces (not character positions) avoid Python/JavaScript index
    differences with emoji. Where two quotes overlap, the one that starts first (then the longer) wins."""
    spans = []
    for cue in cues:
        quote = (cue.get("text") or "").strip()
        if len(quote) >= 2:  # "(hidden characters)" or "(reported by user)" are not in the text, so never match
            spans += [(m.start(), m.end(), cue["type"]) for m in re.finditer(re.escape(quote), text, re.I)]
    segments, pos = [], 0
    for start, end, ctype in sorted(spans, key=lambda s: (s[0], s[0] - s[1])):
        if start < pos:
            continue
        if start > pos:
            segments.append([text[pos:start], None])
        segments.append([text[start:end], ctype])
        pos = end
    if pos < len(text):
        segments.append([text[pos:], None])
    return segments


def handle(payload, call=None, reputation=None):
    """Pure request handler: (payload dict) -> (http_status, response dict). Unit-testable."""
    if not isinstance(payload, dict):
        return 400, {"error": "Request must be a JSON object."}
    channel = payload.get("channel", "sms")
    language = payload.get("language", "en")
    language = language if language in ("en", "ms") else "en"
    text, extra = payload.get("text"), []

    if payload.get("image_b64"):
        try:
            image = base64.b64decode(payload["image_b64"], validate=True)
        except (binascii.Error, ValueError, TypeError):
            return 400, {"error": "The image could not be read."}
        decoded, reason = checks.decode_qr(image)
        if decoded is None:
            errors = QR_ERRORS[language]
            return 422, {"error": errors.get(reason, errors["no_qr_found"]), "reason": reason}
        text, channel = decoded, "qr"
        extra = [{"tool": "qr_decode", "status": "ok", "result": "decoded"}]

    if not isinstance(text, str) or not text.strip():
        return 400, {"error": "Paste a message, a link, or upload a QR image."}
    if len(text) > MAX_TEXT:
        return 413, {"error": f"That text is too long to check ({len(text):,} characters, limit {MAX_TEXT:,}). "
                              "Paste only the message itself, including any link in it."}
    rec = gl.build_record(text, channel, language, call=call,
                          url_reputation=reputation, extra_checks=extra)
    out = aw.assess(rec, payload.get("answers"), bool(payload.get("already_acted")))
    if out.get("status") == "error":
        return 400, {"error": "; ".join(out["error"])}
    shown = out if out["status"] == "final" else out["provisional"]
    out["family_summary"] = family_summary(rec, shown)
    lang = rec["language"] if rec["language"] in SUMMARY else "en"
    out["reasons"] = [] if shown["result_code"] == "likely_safe" else summary_reasons(rec, shown, lang)
    # The urgent 997 banner is for someone who acted on a risky message, not on one found Likely Safe.
    out["call_997"] = bool(payload.get("already_acted")) and shown["result_code"] != "likely_safe"
    out["trace"] = {"engine": rec["engine"], "risk_score": rec["risk_score"],
                    "checks": rec["checks_run"],
                    "cues": [{"type": c["type"], "text": c["text"], "why": c["why"]} for c in rec["cues"]],
                    "redacted_text": rec["redacted_text"],
                    "segments": highlight_segments(rec["redacted_text"], rec["cues"])}
    return 200, out


class Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, call=None, reputation=None, **kwargs):
        self.call, self.reputation = call, reputation
        super().__init__(*args, **kwargs)

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, (ROOT / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path != "/api/assess":
            return self._send(404, b"not found", "text/plain")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                # Read the body before answering: replying early resets the connection, and the browser
                # then shows "Could not reach the checker" instead of this message.
                if length <= MAX_DRAIN:
                    self.rfile.read(length)
                else:
                    self.close_connection = True
                return self._send(413, json.dumps({"error": "That file is too large. Use a screenshot or a smaller "
                                                            "photo of the QR code."}).encode(), "application/json")
            if length <= 0:
                return self._send(400, b'{"error":"Empty request."}', "application/json")
            payload = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return self._send(400, b'{"error":"Bad JSON."}', "application/json")
        status, body = handle(payload, self.call, self.reputation)
        self._send(status, json.dumps(body, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def log_message(self, *args):  # never log request lines or bodies
        pass


class Server(ThreadingHTTPServer):
    """One server per port. On Windows, SO_REUSEADDR (the http.server default) lets a second copy bind the
    same port silently, and requests then reach either copy at random, so it is replaced there by
    SO_EXCLUSIVEADDRUSE: a second start fails with a clear 'port in use' error instead."""
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_server(call=None, reputation=None, port=8000):
    return Server(("127.0.0.1", port), partial(Handler, call=call, reputation=reputation))


def serve(call=None, reputation=None, port=8000):
    """Start the demo server on 127.0.0.1 (blocks until Ctrl+C)."""
    server = make_server(call, reputation, port)
    qr = checks.qr_supported()
    print(f"Gemini: {'ON' if call else 'off'} | Safe Browsing: {'ON' if reputation else 'off'} "
          f"| QR photos: {'ON' if qr else 'off'} | http://127.0.0.1:{port}  (Ctrl+C to stop)")
    if not qr:
        print("  QR photos are off for this Python. To turn them on: pip install opencv-python-headless numpy")
    server.serve_forever()


def main():
    call = gl.gemini_from_env()
    key = os.environ.get("SAFE_BROWSING_KEY")
    reputation = (lambda urls: checks.safe_browsing(key, urls)) if key else None
    serve(call, reputation)


if __name__ == "__main__":
    main()
