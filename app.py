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
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import agent_workflow as aw
import checks
import gemini_layer as gl

ROOT = Path(__file__).parent
MAX_BODY = 3_000_000
MAX_TEXT = 4000

SUMMARY = {
    "en": ("Scam check: {label}. I got a {channel} message and I am NOT acting on it.\n"
           "Why: {why}.\nPlease do not click links, call numbers in it, or send money. "
           "If someone already got tricked, call 997 and the bank straight away.\n"
           "Message (personal details removed): {text}"),
    "ms": ("Semakan penipuan: {label}. Saya terima mesej {channel} dan saya TIDAK akan bertindak.\n"
           "Sebab: {why}.\nJangan klik pautan, telefon nombor dalam mesej, atau hantar wang. "
           "Jika ada yang sudah tertipu, hubungi 997 dan bank dengan segera.\n"
           "Mesej (butiran peribadi dibuang): {text}"),
}


def family_summary(rec, label):
    lang = rec["language"] if rec["language"] in SUMMARY else "en"
    why = "; ".join(c["why"] for c in rec["cues"][:3] if c.get("why")) or "-"
    return SUMMARY[lang].format(label=label, channel=rec["channel"], why=why, text=rec["redacted_text"])


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
            return 422, {"error": f"No QR code could be read from that image ({reason}). "
                                  "Paste the link or message text instead."}
        text, channel = decoded, "qr"
        extra = [{"tool": "qr_decode", "status": "ok", "result": "decoded"}]

    if not isinstance(text, str) or not text.strip():
        return 400, {"error": "Paste a message, a link, or upload a QR image."}
    rec = gl.build_record(text[:MAX_TEXT], channel, language, call=call,
                          url_reputation=reputation, extra_checks=extra)
    out = aw.assess(rec, payload.get("answers"), bool(payload.get("already_acted")))
    if out.get("status") == "error":
        return 400, {"error": "; ".join(out["error"])}
    shown = out if out["status"] == "final" else out["provisional"]
    out["family_summary"] = family_summary(rec, shown["result"])
    out["call_997"] = bool(payload.get("already_acted"))
    out["trace"] = {"engine": rec["engine"], "risk_score": rec["risk_score"],
                    "checks": rec["checks_run"],
                    "cues": [{"type": c["type"], "text": c["text"]} for c in rec["cues"]],
                    "redacted_text": rec["redacted_text"]}
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
            if not 0 < length <= MAX_BODY:
                return self._send(413, b'{"error":"Request too large."}', "application/json")
            payload = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return self._send(400, b'{"error":"Bad JSON."}', "application/json")
        status, body = handle(payload, self.call, self.reputation)
        self._send(status, json.dumps(body, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def log_message(self, *args):  # never log request lines or bodies
        pass


def serve(call=None, reputation=None, port=8000):
    """Start the demo server on 127.0.0.1 (blocks until Ctrl+C)."""
    print(f"Gemini: {'ON' if call else 'off'} | Safe Browsing: {'ON' if reputation else 'off'} "
          f"| http://127.0.0.1:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", port), partial(Handler, call=call, reputation=reputation)).serve_forever()


def main():
    call = gl.make_gemini_call() if os.environ.get("GEMINI_API_KEY") else None
    key = os.environ.get("SAFE_BROWSING_KEY")
    reputation = (lambda urls: checks.safe_browsing(key, urls)) if key else None
    serve(call, reputation)


if __name__ == "__main__":
    main()
