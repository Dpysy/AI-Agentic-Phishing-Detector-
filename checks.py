"""Standalone checks used by gemini_layer.build_record. Standard library only,
except decode_qr (optional: pip install opencv-python-headless numpy).

* rules_cues      : deterministic English/Malay keyword rules. Works offline, is the fallback
                    when Gemini is unavailable, and is what the offline evaluation measures.
* safe_browsing   : Google Safe Browsing v4 lookup. NOT exercised live in this repo's tests
                    (needs a key and network). "clean" only means "not on Google's list yet".
* decode_qr       : QR image -> text. A QR code is just a link in disguise.
"""
import importlib.util
import json
import re
import urllib.request

# ------------------------------------------------------------------ rules
_NEG = re.compile(r"(do not|don't|dont|never|jangan|tidak akan|tak akan)\W+(\w+\W+){0,3}$", re.I)

RULES = {
    "urgency": [
        r"within \d+ ?(hours?|hrs?|minutes?|mins?)", r"\bimmediately\b", r"\burgent(ly)?\b",
        r"\bact now\b", r"final notice|last warning", r"expires? today", r"\bsegera\b",
        r"serta-merta", r"dalam masa \d+ ?(jam|minit|hari)", r"hari ini sahaja",
        r"\b24 jam\b", r"\bre-?verify now\b", r"\bnow to avoid\b",
    ],
    "fear": [
        r"(account|akaun|wallet|card|kad).{0,30}(frozen|suspended|blocked|locked|closed|limited|dibekukan|digantung|disekat|ditutup|dikunci|dihadkan)",
        r"(arrest|warrant|waran|ditangkap|tangkap|legal action|tindakan undang|summons|saman\b|mahkamah)",
        r"(unauthori[sz]ed|suspicious) (transaction|activity)", r"transaksi (mencurigakan|tanpa kebenaran)",
        r"money laundering|pengubahan wang haram", r"will be (closed|terminated)",
        r"permanent(ly)? (closure|closed)",
    ],
    "claims_authority": [
        r"bank negara|\bbnm\b|\bpdrm\b|\bpolis\b|\bpolice\b|\blhdn\b|inland revenue|\bmcmc\b|kastam|customs",
        r"pos ?laju|j&t|\bdhl\b|maybank|cimb|public bank|\brhb\b|hong leong|ambank|bank islam|touch ?.?n.? ?go|\bmybank\b",
    ],
    "sensitive_request": [
        r"(send|enter|provide|give|share|reply with|key in|submit|masukkan|berikan|beri|hantar|kongsi|isi)\b.{0,30}(otp|tac|password|kata laluan|\bpin\b|cvv|card number|nombor kad|bank details|butiran akaun|butiran bank|username)",
        r"(transfer|pindah|remit|bayar|pay)\b.{0,40}(to|ke|into)\b.{0,30}(account|akaun|acc\b)",
        r"safe account|akaun selamat", r"(processing|admin) fee|yuran proses",
    ],
    "callback_request": [
        r"(call|hubungi|telefon|phone)\b.{0,50}\[phone\]",
        r"\[phone\].{0,50}(cancel|batal|verify|sahkan|dispute)",
    ],
    "lure": [
        r"you have won|you('ve| have) been (selected|chosen)|tahniah|congratulations|\bmenang\b|hadiah|\bprize\b",
        r"claim (your|now)|tuntut sekarang|reward points?|mata ganjaran|free (gift|iphone)|cash reward",
        r"earn rm ?\d+|per day|sehari|setiap hari|part-?time job|kerja sambilan|no experience",
        r"guaranteed (profit|returns?)|pulangan terjamin|\d+% profit|bantuan tunai|tax refund|bayaran balik cukai|\brefund\b",
    ],
}
_COMPILED = {k: [re.compile(p, re.I) for p in v] for k, v in RULES.items()}
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060\ufeff]")
_NEEDS_CONTEXT = {"claims_authority"}  # only worth showing next to another cue
_CALLBACK_WORDS = re.compile(r"cancel|batal|verify|sahkan|dispute|not you|bukan anda|unauthori|tanpa kebenaran", re.I)


def rules_cues(redacted_text):
    """Return (cues, check). Never raises."""
    cues = []
    for ctype, patterns in _COMPILED.items():
        for pat in patterns:
            hit = None
            for m in pat.finditer(redacted_text):
                before = redacted_text[max(0, m.start() - 40):m.start()]
                if ctype == "sensitive_request" and _NEG.search(before + m.group(0).split()[0] + " "):
                    continue  # "do not share your OTP" is a warning, not a request
                if ctype == "callback_request" and not _CALLBACK_WORDS.search(redacted_text):
                    continue
                hit = m
                break
            if hit:
                cues.append({"type": ctype, "text": hit.group(0).strip()[:80], "why": ""})
                break
    if _ZERO_WIDTH.search(redacted_text):
        cues.append({"type": "hidden_text", "text": "(hidden characters)", "why": ""})
    if len(cues) == 1 and cues[0]["type"] in _NEEDS_CONTEXT:
        cues = []
    return cues, {"tool": "rules_cues", "status": "ok", "result": f"{len(cues)} cues"}


# ------------------------------------------------------------------ Safe Browsing
SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="


def safe_browsing(api_key, urls, opener=urllib.request.urlopen, timeout=8):
    """One batched lookup. Returns a checks_run entry; never raises.
    URLs sent to Google are the (scam) links in the message, never the message text."""
    body = {"client": {"clientId": "scam-defence-prototype", "clientVersion": "0.1"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": u} for u in urls[:50]]}}
    req = urllib.request.Request(SB_ENDPOINT + api_key, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with opener(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return {"tool": "url_reputation", "status": "ok",
                "result": "flagged" if data.get("matches") else "clean"}
    except Exception as exc:
        return {"tool": "url_reputation", "status": "failed", "result": type(exc).__name__}


# ------------------------------------------------------------------ QR
def qr_supported():
    """True when the optional QR packages are installed (pip install opencv-python-headless numpy)."""
    return all(importlib.util.find_spec(name) for name in ("cv2", "numpy"))


def decode_qr(image_bytes):
    """Return (text_or_None, reason). Needs opencv-python-headless + numpy."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        return None, "qr_support_not_installed"
    log = getattr(getattr(cv2, "utils", None), "logging", None)
    if log:  # hide harmless console warnings such as "ECI is not supported properly"
        log.setLogLevel(log.LOG_LEVEL_ERROR)
    img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return None, "unreadable_image"
    text, _points, _ = cv2.QRCodeDetector().detectAndDecode(img)
    return (text, "ok") if text else (None, "no_qr_found")
