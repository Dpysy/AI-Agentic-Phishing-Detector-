"""One-command launcher. Reads your keys from the ENVIRONMENT (never from a file in this folder),
checks that they work, then starts the app.

    python run.py                  check keys, then start the app on http://127.0.0.1:8000
    python run.py --check          only check keys, then exit (exit code 0 = Gemini works)
    python run.py --require-gemini refuse to start without a working Gemini key
    python run.py --no-check       skip the live key check and just start
    python run.py --port 8080

If Google is only busy (503/429/timeout) at startup, Gemini stays on: every check tries it again, and a
check where it does not answer is shown as "failed", which can never give "Likely Safe".

Environment variables:
    GEMINI_API_KEY      required for Gemini cue extraction (from Google AI Studio)
    GEMINI_MODEL        optional; tried first, then gemini-flash-lite-latest, then gemini-flash-latest
    SAFE_BROWSING_KEY   optional, enables the Google Safe Browsing link check

Set them (open a NEW terminal afterwards for the permanent options):
    Windows PowerShell, this session only:  $env:GEMINI_API_KEY = "paste-key-here"
    Windows, permanent:                     setx GEMINI_API_KEY "paste-key-here"
    macOS / Linux, this session only:       export GEMINI_API_KEY="paste-key-here"
    macOS / Linux, permanent:               add the export line to ~/.zshrc or ~/.bashrc
"""
import argparse
import os
import sys

import checks
import gemini_layer as gl

GEMINI_TEST_MESSAGE = "MyBank: Your account has been frozen. Verify within 24 hours at https://mybank-secure.example/verify"
GOOGLES_TEST_URL = "https://testsafebrowsing.appspot.com/s/malware.html"


def read_key(name, env=None):
    """Return the cleaned value of an environment variable, or None. Strips spaces and pasted quotes."""
    value = (env if env is not None else os.environ).get(name)
    if value is None:
        return None
    value = value.strip().strip("'\"").strip()
    return value or None


def scrub(text, secrets):
    """Remove every secret from text before it is ever printed."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def describe_key(key):
    return f"{key[:4]}... ({len(key)} characters)"


def check_gemini(key, call_factory=gl.make_gemini_call, timeout_s=25.0):
    """Make ONE real call. Returns (ok, message); the message never contains the key.
    ok is True (works), False (broken: key, package, model name) or None (Google busy or slow right now;
    the key may be fine, so the app keeps Gemini on and each check shows it as failed if it stays busy)."""
    try:
        call = call_factory()
    except ImportError:
        return False, "The google-genai package is missing. Run:  pip install google-genai"
    except Exception as exc:
        return False, scrub(f"Could not set up Gemini: {type(exc).__name__}: {exc}"[:300], [key])
    import json
    try:
        raw = gl.call_with_timeout(call, gl.build_prompt(gl.redact(GEMINI_TEST_MESSAGE)), timeout_s)
        data = json.loads(raw)
        n = len(data["cues"])
    except TimeoutError:
        return None, (f"No answer from Gemini within {timeout_s:.0f}s. Google may be busy; "
                      "otherwise check your internet connection.")
    except Exception as exc:
        text = scrub(f"{type(exc).__name__}: {exc}"[:300], [key])
        low = text.lower()
        if "api key" in low or "api_key" in low or "401" in low or "403" in low or "permission" in low:
            return False, text + "  Hint: the key looks wrong, expired or not enabled. Create a new one in Google AI Studio."
        if "404" in low or "not found" in low:
            return False, text + "  Hint: the model name may be outdated. Set GEMINI_MODEL to a current model from AI Studio."
        if "connect" in low or "name or service" in low or "getaddrinfo" in low or "timed out" in low:
            return None, text + "  Hint: could not reach Google. Check your internet connection, VPN or firewall."
        if "429" in low or "quota" in low or "resource" in low:
            return None, text + "  Hint: rate or quota limit reached. Wait a minute and try again."
        if "503" in low or "500" in low or "unavailable" in low or "overloaded" in low or "demand" in low:
            return None, text + "  Hint: Google is busy right now. This usually passes within minutes."
        return False, text
    if n == 0:
        return True, "Gemini answered, but found no warning signs in a test scam message (unexpected; the rules still work)."
    return True, f"Gemini works: it labelled {n} warning sign(s) in a test scam message."


def check_safe_browsing(key):
    entry = checks.safe_browsing(key, [GOOGLES_TEST_URL])
    if entry["status"] != "ok":
        return False, f"Safe Browsing check failed ({entry['result']}). Check the key and that the API is enabled."
    if entry["result"] == "flagged":
        return True, "Safe Browsing works: Google's test URL was flagged."
    return True, "Safe Browsing answered 'clean' for Google's test URL (expected 'flagged'). Treat as unconfirmed."


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check keys from the environment, then start the scam checker.")
    ap.add_argument("--check", action="store_true", help="only check keys, then exit")
    ap.add_argument("--no-check", action="store_true", help="skip the live key check")
    ap.add_argument("--require-gemini", action="store_true", help="exit instead of running without Gemini")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)

    gem_key = read_key("GEMINI_API_KEY")
    sb_key = read_key("SAFE_BROWSING_KEY")
    gemini_ok = False

    if gem_key is None:
        print("GEMINI_API_KEY is not set in this terminal.")
        print("  Windows PowerShell:  $env:GEMINI_API_KEY = \"paste-key-here\"   (permanent: setx GEMINI_API_KEY \"...\", then open a new terminal)")
        print("  macOS / Linux:       export GEMINI_API_KEY=\"paste-key-here\"")
    else:
        os.environ["GEMINI_API_KEY"] = gem_key  # cleaned value for the SDK call
        print(f"GEMINI_API_KEY found: {describe_key(gem_key)}   models, in order: {', '.join(gl.model_names())}")
        if args.no_check:
            gemini_ok = True
        else:
            print("Testing Gemini with one small call...")
            gemini_ok, msg = check_gemini(gem_key)
            print({True: "  OK: ", False: "  FAILED: ", None: "  BUSY: "}[gemini_ok] + msg)
            if gemini_ok is None:
                print("  Keeping Gemini on. Checks where it does not answer show it as 'failed' (never 'Likely Safe').")

    reputation = None
    if sb_key:
        print(f"SAFE_BROWSING_KEY found: {describe_key(sb_key)}")
        if args.no_check:
            sb_ok = True
        else:
            sb_ok, msg = check_safe_browsing(sb_key)
            print(("  OK: " if sb_ok else "  FAILED: ") + msg)
        if sb_ok:
            reputation = lambda urls: checks.safe_browsing(sb_key, urls)

    if args.check:
        return 0 if gemini_ok else 1
    use_gemini = gemini_ok is not False  # None = busy right now, worth retrying per check
    if args.require_gemini and not use_gemini:
        print("Stopping: --require-gemini was given and Gemini is not working.")
        return 1

    call = gl.make_gemini_call() if use_gemini else None
    if call is None:
        print("Starting in rules-only mode (no Gemini). The result page shows which engine ran.")
    import app
    try:
        app.serve(call, reputation, args.port)
    except KeyboardInterrupt:
        print("\nStopped.")
    except OSError as exc:
        print(f"Could not start on port {args.port}: {exc}. Try --port 8080.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
