# AI Agentic Phishing Detector - safer workflow prototype

This folder contains a defensive update to `agent_workflow.py`. It processes an evidence record and produces a verdict, explanation, next steps, and (when relevant) a report draft.

## Important scope limitation

This Python file is a **decision and response layer**, not a complete independent phishing detector. It does not fetch URLs, query reputation services, parse email headers, or call Gemini. Those capabilities must be implemented in an upstream detection layer and its results supplied through `checks_run`, `cues`, and `risk_score`. A prompt string alone is not a live Gemini integration.

## Run the demonstration

```bash
python agent_workflow.py
```

## Run automated tests

```bash
python -m py_compile agent_workflow.py
python -m unittest discover -s tests -v
```

The tests use only Python's standard library.

## Changes in this version

- Stronger schema and type validation; malformed records return a structured `error` instead of causing common `TypeError`/`KeyError` crashes.
- Conservative verdict rules: a flagged check means `Likely Scam`; a failed/unknown/skipped check or no checks means a low-score message cannot be labelled `Likely Safe`.
- User-reported sensitive requests are added as evidence and cannot silently leave a low-risk record as `Likely Safe`.
- Check coverage is described as coverage, not as calibrated detection confidence. The legacy `confidence` output field remains for compatibility and mirrors the coverage level.
- The caller's evidence record is copied before processing so human reflection does not mutate the original input.
- More cautious safe-message wording, plus recovery guidance if the user has already acted.
- Added automated regression tests for built-in examples, unsafe verdict cases, invalid data, and mutation behaviour.

## Decision thresholds

- Risk score >= 70: `Likely Scam`
- Risk score 40-69: `Verify First`
- Risk score < 40: `Likely Safe` only if checks are available and none failed/flagged, and no overriding warning cues are present. Otherwise `Verify First` or `Likely Scam`.

These are rule-based thresholds, not empirically validated detection performance. Tune them only after evaluating a labelled test set and measuring precision, recall, false positives, and false negatives.

## Safety notes

- Use redacted message content. Never place real passwords, OTPs, access tokens, or unnecessary personal data in test fixtures.
- The workflow only prepares report drafts. It does not send reports or interact with suspicious links.
- Do not treat `Likely Safe` as a guarantee. Independent checks can be incomplete or wrong.
- Before deploying, implement and test the actual evidence-generation layer and any promised LLM/tool integration.

## How the pieces fit

```
raw message / link / QR photo
   -> gemini_layer.build_record   local URL + domain checks (raw text)
                                  redaction (OTP, phone, NRIC, card, email masked, URLs defanged)
                                  checks.rules_cues  (English + Malay rules, offline)
                                  Gemini cue extraction (optional, untrusted)
                                  checks.safe_browsing (optional)
   -> agent_workflow.assess       two-turn: may ask ONE question, then final verdict
   -> app.py + static/index.html  result, what to do, family summary, report draft, "show your work"
```

Run: `python run.py`. It reads `GEMINI_API_KEY` (and optionally `SAFE_BROWSING_KEY`, `GEMINI_MODEL`) from your environment, makes one test call to confirm the key works, then starts the app at http://127.0.0.1:8000. Use `python run.py --check` to only test the key, `--require-gemini` to refuse to start without it. The key is never printed or written to a file. `python app.py` starts the app without the key check.

Set the key (open a new terminal after `setx` / editing your shell profile): Windows PowerShell `$env:GEMINI_API_KEY = "..."` for this session or `setx GEMINI_API_KEY "..."` permanently; macOS/Linux `export GEMINI_API_KEY="..."`.
Tests: `python -m unittest discover -s tests -v`. Offline evaluation: `python eval_detector.py`.

## Design rules

- Gemini is one untrusted check. It can add cues, never lower a verdict, and none of its words reach the user: it only picks cue types from a fixed list and quotes a span, which must really appear in the message.
- If Gemini or Safe Browsing fails, that check is `failed` and the workflow cannot return "No Red Flags Found". A link with no reputation result is `skipped` for the same reason, unless every link is on an official bank domain.
- Any listed warning sign blocks "No Red Flags Found". The label is deliberately not "Likely Safe": sender IDs can be spoofed and a clean result only means the available checks found nothing.
- Banks (CIMB, Maybank) say they do not send links by SMS, and do not ask you to call a number in an SMS to verify or dispute a transaction. Both are treated as warning signs, even for official-looking links. Sender identity is never treated as proof, so there is no `trusted_sender` check in the builder.
- `ORGS` in `gemini_layer.py` holds only banks whose domains were confirmed on their own sites (Maybank, CIMB) plus a fictional demo bank. Add others only after confirming; an org not in the table is simply not checked.

## Evaluation (read the caveats)

`python eval_detector.py` on `data/eval_set.jsonl` (40 hand-written synthetic messages, English and Malay, 20 scam / 20 legitimate), rules only:

| Operating point | Scam caught | Legit wrongly flagged |
|---|---|---|
| Strict (Likely Scam only) | 10/20 (50%) | 0/20 |
| Cautious (Likely Scam or Verify First) | 20/20 (100%) | 2/20 (10%) |

Caveats: the set is tiny and written by the same people who wrote the rules, so these numbers are optimistic and are **not** a measure of real-world accuracy. After the first run (35% / 95% / 10%) the `sensitive_request` weight was raised and a rule was added that any warning sign blocks "No Red Flags"; both changes are principled but were made after seeing results. Without a Safe Browsing key every message with an unknown link stays at "Verify First" by design. Re-run with `GEMINI_API_KEY` set to measure Gemini, and replace the set with real redacted samples.

## Not verified here

- Live Gemini call (`make_gemini_call`) and live Safe Browsing lookup: no network access or keys in the build environment. Tests use fakes. Run `python gemini_layer.py` with a key and confirm the model name in AI Studio.
- 997 hours: government pages and March 2026 news say 24 hours, but some banks' pages still say 8am-8pm. The app tells people to call 997 without quoting hours. Confirm before the demo.
- Redaction does not remove names or addresses (no name recognition). Do not paste anything you would not show a judge.
- Cue weights in `CUE_WEIGHTS` are hand-set and uncalibrated.
- The browser page was not exercised in a real browser here; the API and server are tested.
