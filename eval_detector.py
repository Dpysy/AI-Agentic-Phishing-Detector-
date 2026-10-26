"""Offline evaluation on data/eval_set.jsonl (hand-written, synthetic, 40 messages).

Reports two operating points:
  strict : positive = "Likely Scam" only
  cautious: positive = "Likely Scam" or "Verify First"
For legit messages, only a "Likely Safe" verdict is a fully correct outcome at the cautious point.

Honest limits: the set is tiny, written by the same people who wrote the rules, so numbers are
OPTIMISTIC. Treat it as a regression test and a template. Replace with real (redacted) samples.
Run:  python eval_detector.py            (rules only, no network)
      GEMINI_API_KEY=... python eval_detector.py --delay 5   (adds live Gemini; the delay keeps 40 calls
      under the free tier's per-minute limit, otherwise later messages fail and count as "Verify First")
"""
import argparse
import json
import os
import sys
import time

import agent_workflow as aw
import gemini_layer as gl

PATH = os.path.join(os.path.dirname(__file__), "data", "eval_set.jsonl")


def load():
    with open(PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def predict(row, call=None, reputation=None):
    rec = gl.build_record(row["text"], row["channel"], row["language"], call=call, url_reputation=reputation)
    out = aw.run(rec, {"asked_for_secret": False}, interactive=False)
    return out["result_code"], rec


def metrics(rows, preds, positive):
    tp = sum(1 for r, p in zip(rows, preds) if r["label"] == "scam" and p in positive)
    fn = sum(1 for r, p in zip(rows, preds) if r["label"] == "scam" and p not in positive)
    fp = sum(1 for r, p in zip(rows, preds) if r["label"] == "legit" and p in positive)
    tn = sum(1 for r, p in zip(rows, preds) if r["label"] == "legit" and p not in positive)
    rate = lambda a, b: f"{a}/{a + b} = {100 * a / (a + b):.0f}%" if a + b else "n/a"
    return {"scam caught (recall)": rate(tp, fn), "legit wrongly flagged (FP rate)": rate(fp, tn)}


def main(call=None, reputation=None, out=sys.stdout, delay_s=0.0):
    rows = load()
    results = []
    for i, r in enumerate(rows):
        if call is not None and delay_s and i:
            time.sleep(delay_s)
        results.append(predict(r, call, reputation))
    preds, recs = zip(*results)
    engine = recs[0]["engine"]
    print(f"Engine: {engine}   messages: {len(rows)} ({sum(r['label'] == 'scam' for r in rows)} scam, "
          f"{sum(r['label'] == 'legit' for r in rows)} legit)", file=out)
    failed = [r["id"] for r, rec in zip(rows, recs)
              if any(c["tool"] == "gemini_cues" and c["status"] == "failed" for c in rec["checks_run"])]
    if failed:
        # A failed check is "unknown", which blocks Likely Safe by design, so failures inflate false alarms.
        print(f"Gemini check FAILED on {len(failed)} message(s) (often the free-tier rate limit): "
              f"{', '.join(f'#{i}' for i in failed)}. Those cannot be Likely Safe.", file=out)
    print(file=out)
    for name, positive in (("strict (Likely Scam only)", {"likely_scam"}),
                           ("cautious (Likely Scam or Verify First)", {"likely_scam", "verify_first"})):
        print(name, file=out)
        for k, v in metrics(rows, preds, positive).items():
            print(f"  {k}: {v}", file=out)
    print("\nMissed scams (verdict not Likely Scam):", file=out)
    for r, p in zip(rows, preds):
        if r["label"] == "scam" and p != "likely_scam":
            print(f"  #{r['id']:>2} [{p}] {r['text'][:80]}", file=out)
    print("\nLegit messages not cleared (verdict not Likely Safe):", file=out)
    for r, p in zip(rows, preds):
        if r["label"] == "legit" and p != "likely_safe":
            print(f"  #{r['id']:>2} [{p}] {r['text'][:80]}", file=out)
    return preds


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Evaluate the detector on data/eval_set.jsonl.")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to wait between Gemini calls")
    main(gl.gemini_from_env(), delay_s=ap.parse_args().delay)
