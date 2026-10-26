import copy
import unittest

import agent_workflow as aw


class WorkflowTests(unittest.TestCase):
    def test_demo_scam_is_scam(self):
        self.assertEqual(aw.run(aw.DEMO_SCAM, {"asked_for_secret": False})["result_code"], "likely_scam")

    def test_legitimate_demo_is_safe_when_checks_succeed(self):
        self.assertEqual(aw.run(aw.DEMO_LEGIT)["result_code"], "likely_safe")

    def test_neutral_demo_is_safe_when_checks_succeed(self):
        self.assertEqual(aw.run(aw.DEMO_NEUTRAL)["result_code"], "likely_safe")

    def test_failed_check_prevents_safe_verdict(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["checks_run"] = [{"tool": "url_reputation", "status": "failed", "result": None}]
        self.assertEqual(aw.run(rec, {"asked_for_secret": False})["result_code"], "verify_first")

    def test_no_checks_prevents_safe_verdict(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["checks_run"] = []
        self.assertEqual(aw.run(rec, {"asked_for_secret": False})["result_code"], "verify_first")

    def test_flagged_check_prevents_safe_verdict(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["checks_run"] = [{"tool": "url_reputation", "status": "ok", "result": "flagged"}]
        self.assertEqual(aw.run(rec)["result_code"], "likely_scam")

    def test_user_reports_sensitive_request_prevents_safe_verdict(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["checks_run"] = [{"tool": "url_reputation", "status": "failed", "result": None}]
        self.assertEqual(aw.run(rec, {"asked_for_secret": True})["result_code"], "verify_first")

    def test_sensitive_request_and_impersonation_escalate(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["cues"] = [{"type": "sensitive_request", "text": "", "why": ""},
                       {"type": "impersonation", "text": "bank", "why": ""}]
        self.assertEqual(aw.run(rec)["result_code"], "likely_scam")

    def test_string_score_returns_validation_error(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["risk_score"] = "87"
        self.assertIn("error", aw.run(rec))

    def test_none_checks_returns_validation_error(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["checks_run"] = None
        self.assertIn("error", aw.run(rec))

    def test_missing_tool_returns_validation_error(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["checks_run"] = [{"status": "failed", "result": None}]
        self.assertIn("error", aw.run(rec))

    def test_none_cues_returns_validation_error(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["cues"] = None
        self.assertIn("error", aw.run(rec))

    def test_string_cue_returns_validation_error(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["cues"] = ["urgency"]
        self.assertIn("error", aw.run(rec))

    def test_unhashable_status_returns_validation_error(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        rec["checks_run"] = [{"tool": "url_reputation", "status": [], "result": None}]
        self.assertIn("error", aw.run(rec))

    def test_unhashable_language_falls_back_safely(self):
        rec = copy.deepcopy(aw.DEMO_SCAM)
        rec["language"] = []
        result = aw.run(rec, {"asked_for_secret": False})
        self.assertEqual(result["result_code"], "likely_scam")
        self.assertIn("Only English and Malay", result["explanation"])

    def test_caller_record_is_not_mutated(self):
        rec = copy.deepcopy(aw.DEMO_NEUTRAL)
        before = copy.deepcopy(rec)
        aw.run(rec, {"asked_for_secret": True})
        self.assertEqual(rec, before)

    def test_already_acted_adds_recovery_steps(self):
        result = aw.run(aw.DEMO_SCAM, {"asked_for_secret": False}, already_acted=True)
        self.assertTrue(any("contact your bank" in action.lower() for action in result["actions"]))
        self.assertIsNotNone(result["report_draft"])

    def test_invalid_channel_returns_validation_error(self):
        rec = copy.deepcopy(aw.DEMO_SCAM)
        rec["channel"] = "telegram"
        self.assertIn("error", aw.run(rec))


if __name__ == "__main__":
    unittest.main()
