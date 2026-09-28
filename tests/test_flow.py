import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, PrivacyRequestService  # noqa: E402


class PrivacyRequestFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = PrivacyRequestService(Path(self.tmp.name) / "test.db")
        self.service.configure_jurisdiction("sup1", "supervisor", "CN", "中国", 30, 30, True, True)
        self.subject = self.service.create_subject("intake1", "intake", "SUB-001", "CN", False, "person@example.test")

    def tearDown(self):
        self.tmp.cleanup()

    def make_request(self, number, kind="access", subject=None, key=None, requester="self", authority=None):
        return self.service.create_request(
            "intake1", "intake", number, (subject or self.subject)["id"], kind,
            key or "IDEM-" + number, requester, authority,
        )["request"]

    def test_complete_access_request_with_redaction(self):
        request = self.make_request("PR-001")
        request = self.service.verify_identity("officer1", "privacy_officer", request["id"], request["version"], "ID-001")
        request = self.service.assign_request("sup1", "supervisor", request["id"], "officer1", request["version"])
        normal = self.service.add_data_location("officer1", "privacy_officer", request["id"], "CRM", "profile", "customer")
        third = self.service.add_data_location("officer1", "privacy_officer", request["id"], "SUPPORT", "messages", "service")
        classified = self.service.classify_location("officer1", "privacy_officer", normal["id"], False, False, False)
        self.assertEqual("classified", classified["status"])
        third = self.service.classify_location("officer1", "privacy_officer", third["id"], True, False, False, "已遮蔽第三方姓名")
        self.assertEqual("classified", third["status"])
        request = self.service.prepare_response("officer1", "privacy_officer", request["id"], request["version"])
        request = self.service.fulfill_request("officer1", "privacy_officer", request["id"], "已提供副本并遮蔽第三方信息", request["version"])
        self.assertEqual("fulfilled", request["status"])
        detail = self.service.get_request("sup1", "supervisor", request["id"])
        self.assertEqual(2, len(detail["locations"]))
        self.assertGreaterEqual(len(detail["timeline"]), 6)

    def test_minor_agent_duplicate_and_extension_rules(self):
        minor = self.service.create_subject("intake1", "intake", "SUB-MINOR", "CN", True, "minor@example.test")
        with self.assertRaises(DomainError) as ctx:
            self.service.create_request("intake1", "intake", "PR-M1", minor["id"], "deletion", "IDEM-M1", "self")
        self.assertEqual(403, ctx.exception.status)
        first = self.service.create_request("intake1", "intake", "PR-M2", minor["id"], "deletion", "IDEM-M2", "guardian")
        duplicate = self.service.create_request("intake1", "intake", "PR-M3", minor["id"], "deletion", "IDEM-M3", "guardian")
        self.assertEqual("duplicate", duplicate["request"]["status"])
        self.assertEqual(first["request"]["id"], duplicate["request"]["duplicate_of"])
        same = self.service.create_request("intake1", "intake", "PR-M4", minor["id"], "deletion", "IDEM-M2", "guardian")
        self.assertTrue(same["idempotent"])
        request = first["request"]
        request = self.service.verify_identity("officer1", "privacy_officer", request["id"], request["version"], "ID-MINOR")
        request = self.service.assign_request("sup1", "supervisor", request["id"], "officer1", request["version"])
        request = self.service.extend_request("sup1", "supervisor", request["id"], 10, "等待跨系统取证", request["version"])
        self.assertEqual("extended", request["status"])
        with self.assertRaises(DomainError) as ctx2:
            self.service.extend_request("sup1", "supervisor", request["id"], 5, "再次延期", request["version"])
        self.assertEqual(409, ctx2.exception.status)

    def test_deletion_legal_hold_permission_and_version_conflict(self):
        request = self.make_request("PR-DEL", "deletion")
        request = self.service.verify_identity("officer1", "privacy_officer", request["id"], request["version"], "ID-DEL")
        request = self.service.assign_request("sup1", "supervisor", request["id"], "officer1", request["version"])
        location = self.service.add_data_location("officer1", "privacy_officer", request["id"], "ARCHIVE", "records", "legal")
        blocked = self.service.classify_location("officer1", "privacy_officer", location["id"], False, True, False)
        self.assertEqual("blocked", blocked["status"])
        with self.assertRaises(DomainError) as ctx:
            self.service.prepare_response("officer1", "privacy_officer", request["id"], request["version"])
        self.assertEqual(409, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx2:
            self.service.classify_location("other", "privacy_officer", location["id"], False, False, False)
        self.assertEqual(403, ctx2.exception.status)
        with self.assertRaises(DomainError) as ctx3:
            self.service.fulfill_request("officer1", "privacy_officer", request["id"], "越权完成", request["version"] + 10)
        self.assertEqual(409, ctx3.exception.status)


if __name__ == "__main__":
    unittest.main()
