import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, PrivacyRequestService  # noqa: E402


class FakeClock:
    def __init__(self, dt):
        self.dt = dt

    def __call__(self):
        return self.dt

    def advance(self, **kwargs):
        self.dt += timedelta(**kwargs)
        return self.dt.isoformat(timespec="seconds")

    def iso(self):
        return self.dt.isoformat(timespec="seconds")


def timeline_events(detail):
    return [{**e, "details": json.loads(e["details"])} for e in detail["timeline"]]


class RuleVersioningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = FakeClock(datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc))
        self.service = PrivacyRequestService(Path(self.tmp.name) / "test.db", clock=self.clock)
        self.service.configure_jurisdiction("sup1", "supervisor", "CN", "中国", 30, 30, True, True)
        self.subject = self.service.create_subject("intake1", "intake", "SUB-001", "CN", False, "p@example.test")

    def tearDown(self):
        self.tmp.cleanup()

    def make_request(self, number, kind="access"):
        return self.service.create_request(
            "intake1", "intake", number, self.subject["id"], kind, "IDEM-" + number
        )["request"]

    def open_request(self, number, kind="access"):
        req = self.make_request(number, kind)
        req = self.service.verify_identity("o1", "privacy_officer", req["id"], req["version"], "ID-1")
        return self.service.assign_request("sup1", "supervisor", req["id"], "o1", req["version"])

    def test_draft_not_used_until_effective_time(self):
        future = (self.clock.dt + timedelta(days=2)).isoformat()
        draft = self.service.configure_jurisdiction(
            "sup1", "supervisor", "CN", "中国", 10, 5, True, True,
            change_reason="监管时限收紧", effective_at=future,
        )
        self.assertEqual("draft", draft["status"])
        self.assertEqual(2, draft["version_no"])
        # 草案未到点：新案件仍按 v1（30 天）
        req = self.make_request("PR-A", "access")
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        self.assertEqual(1, detail["request"]["rule_version_no"])
        self.assertEqual(30, detail["rule_version"]["response_days"])
        # 到点后受理：自动发布 v2，新案件按 v2（10 天）
        self.clock.advance(days=3)
        req2 = self.make_request("PR-B", "correction")
        detail2 = self.service.get_request("sup1", "supervisor", req2["id"])
        self.assertEqual(2, detail2["request"]["rule_version_no"])
        self.assertEqual(10, detail2["rule_version"]["response_days"])
        versions = {v["version_no"]: v["status"] for v in self.service.jurisdiction_history(code="CN")}
        self.assertEqual("superseded", versions[1])
        self.assertEqual("active", versions[2])

    def test_extension_reads_bound_version_cap(self):
        req = self.open_request("PR-EXT", "access")
        original_due = req["original_due_date"]
        future = (self.clock.dt + timedelta(days=2)).isoformat()
        self.service.configure_jurisdiction(
            "sup1", "supervisor", "CN", "中国", 30, 5, True, True,
            change_reason="延期上限下调", effective_at=future,
        )
        self.clock.advance(days=3)  # v2（上限 5 天）生效，但案件绑的是 v1（上限 30 天）
        # 20 天：超过新上限但在受理时 v1 上限内，应当允许
        req = self.service.extend_request("sup1", "supervisor", req["id"], 20, "跨系统取证", req["version"])
        self.assertEqual("extended", req["status"])
        self.assertEqual(original_due, req["original_due_date"])
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        self.assertEqual(1, detail["rule_version"]["version_no"])
        ext_event = [e for e in timeline_events(detail) if e["action"] == "request.extended"]
        self.assertEqual(1, ext_event[0]["details"]["rule_version_no"])
        self.assertEqual(30, ext_event[0]["details"]["max_extension_days"])
        # 新案件受 v2 上限约束（用不同请求类型避免 30 天重复识别）
        new_req = self.open_request("PR-EXT2", "correction")
        with self.assertRaises(DomainError) as ctx:
            self.service.extend_request("sup1", "supervisor", new_req["id"], 20, "超限", new_req["version"])
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("v2", str(ctx.exception))

    def test_draft_can_be_withdrawn_published_cannot_change(self):
        future = (self.clock.dt + timedelta(days=2)).isoformat()
        draft = self.service.configure_jurisdiction(
            "sup1", "supervisor", "CN", "中国", 10, 5, True, True,
            change_reason="拟收紧", effective_at=future,
        )
        # 已发布版本不能撤回（即使当前有草案）
        with self.assertRaises(DomainError) as ctx_active:
            self.service.withdraw_rule_draft("sup1", "supervisor", 1, "想改回")
        self.assertEqual(409, ctx_active.exception.status)
        withdrawn = self.service.withdraw_rule_draft("sup1", "supervisor", draft["id"], "参数填错")
        self.assertEqual("withdrawn", withdrawn["status"])
        # 撤回必须填原因
        with self.assertRaises(DomainError) as ctx_reason:
            self.service.withdraw_rule_draft("sup1", "supervisor", draft["id"], "")
        self.assertEqual(400, ctx_reason.exception.status)
        # 草案撤回后：发布过的规则仍不能原地改
        with self.assertRaises(DomainError) as ctx2:
            self.service.configure_jurisdiction("sup1", "supervisor", "CN", "中国", 40, 40)
        self.assertEqual(409, ctx2.exception.status)
        # 补正必须带原因
        with self.assertRaises(DomainError) as ctx3:
            self.service.configure_jurisdiction(
                "sup1", "supervisor", "CN", "中国", 40, 40, effective_at=future
            )
        self.assertEqual(400, ctx3.exception.status)
        # 生效时间必须在未来
        with self.assertRaises(DomainError) as ctx4:
            self.service.configure_jurisdiction(
                "sup1", "supervisor", "CN", "中国", 40, 40,
                change_reason="立即", effective_at=self.clock.iso(),
            )
        self.assertEqual(409, ctx4.exception.status)
        # 非主管不能配置或撤回
        with self.assertRaises(DomainError) as ctx5:
            self.service.configure_jurisdiction(
                "o1", "privacy_officer", "CN", "中国", 12, 6, True, True,
                change_reason="越权", effective_at=future,
            )
        self.assertEqual(403, ctx5.exception.status)
        # 撤回后可以重新补正，版本号继续递增（不复用撤回版本）
        future2 = (self.clock.dt + timedelta(days=5)).isoformat()
        redraft = self.service.configure_jurisdiction(
            "sup1", "supervisor", "CN", "中国", 12, 6, True, True,
            change_reason="重新修订", effective_at=future2,
        )
        self.assertEqual("draft", redraft["status"])
        self.assertEqual(3, redraft["version_no"])
        with self.assertRaises(DomainError) as ctx6:
            self.service.withdraw_rule_draft("o1", "privacy_officer", redraft["id"], "x")
        self.assertEqual(403, ctx6.exception.status)

    def test_only_one_pending_draft_per_jurisdiction(self):
        future = (self.clock.dt + timedelta(days=5)).isoformat()
        self.service.configure_jurisdiction(
            "sup1", "supervisor", "CN", "中国", 10, 5, True, True,
            change_reason="草案一", effective_at=future,
        )
        with self.assertRaises(DomainError) as ctx:
            self.service.configure_jurisdiction(
                "sup1", "supervisor", "CN", "中国", 12, 6, True, True,
                change_reason="草案二", effective_at=(self.clock.dt + timedelta(days=6)).isoformat(),
            )
        self.assertEqual(409, ctx.exception.status)

    def test_recalculate_uses_bound_version_and_keeps_original_due(self):
        req = self.open_request("PR-RC", "access")
        original_due = req["original_due_date"]
        req = self.service.extend_request("sup1", "supervisor", req["id"], 10, "取证", req["version"])
        extended_due = req["due_date"]
        # 重算不改变原到期日；延期天数仍叠加在原到期日上
        req = self.service.recalculate_deadline(
            "sup1", "supervisor", req["id"], req["version"], reason="核对节假日"
        )
        self.assertEqual(original_due, req["original_due_date"])
        self.assertEqual(extended_due, req["due_date"])
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        event = [e for e in timeline_events(detail) if e["action"] == "deadline.recalculated"]
        self.assertEqual(1, event[0]["details"]["rule_version_no"])
        with self.assertRaises(DomainError) as ctx:
            self.service.recalculate_deadline("o1", "privacy_officer", req["id"], req["version"])
        self.assertEqual(403, ctx.exception.status)

    def test_detail_shows_rule_version_original_due_and_changes(self):
        req = self.open_request("PR-DET", "access")
        future = (self.clock.dt + timedelta(days=2)).isoformat()
        self.service.configure_jurisdiction(
            "sup1", "supervisor", "CN", "中国", 10, 5, True, True,
            change_reason="收紧", effective_at=future,
        )
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        self.assertIn("original_due_date", detail["request"])
        self.assertEqual(1, detail["request"]["rule_version_no"])
        self.assertEqual(30, detail["rule_version"]["response_days"])
        statuses = [(v["version_no"], v["status"], v["change_reason"]) for v in detail["rule_changes"]]
        self.assertIn((1, "active", ""), statuses)
        self.assertIn((2, "draft", "收紧"), statuses)

    def test_legacy_single_row_schema_migrates_and_binds_existing_requests(self):
        db = Path(self.tmp.name) / "legacy.db"
        with sqlite3.connect(db) as conn:
            conn.executescript(
                """
                CREATE TABLE jurisdictions(code TEXT PRIMARY KEY,name TEXT NOT NULL,response_days INTEGER NOT NULL,
                    max_extension_days INTEGER NOT NULL,minor_guardian_required INTEGER NOT NULL,
                    agent_authority_required INTEGER NOT NULL,updated_by TEXT NOT NULL,updated_at TEXT NOT NULL);
                CREATE TABLE data_subjects(id INTEGER PRIMARY KEY AUTOINCREMENT,subject_ref TEXT NOT NULL UNIQUE,
                    region TEXT NOT NULL,is_minor INTEGER NOT NULL DEFAULT 0,contact_hash TEXT NOT NULL,created_at TEXT NOT NULL);
                CREATE TABLE requests(id INTEGER PRIMARY KEY AUTOINCREMENT,request_no TEXT NOT NULL UNIQUE,
                    subject_id INTEGER NOT NULL,request_type TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'received',
                    jurisdiction TEXT NOT NULL,requester_kind TEXT NOT NULL,agent_authority_ref TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE,duplicate_of INTEGER REFERENCES requests(id),
                    submitted_at TEXT NOT NULL,due_date TEXT NOT NULL,original_due_date TEXT NOT NULL,
                    extension_days INTEGER NOT NULL DEFAULT 0,verified_at TEXT,verified_by TEXT,assigned_to TEXT,
                    denial_reason TEXT,response_summary TEXT,created_by TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL);
                CREATE TABLE data_locations(id INTEGER PRIMARY KEY AUTOINCREMENT,request_id INTEGER NOT NULL,
                    system_name TEXT NOT NULL,data_category TEXT NOT NULL,owner_team TEXT NOT NULL,
                    contains_third_party INTEGER NOT NULL DEFAULT 0,legal_hold INTEGER NOT NULL DEFAULT 0,
                    retention_exception INTEGER NOT NULL DEFAULT 0,third_party_exception INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'located',note TEXT NOT NULL DEFAULT '',version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
                CREATE TABLE timeline(id INTEGER PRIMARY KEY AUTOINCREMENT,request_id INTEGER,actor TEXT NOT NULL,
                    action TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL);
                """
            )
            conn.execute(
                "INSERT INTO jurisdictions VALUES('CN','中国',45,45,1,1,'old-sup','2025-12-01T00:00:00+00:00')"
            )
            conn.execute(
                "INSERT INTO data_subjects(subject_ref,region,is_minor,contact_hash,created_at) VALUES('S1','CN',0,'h','2025-12-02T00:00:00+00:00')"
            )
            conn.execute(
                """INSERT INTO requests(request_no,subject_id,request_type,status,jurisdiction,requester_kind,
                   idempotency_key,submitted_at,due_date,original_due_date,created_by,updated_at)
                   VALUES('PR-OLD',1,'access','processing','CN','self','K1','2025-12-02T00:00:00+00:00',
                   '2026-01-16T00:00:00+00:00','2026-01-16T00:00:00+00:00','i','2025-12-02T00:00:00+00:00')"""
            )
        legacy = PrivacyRequestService(db, clock=self.clock)
        detail = legacy.get_request("sup1", "supervisor", 1)
        self.assertEqual(1, detail["request"]["rule_version_no"])
        self.assertEqual(45, detail["rule_version"]["response_days"])
        self.assertEqual(45, detail["rule_version"]["max_extension_days"])
        # 迁移后不能原地改；存量案件延期仍按旧上限 45
        future = (self.clock.dt + timedelta(days=2)).isoformat()
        legacy.configure_jurisdiction(
            "sup1", "supervisor", "CN", "中国", 30, 30, True, True,
            change_reason="新规", effective_at=future,
        )
        req = legacy.extend_request("sup1", "supervisor", 1, 40, "旧案延期", detail["request"]["version"])
        self.assertEqual("extended", req["status"])


if __name__ == "__main__":
    unittest.main()
