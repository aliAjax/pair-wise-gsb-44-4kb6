import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, PrivacyRequestService  # noqa: E402

BASE = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=BASE):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, days=0, hours=0):
        self.now += timedelta(days=days, hours=hours)
        return self.now.isoformat(timespec="seconds")


class RuleVersioningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.service = PrivacyRequestService(Path(self.tmp.name) / "test.db", clock=self.clock)
        self.service.configure_jurisdiction("sup1", "supervisor", "CN", "中国", 30, 30, True, True)
        self.subject = self.service.create_subject("intake1", "intake", "SUB-001", "CN", False, "person@example.test")

    def tearDown(self):
        self.tmp.cleanup()

    def make_request(self, number):
        return self.service.create_request(
            "intake1", "intake", number, self.subject["id"], "access", "IDEM-" + number
        )["request"]

    def start_processing(self, request):
        request = self.service.verify_identity("officer1", "privacy_officer", request["id"], request["version"], "ID-1")
        return self.service.assign_request("sup1", "supervisor", request["id"], "officer1", request["version"])

    def test_request_bound_to_version_effective_at_intake(self):
        # v1 生效中：30 天 / 延期上限 30 天
        request = self.make_request("PR-001")
        detail = self.service.get_request("sup1", "supervisor", request["id"])
        self.assertEqual(1, detail["request"]["rule_version"]["version_no"])
        self.assertEqual(request["due_date"], request["original_due_date"])
        self.assertEqual("CN v1", detail["request"]["rule_version_label"])

        # 补正 v2：响应 60 天 / 延期上限 15 天，10 天后生效，必须带原因
        future1 = (self.clock.now + timedelta(days=10)).isoformat(timespec="seconds")
        with self.assertRaises(DomainError) as ctx:
            self.service.create_rule_draft("sup1", "supervisor", "CN", 60, 15, future1, "   ")
        self.assertEqual(400, ctx.exception.status)
        draft = self.service.create_rule_draft("sup1", "supervisor", "CN", 60, 15, future1, "法定响应期调整")
        self.assertEqual(2, draft["version_no"])
        self.assertEqual("draft", draft["status"])

        # 生效前的新案件仍用 v1
        before = self.make_request("PR-002")
        before_detail = self.service.get_request("sup1", "supervisor", before["id"])
        self.assertEqual(1, before_detail["request"]["rule_version"]["version_no"],
                         "草案未生效前不应用于新案件")

        # 到点后新案件用 v2
        self.clock.advance(days=11)
        after = self.make_request("PR-003")
        detail_after = self.service.get_request("sup1", "supervisor", after["id"])
        self.assertEqual(2, detail_after["request"]["rule_version"]["version_no"])
        rules = {r["version_no"]: r for r in self.service.list_rules("sup1", "supervisor", "CN")}
        self.assertEqual("effective", rules[2]["status"])
        self.assertEqual("superseded", rules[1]["status"], "旧版本应在新版本生效时标记为被取代")

    def test_extension_and_recalculate_always_use_bound_version(self):
        request = self.start_processing(self.make_request("PR-101"))
        v1_due = request["due_date"]

        # v2 把延期上限收紧到 15 天并安排在 10 天后生效
        self.service.create_rule_draft(
            "sup1", "supervisor", "CN", 60, 15,
            (self.clock.now + timedelta(days=10)).isoformat(timespec="seconds"), "延期窗口收紧")
        self.clock.advance(days=11)

        # 旧案件再延期：仍按 v1 的 30 天上限，20 天允许
        request = self.service.extend_request("sup1", "supervisor", request["id"], 20,
                                              "跨系统取证", request["version"])
        self.assertEqual("extended", request["status"])
        self.assertEqual(20, request["extension_days"])
        # 原承诺到期日不变，当前到期日顺延
        self.assertEqual(v1_due, request["original_due_date"])
        self.assertGreater(request["due_date"], request["original_due_date"])

        # 重算也只认绑定的 v1：30 基础 + 20 延期，当前 due_date 不应被改写成 60 天版
        recalculated = self.service.recalculate_due_date(
            "sup1", "supervisor", request["id"], request["version"], "按受理时规则复核")
        self.assertEqual(request["due_date"], recalculated["due_date"])
        self.assertEqual(v1_due, recalculated["original_due_date"])

        # 新案件按 v2：延期 20 天超过新上限 15 天
        subject2 = self.service.create_subject("intake1", "intake", "SUB-002", "CN", False, "second@example.test")
        fresh_row = self.service.create_request("intake1", "intake", "PR-102", subject2["id"], "access", "IDEM-PR-102")["request"]
        fresh = self.start_processing(fresh_row)
        with self.assertRaises(DomainError) as ctx:
            self.service.extend_request("sup1", "supervisor", fresh["id"], 20, "试超上限", fresh["version"])
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("v2", str(ctx.exception))

    def test_draft_can_be_withdrawn_and_published_version_immutable(self):
        future = (self.clock.now + timedelta(days=5)).isoformat(timespec="seconds")
        draft = self.service.create_rule_draft("sup1", "supervisor", "CN", 45, 10, future, "试点调整")

        # 同一地区同时只能有一份未生效草案
        with self.assertRaises(DomainError) as ctx:
            self.service.create_rule_draft("sup1", "supervisor", "CN", 50, 10,
                                           (self.clock.now + timedelta(days=6)).isoformat(timespec="seconds"),
                                           "重复草案")
        self.assertEqual(409, ctx.exception.status)

        withdrawn = self.service.withdraw_rule_draft("sup1", "supervisor", draft["id"], "取消试点")
        self.assertEqual("withdrawn", withdrawn["status"])
        # 撤回后可以再建
        draft2 = self.service.create_rule_draft("sup1", "supervisor", "CN", 45, 10,
                                                (self.clock.now + timedelta(days=7)).isoformat(timespec="seconds"),
                                                "再次调整")
        # 已撤回的草案不能再撤回
        with self.assertRaises(DomainError) as ctx2:
            self.service.withdraw_rule_draft("sup1", "supervisor", draft["id"])
        self.assertEqual(409, ctx2.exception.status)
        self.clock.advance(days=8)
        # 发布后的版本不能撤回
        with self.assertRaises(DomainError) as ctx3:
            self.service.withdraw_rule_draft("sup1", "supervisor", draft2["id"])
        self.assertEqual(409, ctx3.exception.status)
        # 旧接口不能原地改已发布规则
        with self.assertRaises(DomainError) as ctx4:
            self.service.configure_jurisdiction("sup2", "supervisor", "CN", "中国", 90, 40, True, True)
        self.assertEqual(409, ctx4.exception.status)
        # 内容与当前生效版本一致时旧接口幂等
        same = self.service.configure_jurisdiction("sup1", "supervisor", "CN", "中国", 45, 10, True, True)
        self.assertEqual(3, same["version_no"])

    def test_new_region_requires_effective_rule_for_requests(self):
        subject = self.service.create_subject("intake1", "intake", "SUB-EU", "EU", False, "eu@example.test")
        future = (self.clock.now + timedelta(days=3)).isoformat(timespec="seconds")
        self.service.create_rule_draft("sup1", "supervisor", "EU", 25, 10, future,
                                       "新地区建规", name="欧盟")
        # 草案未生效，新案件不能受理
        with self.assertRaises(DomainError) as ctx:
            self.service.create_request("intake1", "intake", "PR-EU1", subject["id"], "access", "IDEM-EU1")
        self.assertEqual(409, ctx.exception.status)
        # 草案生效前旧配置接口也不能为该地区另建生效版本
        with self.assertRaises(DomainError) as ctx2:
            self.service.configure_jurisdiction("sup1", "supervisor", "EU", "欧盟", 25, 10, True, True)
        self.assertEqual(409, ctx2.exception.status)
        self.clock.advance(days=4)
        req = self.service.create_request("intake1", "intake", "PR-EU1", subject["id"], "access", "IDEM-EU1")["request"]
        req_detail = self.service.get_request("sup1", "supervisor", req["id"])
        self.assertEqual(1, req_detail["request"]["rule_version"]["version_no"])
        self.assertEqual("EU", req_detail["request"]["rule_version"]["code"])

    def test_detail_shows_bound_version_original_due_and_change_history(self):
        request = self.start_processing(self.make_request("PR-201"))
        self.service.extend_request("sup1", "supervisor", request["id"], 15, "取证", request["version"])
        self.service.create_rule_draft("sup1", "supervisor", "CN", 40, 20,
                                       (self.clock.now + timedelta(days=2)).isoformat(timespec="seconds"),
                                       "响应期延长至40天")
        self.clock.advance(days=3)
        detail = self.service.get_request("sup1", "supervisor", request["id"])
        bound = detail["request"]["rule_version"]
        self.assertEqual(1, bound["version_no"])
        self.assertNotEqual(detail["request"]["due_date"], detail["request"]["original_due_date"])
        versions = {r["version_no"]: r for r in detail["rule_changes"]}
        self.assertEqual("superseded", versions[1]["status"])
        self.assertEqual("effective", versions[2]["status"])
        self.assertEqual("响应期延长至40天", versions[2]["change_reason"])
        actions = {e["action"] for e in detail["timeline"]}
        self.assertIn("request.extended", actions)
        # 全局审计时间线包含规则生命周期事件
        state = self.service.state("sup1", "supervisor")
        rule_actions = {e["action"] for e in state["timeline"]}
        self.assertIn("jurisdiction_rule.draft_created", rule_actions)
        self.assertIn("jurisdiction_rule.activated", rule_actions)


if __name__ == "__main__":
    unittest.main()
