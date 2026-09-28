"""Personal data-rights request workflow service."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from collections.abc import Callable

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "privacy_requests.db"
REQUEST_TYPES = {"access", "correction", "deletion", "withdraw_consent", "restriction"}
OPEN_STATUSES = {"received", "verifying", "processing", "extended", "response_ready"}
FINAL_STATUSES = {"fulfilled", "rejected", "duplicate"}
RULE_DRAFT, RULE_ACTIVE, RULE_SUPERSEDED, RULE_WITHDRAWN = "draft", "active", "superseded", "withdrawn"


class DomainError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DomainError("日期格式无效") from exc
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def clean_actor(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor:
        raise DomainError("缺少操作人")
    return actor


def require_role(role: str, allowed: set[str], action: str) -> None:
    if role not in allowed:
        raise DomainError("角色无权执行：%s" % action, 403)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PrivacyRequestService:
    def __init__(self, db_path: str | os.PathLike[str] = DEFAULT_DB,
                 clock: Callable[[], datetime] | None = None):
        self.db_path = str(db_path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._init_schema()

    def now_dt(self) -> datetime:
        return self._clock().astimezone(timezone.utc)

    def now_str(self) -> str:
        return self.now_dt().isoformat(timespec="seconds")

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS jurisdictions (
                    code TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    response_days INTEGER NOT NULL,
                    max_extension_days INTEGER NOT NULL,
                    minor_guardian_required INTEGER NOT NULL,
                    agent_authority_required INTEGER NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jurisdiction_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL REFERENCES jurisdictions(code),
                    version_no INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    response_days INTEGER NOT NULL,
                    max_extension_days INTEGER NOT NULL,
                    minor_guardian_required INTEGER NOT NULL,
                    agent_authority_required INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    change_reason TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    effective_at TEXT NOT NULL,
                    published_at TEXT,
                    superseded_at TEXT,
                    withdrawn_at TEXT,
                    UNIQUE(code,version_no)
                );
                CREATE INDEX IF NOT EXISTS idx_jv_code_status ON jurisdiction_versions(code,status);
                CREATE INDEX IF NOT EXISTS idx_jv_effective ON jurisdiction_versions(status,effective_at);
                CREATE TABLE IF NOT EXISTS data_subjects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject_ref TEXT NOT NULL UNIQUE,
                    region TEXT NOT NULL,
                    is_minor INTEGER NOT NULL DEFAULT 0,
                    contact_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_no TEXT NOT NULL UNIQUE,
                    subject_id INTEGER NOT NULL REFERENCES data_subjects(id),
                    request_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'received',
                    jurisdiction TEXT NOT NULL REFERENCES jurisdictions(code),
                    requester_kind TEXT NOT NULL,
                    agent_authority_ref TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    duplicate_of INTEGER REFERENCES requests(id),
                    submitted_at TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    original_due_date TEXT NOT NULL,
                    extension_days INTEGER NOT NULL DEFAULT 0,
                    rule_version_id INTEGER REFERENCES jurisdiction_versions(id),
                    verified_at TEXT,
                    verified_by TEXT,
                    assigned_to TEXT,
                    denial_reason TEXT,
                    response_summary TEXT,
                    created_by TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS data_locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER NOT NULL REFERENCES requests(id),
                    system_name TEXT NOT NULL,
                    data_category TEXT NOT NULL,
                    owner_team TEXT NOT NULL,
                    contains_third_party INTEGER NOT NULL DEFAULT 0,
                    legal_hold INTEGER NOT NULL DEFAULT 0,
                    retention_exception INTEGER NOT NULL DEFAULT 0,
                    third_party_exception INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'located',
                    note TEXT NOT NULL DEFAULT '',
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(request_id,system_name,data_category)
                );
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER REFERENCES requests(id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_requests_due ON requests(status,due_date);
                CREATE INDEX IF NOT EXISTS idx_requests_subject ON requests(subject_id,request_type,submitted_at);
                """
            )
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(requests)").fetchall()}
            if "rule_version_id" not in cols:
                conn.execute("ALTER TABLE requests ADD COLUMN rule_version_id INTEGER REFERENCES jurisdiction_versions(id)")
            self._migrate_legacy_rules(conn)

    def _migrate_legacy_rules(self, conn: sqlite3.Connection) -> None:
        """旧库只有单行 jurisdictions：按行补一份 v1，并回填存量案件绑定。"""
        legacy = conn.execute("SELECT * FROM jurisdictions").fetchall()
        for row in legacy:
            exists = conn.execute(
                "SELECT 1 FROM jurisdiction_versions WHERE code=?", (row["code"],)
            ).fetchone()
            if not exists:
                conn.execute(
                    """INSERT INTO jurisdiction_versions(code,version_no,name,response_days,max_extension_days,
                       minor_guardian_required,agent_authority_required,status,change_reason,created_by,created_at,
                       effective_at,published_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (row["code"], 1, row["name"], row["response_days"], row["max_extension_days"],
                     row["minor_guardian_required"], row["agent_authority_required"], RULE_ACTIVE,
                     "历史规则迁移", row["updated_by"], row["updated_at"], row["updated_at"], row["updated_at"]),
                )
                version_id = conn.execute(
                    "SELECT id FROM jurisdiction_versions WHERE code=? AND version_no=1", (row["code"],)
                ).fetchone()["id"]
                conn.execute(
                    "UPDATE requests SET rule_version_id=? WHERE rule_version_id IS NULL AND jurisdiction=?",
                    (version_id, row["code"]),
                )

    def _promote_due_drafts(self, conn: sqlite3.Connection) -> int:
        """到生效时间的草案发布为当前版本；旧生效版本置为 superseded。返回发布条数。"""
        now = self.now_str()
        drafts = conn.execute(
            "SELECT * FROM jurisdiction_versions WHERE status=? AND effective_at<=? ORDER BY effective_at,id",
            (RULE_DRAFT, now),
        ).fetchall()
        promoted = 0
        for draft in drafts:
            cur = conn.execute(
                "UPDATE jurisdiction_versions SET status=?,published_at=? WHERE id=? AND status=?",
                (RULE_ACTIVE, now, draft["id"], RULE_DRAFT),
            )
            if cur.rowcount == 0:
                continue
            conn.execute(
                "UPDATE jurisdiction_versions SET status=?,superseded_at=? WHERE code=? AND status=? AND id<>?",
                (RULE_SUPERSEDED, now, draft["code"], RULE_ACTIVE, draft["id"]),
            )
            conn.execute(
                """UPDATE jurisdictions SET name=?,response_days=?,max_extension_days=?,
                   minor_guardian_required=?,agent_authority_required=?,updated_by=?,updated_at=? WHERE code=?""",
                (draft["name"], draft["response_days"], draft["max_extension_days"],
                 draft["minor_guardian_required"], draft["agent_authority_required"],
                 draft["created_by"], now, draft["code"]),
            )
            self._audit(conn, None, draft["created_by"], "jurisdiction.rule_activated", {
                "code": draft["code"], "version_no": draft["version_no"], "effective_at": draft["effective_at"],
            })
            promoted += 1
        return promoted

    def _audit(self, conn: sqlite3.Connection, request_id: int | None, actor: str,
               action: str, details: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO timeline(request_id,actor,action,details,created_at) VALUES(?,?,?,?,?)",
            (request_id, actor, action, json.dumps(details, ensure_ascii=False, sort_keys=True), self.now_str()),
        )

    def _validate_rule_params(self, response_days: int, max_extension_days: int,
                              code: str, name: str) -> tuple[int, int]:
        code = (code or "").strip().upper()
        name = (name or "").strip()
        try:
            response_days, max_extension_days = int(response_days), int(max_extension_days)
        except (TypeError, ValueError) as exc:
            raise DomainError("时限必须是整数") from exc
        if not code or not name or not 1 <= response_days <= 180 or not 0 <= max_extension_days <= 180:
            raise DomainError("地区规则参数无效")
        return response_days, max_extension_days

    def _active_rule(self, conn: sqlite3.Connection, code: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM jurisdiction_versions WHERE code=? AND status=? ORDER BY version_no DESC LIMIT 1",
            (code, RULE_ACTIVE),
        ).fetchone()

    def _rule_or_404(self, conn: sqlite3.Connection, version_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM jurisdiction_versions WHERE id=?", (version_id,)).fetchone()
        if not row:
            raise DomainError("地区规则版本不存在", 404)
        return row

    def jurisdiction_history(self, actor: str = "", role: str = "viewer",
                             code: str | None = None) -> list[dict[str, Any]]:
        """规则版本属于可公开查阅的配置，任何角色可读；变更操作另限主管。"""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            sql = "SELECT * FROM jurisdiction_versions"
            params: tuple[Any, ...] = ()
            if code:
                sql += " WHERE code=?"
                params = (code.strip().upper(),)
            sql += " ORDER BY code,version_no"
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def configure_jurisdiction(self, actor: str, role: str, code: str, name: str,
                               response_days: int, max_extension_days: int,
                               minor_guardian_required: bool = True,
                               agent_authority_required: bool = True,
                               change_reason: str | None = None,
                               effective_at: str | None = None) -> dict[str, Any]:
        """建立或修订地区规则。

        首次配置生成 v1 并立即生效；此后一律先生成草案（必须指定未来生效时间和
        补正原因），到点后才用于新案件。已发布的版本不再原地修改。
        """
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "配置地区规则")
        code = code.strip().upper()
        name = name.strip()
        response_days, max_extension_days = self._validate_rule_params(response_days, max_extension_days, code, name)
        change_reason = (change_reason or "").strip()
        now_dt = self.now_dt()
        now = now_dt.isoformat(timespec="seconds")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            latest = conn.execute(
                "SELECT * FROM jurisdiction_versions WHERE code=? ORDER BY version_no DESC LIMIT 1",
                (code,),
            ).fetchone()
            if latest is None:
                if effective_at:
                    eff_dt = parse_time(effective_at)
                    status, published_at, eff_str = (RULE_DRAFT, None, eff_dt.isoformat(timespec="seconds"))
                    if not change_reason:
                        raise DomainError("预约生效的规则草案必须填写补正原因")
                else:
                    status, published_at, eff_str = RULE_ACTIVE, now, now
                conn.execute(
                    "INSERT INTO jurisdictions(code,name,response_days,max_extension_days,minor_guardian_required,agent_authority_required,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (code, name, response_days, max_extension_days, int(bool(minor_guardian_required)),
                     int(bool(agent_authority_required)), actor, now),
                )
                cur = conn.execute(
                    """INSERT INTO jurisdiction_versions(code,version_no,name,response_days,max_extension_days,
                       minor_guardian_required,agent_authority_required,status,change_reason,created_by,created_at,
                       effective_at,published_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (code, 1, name, response_days, max_extension_days,
                     int(bool(minor_guardian_required)), int(bool(agent_authority_required)),
                     status, change_reason, actor, now, eff_str, published_at),
                )
                self._audit(conn, None, actor, "jurisdiction.rule_created",
                            {"code": code, "version_no": 1, "status": status, "effective_at": eff_str})
                return dict(self._rule_or_404(conn, cur.lastrowid))

            pending = conn.execute(
                "SELECT * FROM jurisdiction_versions WHERE code=? AND status=?", (code, RULE_DRAFT)
            ).fetchone()
            if pending:
                raise DomainError("该地区已有未生效草案，请先撤回或等待生效后再补正", 409)
            if not effective_at:
                raise DomainError("规则已发布，补正必须指定生效时间并生成新版本，不能原地修改", 409)
            if not change_reason:
                raise DomainError("补正地区规则必须填写原因")
            eff_dt = parse_time(effective_at)
            if eff_dt <= now_dt:
                raise DomainError("新版本生效时间必须晚于当前时间，修订须先存草案", 409)
            version_no = latest["version_no"] + 1
            eff_str = eff_dt.isoformat(timespec="seconds")
            cur = conn.execute(
                """INSERT INTO jurisdiction_versions(code,version_no,name,response_days,max_extension_days,
                   minor_guardian_required,agent_authority_required,status,change_reason,created_by,created_at,
                   effective_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (code, version_no, name, response_days, max_extension_days,
                 int(bool(minor_guardian_required)), int(bool(agent_authority_required)),
                 RULE_DRAFT, change_reason, actor, now, eff_str),
            )
            self._audit(conn, None, actor, "jurisdiction.rule_drafted",
                        {"code": code, "version_no": version_no, "effective_at": eff_str, "reason": change_reason})
            return dict(self._rule_or_404(conn, cur.lastrowid))

    def withdraw_rule_draft(self, actor: str, role: str, version_id: int,
                            reason: str | None = None) -> dict[str, Any]:
        """撤回尚未生效的规则草案。已发布版本不能撤回或修改。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "撤回规则草案")
        reason = (reason or "").strip()
        if not reason:
            raise DomainError("撤回原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            draft = self._rule_or_404(conn, version_id)
            if draft["status"] != RULE_DRAFT:
                raise DomainError("只有未生效草案可以撤回，已发布规则不可撤回", 409)
            conn.execute(
                "UPDATE jurisdiction_versions SET status=?,withdrawn_at=? WHERE id=? AND status=?",
                (RULE_WITHDRAWN, self.now_str(), version_id, RULE_DRAFT),
            )
            self._audit(conn, None, actor, "jurisdiction.rule_withdrawn",
                        {"code": draft["code"], "version_no": draft["version_no"], "reason": reason})
            return dict(self._rule_or_404(conn, version_id))

    def create_subject(self, actor: str, role: str, subject_ref: str, region: str,
                       is_minor: bool, contact: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"intake", "privacy_officer"}, "建立数据主体索引")
        if not subject_ref.strip() or not region.strip() or not contact.strip():
            raise DomainError("主体编号、地区和联系方式不能为空")
        with self.connect() as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO data_subjects(subject_ref,region,is_minor,contact_hash,created_at) VALUES(?,?,?,?,?)",
                    (subject_ref.strip(), region.strip().upper(), int(bool(is_minor)), sha256_text(contact.strip().lower()), self.now_str()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("数据主体索引已存在", 409) from exc
            self._audit(conn, None, actor, "subject.created", {"subject_ref": subject_ref.strip()})
            return dict(conn.execute("SELECT id,subject_ref,region,is_minor,created_at FROM data_subjects WHERE id=?", (cur.lastrowid,)).fetchone())

    def create_request(self, actor: str, role: str, request_no: str, subject_id: int,
                       request_type: str, idempotency_key: str, requester_kind: str = "self",
                       agent_authority_ref: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"intake", "privacy_officer"}, "创建权利请求")
        request_type = request_type.strip().lower()
        requester_kind = requester_kind.strip().lower()
        if request_type not in REQUEST_TYPES or requester_kind not in {"self", "guardian", "authorized_agent"}:
            raise DomainError("请求类型或申请人类型无效")
        if not request_no.strip() or not idempotency_key.strip():
            raise DomainError("请求编号和幂等键不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            existing = conn.execute("SELECT * FROM requests WHERE idempotency_key=?", (idempotency_key.strip(),)).fetchone()
            if existing:
                return {"idempotent": True, "request": dict(existing)}
            subject = conn.execute("SELECT * FROM data_subjects WHERE id=?", (subject_id,)).fetchone()
            if not subject:
                raise DomainError("数据主体不存在", 404)
            rule = self._active_rule(conn, subject["region"])
            if not rule:
                raise DomainError("数据主体所在地区尚无已生效的处理规则", 409)
            if subject["is_minor"] and rule["minor_guardian_required"] and requester_kind != "guardian":
                raise DomainError("未成年人请求必须由监护人提出", 403)
            if requester_kind == "authorized_agent" and rule["agent_authority_required"] and not (agent_authority_ref or "").strip():
                raise DomainError("授权代理必须提供有效授权引用", 403)
            now_dt = self.now_dt()
            duplicate = conn.execute(
                """SELECT * FROM requests WHERE subject_id=? AND request_type=? AND status IN ('received','verifying','processing','extended','response_ready')
                   ORDER BY id DESC LIMIT 1""",
                (subject_id, request_type),
            ).fetchone()
            duplicate_of = None
            if duplicate:
                elapsed = (now_dt - parse_time(duplicate["submitted_at"])).total_seconds()
                if 0 <= elapsed <= 30 * 86400:
                    duplicate_of = duplicate["id"]
            now = now_dt.isoformat(timespec="seconds")
            due = (now_dt + timedelta(days=rule["response_days"])).isoformat(timespec="seconds")
            status = "duplicate" if duplicate_of else "received"
            try:
                cur = conn.execute(
                    """INSERT INTO requests(request_no,subject_id,request_type,status,jurisdiction,requester_kind,agent_authority_ref,
                       idempotency_key,duplicate_of,submitted_at,due_date,original_due_date,rule_version_id,created_by,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (request_no.strip(), subject_id, request_type, status, subject["region"], requester_kind,
                     (agent_authority_ref or "").strip() or None, idempotency_key.strip(), duplicate_of,
                     now, due, due, rule["id"], actor, now),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("请求编号已存在", 409) from exc
            request_id = cur.lastrowid
            self._audit(conn, request_id, actor, "request.created", {
                "type": request_type, "duplicate_of": duplicate_of,
                "rule_version_id": rule["id"], "rule_version_no": rule["version_no"],
                "rule_effective_at": rule["effective_at"],
            })
            if duplicate_of:
                self._audit(conn, duplicate_of, actor, "request.duplicate_detected", {"new_request": request_no.strip()})
            return {"idempotent": False, "request": dict(conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone())}

    def _request(self, conn: sqlite3.Connection, request_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            raise DomainError("权利请求不存在", 404)
        return row

    def verify_identity(self, actor: str, role: str, request_id: int, expected_version: int,
                        identity_evidence_ref: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "核验身份")
        if not identity_evidence_ref.strip():
            raise DomainError("身份核验引用不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] != "received":
                raise DomainError("当前请求不能核验身份", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute(
                "UPDATE requests SET status='processing',verified_at=?,verified_by=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (self.now_str(), actor, self.now_str(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "identity.verified", {"evidence_ref": identity_evidence_ref.strip()})
            return dict(self._request(conn, request_id))

    def assign_request(self, actor: str, role: str, request_id: int, assignee: str,
                       expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "分配请求")
        if not assignee.strip():
            raise DomainError("处理人不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("当前请求不能分配", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute("UPDATE requests SET assigned_to=?,version=version+1,updated_at=? WHERE id=? AND version=?", (assignee.strip(), self.now_str(), request_id, expected_version))
            self._audit(conn, request_id, actor, "request.assigned", {"assignee": assignee.strip()})
            return dict(self._request(conn, request_id))

    def _can_process(self, actor: str, role: str, req: sqlite3.Row, action: str) -> None:
        if role == "supervisor":
            return
        if role == "privacy_officer" and req["assigned_to"] == actor:
            return
        raise DomainError("只有被指派的隐私处理人员可以%s" % action, 403)

    def add_data_location(self, actor: str, role: str, request_id: int, system_name: str,
                          data_category: str, owner_team: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "定位数据")
        if not system_name.strip() or not data_category.strip() or not owner_team.strip():
            raise DomainError("系统、数据类别和负责团队不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("请求当前不能定位数据", 409)
            self._can_process(actor, role, req, "定位数据")
            try:
                cur = conn.execute(
                    """INSERT INTO data_locations(request_id,system_name,data_category,owner_team,created_at,updated_at)
                       VALUES(?,?,?,?,?,?)""",
                    (request_id, system_name.strip(), data_category.strip(), owner_team.strip(), self.now_str(), self.now_str()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("同一系统的数据类别已经登记", 409) from exc
            self._audit(conn, request_id, actor, "location.added", {"system": system_name.strip(), "category": data_category.strip()})
            return dict(conn.execute("SELECT * FROM data_locations WHERE id=?", (cur.lastrowid,)).fetchone())

    def classify_location(self, actor: str, role: str, location_id: int,
                          contains_third_party: bool, legal_hold: bool,
                          retention_exception: bool, note: str = "",
                          third_party_exception: bool = False) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "分类数据位置")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM data_locations WHERE id=?", (location_id,)).fetchone()
            if not row:
                raise DomainError("数据位置不存在", 404)
            req = self._request(conn, row["request_id"])
            self._can_process(actor, role, req, "分类数据位置")
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("请求当前不能分类数据", 409)
            if row["status"] != "located":
                raise DomainError("数据位置已经分类", 409)
            if third_party_exception and not contains_third_party:
                raise DomainError("不存在第三方数据时不能使用第三方例外", 409)
            if req["request_type"] == "deletion" and (legal_hold or retention_exception):
                status = "blocked"
            elif req["request_type"] == "access" and contains_third_party and not (third_party_exception or note.strip()):
                status = "needs_redaction"
            else:
                status = "classified"
            conn.execute(
                """UPDATE data_locations SET contains_third_party=?,legal_hold=?,retention_exception=?,third_party_exception=?,status=?,note=?,version=version+1,updated_at=?
                   WHERE id=? AND status='located'""",
                (int(bool(contains_third_party)), int(bool(legal_hold)), int(bool(retention_exception)),
                 int(bool(third_party_exception)), status, note.strip(), self.now_str(), location_id),
            )
            self._audit(conn, row["request_id"], actor, "location.classified", {"location_id": location_id, "status": status})
            return dict(conn.execute("SELECT * FROM data_locations WHERE id=?", (location_id,)).fetchone())

    def extend_request(self, actor: str, role: str, request_id: int, days: int,
                       reason: str, expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "延期处理")
        if not reason.strip():
            raise DomainError("延期原因不能为空")
        try:
            days = int(days)
        except (TypeError, ValueError) as exc:
            raise DomainError("延期天数必须是整数") from exc
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            req = self._request(conn, request_id)
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("当前请求不能延期", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            rule = self._bound_rule(conn, req)
            if req["extension_days"] > 0:
                raise DomainError("每个请求只能延期一次", 409)
            if days <= 0 or days > rule["max_extension_days"]:
                raise DomainError("延期天数超出受理时地区规则上限（v%s 上限 %s 天）"
                                  % (rule["version_no"], rule["max_extension_days"]), 409)
            due = (parse_time(req["due_date"]) + timedelta(days=days)).isoformat(timespec="seconds")
            conn.execute(
                "UPDATE requests SET status='extended',due_date=?,extension_days=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (due, days, self.now_str(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "request.extended", {
                "days": days, "reason": reason.strip(), "due_date": due,
                "rule_version_id": rule["id"], "rule_version_no": rule["version_no"],
                "max_extension_days": rule["max_extension_days"],
            })
            return dict(self._request(conn, request_id))

    def _bound_rule(self, conn: sqlite3.Connection, req: sqlite3.Row) -> sqlite3.Row:
        """案件始终按受理时绑定的规则版本判断；缺失时兜底到该地区最早版本。"""
        if req["rule_version_id"]:
            rule = conn.execute(
                "SELECT * FROM jurisdiction_versions WHERE id=?", (req["rule_version_id"],)
            ).fetchone()
            if rule:
                return rule
        rule = conn.execute(
            "SELECT * FROM jurisdiction_versions WHERE code=? ORDER BY version_no LIMIT 1",
            (req["jurisdiction"],),
        ).fetchone()
        if not rule:
            raise DomainError("案件受理时的地区规则版本缺失，无法判断时限", 409)
        return rule

    def recalculate_deadline(self, actor: str, role: str, request_id: int,
                             expected_version: int, reason: str | None = None) -> dict[str, Any]:
        """按案件绑定版本重算到期日。已延期保留延期天数；重算不改变原到期日。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "重算到期日")
        reason = (reason or "").strip()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            req = self._request(conn, request_id)
            if req["status"] not in OPEN_STATUSES:
                raise DomainError("已结案请求不能重算到期日", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            rule = self._bound_rule(conn, req)
            base = parse_time(req["original_due_date"])
            due = base + timedelta(days=req["extension_days"])
            due_str = due.isoformat(timespec="seconds")
            conn.execute(
                "UPDATE requests SET due_date=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (due_str, self.now_str(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "deadline.recalculated", {
                "reason": reason, "due_date": due_str,
                "original_due_date": req["original_due_date"],
                "extension_days": req["extension_days"],
                "rule_version_id": rule["id"], "rule_version_no": rule["version_no"],
                "response_days": rule["response_days"],
            })
            return dict(self._request(conn, request_id))

    def prepare_response(self, actor: str, role: str, request_id: int,
                         expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "准备回复")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "准备回复")
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("当前请求不能准备回复", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            locations = conn.execute("SELECT * FROM data_locations WHERE request_id=?", (request_id,)).fetchall()
            if not locations:
                raise DomainError("尚未登记任何数据位置，不能回复", 409)
            unresolved = [row["id"] for row in locations if row["status"] in {"located", "needs_redaction"}]
            if unresolved:
                raise DomainError("仍有数据位置未分类或未完成去标识", 409)
            if req["request_type"] == "deletion":
                blocked = [row["id"] for row in locations if row["status"] == "blocked" or row["legal_hold"] or row["retention_exception"]]
                if blocked:
                    raise DomainError("存在法律保留或保存义务，不能执行删除", 409)
            if req["request_type"] == "access":
                bad = [row["id"] for row in locations if row["contains_third_party"] and not row["third_party_exception"] and not row["note"].strip()]
                if bad:
                    raise DomainError("第三方数据尚未完成去标识或例外说明", 409)
            conn.execute("UPDATE requests SET status='response_ready',version=version+1,updated_at=? WHERE id=? AND version=?", (self.now_str(), request_id, expected_version))
            self._audit(conn, request_id, actor, "response.prepared", {"location_count": len(locations)})
            return dict(self._request(conn, request_id))

    def fulfill_request(self, actor: str, role: str, request_id: int, response_summary: str,
                        expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "完成请求")
        if not response_summary.strip():
            raise DomainError("回复摘要不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "完成请求")
            if req["status"] != "response_ready":
                raise DomainError("请求尚未完成回复准备", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute(
                "UPDATE requests SET status='fulfilled',response_summary=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (response_summary.strip(), self.now_str(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "request.fulfilled", {"summary": response_summary.strip()})
            return dict(self._request(conn, request_id))

    def reject_request(self, actor: str, role: str, request_id: int, reason: str,
                       expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "拒绝请求")
        if not reason.strip():
            raise DomainError("拒绝理由不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "拒绝请求")
            if req["status"] not in OPEN_STATUSES:
                raise DomainError("当前请求不能拒绝", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute("UPDATE requests SET status='rejected',denial_reason=?,version=version+1,updated_at=? WHERE id=? AND version=?", (reason.strip(), self.now_str(), request_id, expected_version))
            self._audit(conn, request_id, actor, "request.rejected", {"reason": reason.strip()})
            return dict(self._request(conn, request_id))

    def _visibility(self, actor: str, role: str, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        if role in {"supervisor", "auditor"}:
            return conn.execute("SELECT * FROM requests ORDER BY due_date,id").fetchall()
        if role == "privacy_officer":
            return conn.execute("SELECT * FROM requests WHERE assigned_to=? ORDER BY due_date,id", (actor,)).fetchall()
        if role == "intake":
            return conn.execute("SELECT * FROM requests WHERE created_by=? ORDER BY id DESC", (actor,)).fetchall()
        return []

    def _decorate_rule(self, conn: sqlite3.Connection, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not items:
            return items
        ids = {it.get("rule_version_id") for it in items if it.get("rule_version_id")}
        rules: dict[int, sqlite3.Row] = {}
        if ids:
            placeholders = ",".join("?" * len(ids))
            rules = {r["id"]: r for r in conn.execute(
                "SELECT * FROM jurisdiction_versions WHERE id IN (%s)" % placeholders, tuple(ids)
            ).fetchall()}
        for it in items:
            rv = rules.get(it.get("rule_version_id"))
            if rv is None:
                rv = conn.execute(
                    "SELECT * FROM jurisdiction_versions WHERE code=? ORDER BY version_no LIMIT 1",
                    (it["jurisdiction"],),
                ).fetchone()
            it["rule_version_no"] = rv["version_no"] if rv else None
            it["rule_status"] = rv["status"] if rv else None
            it["rule_effective_at"] = rv["effective_at"] if rv else None
        return items

    def get_request(self, actor: str, role: str, request_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            req = self._request(conn, request_id)
            if role in {"supervisor", "auditor"}:
                pass
            elif role == "privacy_officer" and req["assigned_to"] == actor:
                pass
            elif role == "intake" and req["created_by"] == actor:
                pass
            else:
                raise DomainError("无权查看该权利请求", 403)
            rule = self._bound_rule(conn, req)
            locations = [dict(r) for r in conn.execute("SELECT * FROM data_locations WHERE request_id=? ORDER BY id", (request_id,)).fetchall()]
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline WHERE request_id=? ORDER BY id", (request_id,)).fetchall()]
            rule_changes = [dict(r) for r in conn.execute(
                "SELECT * FROM jurisdiction_versions WHERE code=? ORDER BY version_no", (req["jurisdiction"],)
            ).fetchall()]
            request_view = self._decorate_rule(conn, [dict(req)])[0]
            return {
                "request": request_view,
                "rule_version": dict(rule),
                "rule_changes": rule_changes,
                "locations": locations,
                "timeline": timeline,
            }

    def queue(self, actor: str, role: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            rows = self._visibility(actor, role, conn)
            now = self.now_dt()
            result = self._decorate_rule(conn, [dict(r) for r in rows])
        for item in result:
            item["overdue"] = parse_time(item["due_date"]) < now and item["status"] in OPEN_STATUSES
        return result

    def state(self, actor: str = "", role: str = "viewer") -> dict[str, Any]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_drafts(conn)
            rows = self._visibility(actor, role, conn)
            requests = self._decorate_rule(conn, [dict(r) for r in rows])
            now = self.now_dt()
            locations = []
            for item in requests:
                item["overdue"] = parse_time(item["due_date"]) < now and item["status"] in OPEN_STATUSES
                locations.extend(dict(r) for r in conn.execute("SELECT * FROM data_locations WHERE request_id=? ORDER BY id", (item["id"],)).fetchall())
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline ORDER BY id DESC LIMIT 300").fetchall()]
            rule_versions = [dict(r) for r in conn.execute(
                "SELECT * FROM jurisdiction_versions ORDER BY code,version_no"
            ).fetchall()]
            jurisdictions = [dict(r) for r in conn.execute(
                "SELECT * FROM jurisdiction_versions WHERE status=? ORDER BY code", (RULE_ACTIVE,)
            ).fetchall()]
        return {"requests": requests, "locations": locations, "timeline": timeline,
                "jurisdictions": jurisdictions, "rule_versions": rule_versions,
                "access_limited": not bool(requests)}

    def seed_demo(self) -> dict[str, Any]:
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) AS c FROM requests").fetchone()["c"]:
                return {"seeded": False, "reason": "已有数据"}
        self.configure_jurisdiction("sup-demo", "supervisor", "CN", "中国", 30, 30, True, True)
        subject = self.create_subject("intake-demo", "intake", "SUBJ-DEMO-001", "CN", False, "demo@example.test")
        req = self.create_request("intake-demo", "intake", "PR-DEMO-001", subject["id"], "access", "demo-idem-001")
        return {"seeded": True, "request_id": req["request"]["id"], "subject_id": subject["id"]}


class ApiHandler(BaseHTTPRequestHandler):
    service: PrivacyRequestService

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _headers(self) -> tuple[str, str]:
        return self.headers.get("X-User", ""), self.headers.get("X-Role", "viewer")

    def _json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise DomainError("请求体过大", 413)
        if not length:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DomainError("请求体不是有效 JSON") from exc
        if not isinstance(value, dict):
            raise DomainError("JSON 请求体必须是对象")
        return value

    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path in {"/", "/index.html"}:
                body = (ROOT / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            actor, role = self._headers()
            if path == "/health":
                self._send(200, {"status": "ok", "service": "privacy-requests"})
            elif path == "/api/state":
                self._send(200, self.service.state(actor, role))
            elif path == "/api/queue":
                self._send(200, {"queue": self.service.queue(actor, role)})
            elif path == "/api/jurisdictions":
                query = parse_qs(urlparse(self.path).query)
                code = query.get("code", [None])[0]
                self._send(200, {"versions": self.service.jurisdiction_history(actor, role, code)})
            elif path.startswith("/api/requests/"):
                self._send(200, self.service.get_request(actor, role, int(path.split("/")[3])))
            else:
                self._send(404, {"error": "接口不存在"})
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (ValueError, IndexError) as exc:
            self._send(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            path, data, (actor, role) = urlparse(self.path).path, self._json(), self._headers()
            if path == "/api/jurisdictions":
                result = self.service.configure_jurisdiction(actor, role, **data)
            elif path == "/api/subjects":
                result = self.service.create_subject(actor, role, **data)
            elif path == "/api/requests":
                result = self.service.create_request(actor, role, **data)
            elif path == "/api/requests/verify":
                result = self.service.verify_identity(actor, role, **data)
            elif path == "/api/requests/assign":
                result = self.service.assign_request(actor, role, **data)
            elif path == "/api/locations":
                result = self.service.add_data_location(actor, role, **data)
            elif path == "/api/locations/classify":
                result = self.service.classify_location(actor, role, **data)
            elif path == "/api/requests/extend":
                result = self.service.extend_request(actor, role, **data)
            elif path == "/api/requests/recalculate":
                result = self.service.recalculate_deadline(actor, role, **data)
            elif path == "/api/jurisdictions/withdraw":
                result = self.service.withdraw_rule_draft(actor, role, **data)
            elif path == "/api/requests/prepare":
                result = self.service.prepare_response(actor, role, **data)
            elif path == "/api/requests/fulfill":
                result = self.service.fulfill_request(actor, role, **data)
            elif path == "/api/requests/reject":
                result = self.service.reject_request(actor, role, **data)
            else:
                raise DomainError("接口不存在", 404)
            self._send(201, result)
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (KeyError, TypeError, ValueError) as exc:
            self._send(400, {"error": "请求参数错误: %s" % exc})
        except Exception as exc:
            self._send(500, {"error": "服务器内部错误", "detail": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def serve(service: PrivacyRequestService, host: str, port: int) -> None:
    ApiHandler.service = service
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print("Privacy request service listening on http://%s:%s" % (host, port))
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="个人数据权利请求处理服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8210)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    service = PrivacyRequestService(args.db)
    if args.init:
        print(json.dumps(service.seed_demo() if args.seed else {"initialized": True, "db": args.db}, ensure_ascii=False))
        return
    serve(service, args.host, args.port)


if __name__ == "__main__":
    main()
