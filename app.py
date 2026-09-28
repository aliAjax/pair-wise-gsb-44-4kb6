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
from collections.abc import Callable
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "privacy_requests.db"
REQUEST_TYPES = {"access", "correction", "deletion", "withdraw_consent", "restriction"}
OPEN_STATUSES = {"received", "verifying", "processing", "extended", "response_ready"}
FINAL_STATUSES = {"fulfilled", "rejected", "duplicate"}


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

    def now(self) -> datetime:
        return self._clock().astimezone(timezone.utc)

    def now_text(self) -> str:
        return self.now().isoformat(timespec="seconds")

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
                    name TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jurisdiction_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL REFERENCES jurisdictions(code),
                    version_no INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'draft',
                    response_days INTEGER NOT NULL,
                    max_extension_days INTEGER NOT NULL,
                    minor_guardian_required INTEGER NOT NULL,
                    agent_authority_required INTEGER NOT NULL,
                    change_reason TEXT NOT NULL DEFAULT '',
                    effective_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    published_at TEXT,
                    superseded_at TEXT,
                    withdrawn_by TEXT,
                    withdrawn_at TEXT,
                    withdraw_reason TEXT NOT NULL DEFAULT '',
                    UNIQUE(code,version_no)
                );
                CREATE INDEX IF NOT EXISTS idx_jv_code_status ON jurisdiction_versions(code,status);
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
                    rule_version_id INTEGER REFERENCES jurisdiction_versions(id),
                    requester_kind TEXT NOT NULL,
                    agent_authority_ref TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    duplicate_of INTEGER REFERENCES requests(id),
                    submitted_at TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    original_due_date TEXT NOT NULL,
                    extension_days INTEGER NOT NULL DEFAULT 0,
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
        self._migrate_legacy()

    def _migrate_legacy(self) -> None:
        conn = self.connect()
        # RENAME 父表时 SQLite 默认会改写子表外键引用，迁移期间关闭该行为并停止强制外键
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("PRAGMA legacy_alter_table=ON")
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(jurisdictions)").fetchall()}
        if {"response_days", "max_extension_days", "updated_by"} & cols:
            rows = conn.execute("SELECT * FROM jurisdictions").fetchall()
            conn.execute("ALTER TABLE jurisdictions RENAME TO jurisdictions_legacy")
            conn.execute("CREATE TABLE jurisdictions (code TEXT PRIMARY KEY, name TEXT NOT NULL)")
            conn.executemany("INSERT INTO jurisdictions(code,name) VALUES(?,?)",
                             [(r["code"], r["name"]) for r in rows])
            for r in rows:
                conn.execute(
                    """INSERT INTO jurisdiction_versions(code,version_no,status,response_days,max_extension_days,
                       minor_guardian_required,agent_authority_required,change_reason,effective_at,created_by,created_at,published_at)
                       VALUES(?,1,'effective',?,?,?,?,'历史配置迁移','1970-01-01T00:00:00+00:00',?,?,?)""",
                    (r["code"], r["response_days"], r["max_extension_days"], r["minor_guardian_required"],
                     r["agent_authority_required"], r["updated_by"], r["updated_at"], r["updated_at"]),
                )
            conn.execute("DROP TABLE jurisdictions_legacy")
        req_cols = {r["name"] for r in conn.execute("PRAGMA table_info(requests)").fetchall()}
        if "rule_version_id" not in req_cols:
            conn.execute("ALTER TABLE requests ADD COLUMN rule_version_id INTEGER REFERENCES jurisdiction_versions(id)")
            conn.execute(
                """UPDATE requests SET rule_version_id=(
                       SELECT jv.id FROM jurisdiction_versions jv
                       WHERE jv.code=requests.jurisdiction AND jv.status='effective'
                       ORDER BY jv.version_no DESC LIMIT 1)"""
            )
        conn.commit()
        conn.close()

    def _audit(self, conn: sqlite3.Connection, request_id: int | None, actor: str,
               action: str, details: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO timeline(request_id,actor,action,details,created_at) VALUES(?,?,?,?,?)",
            (request_id, actor, action, json.dumps(details, ensure_ascii=False, sort_keys=True), self.now_text()),
        )

    @staticmethod
    def _validate_rule_params(response_days: int, max_extension_days: int) -> tuple[int, int]:
        try:
            response_days, max_extension_days = int(response_days), int(max_extension_days)
        except (TypeError, ValueError) as exc:
            raise DomainError("时限必须是整数") from exc
        if not 1 <= response_days <= 180 or not 0 <= max_extension_days <= 180:
            raise DomainError("地区规则参数无效")
        return response_days, max_extension_days

    def _activate_due_drafts(self, conn: sqlite3.Connection, at: datetime | None = None) -> list[sqlite3.Row]:
        """到生效时间的草案自动发布；旧生效版本自动标记为被取代。必须在事务内调用。"""
        now = at or self.now()
        activated: list[sqlite3.Row] = []
        due = conn.execute(
            "SELECT * FROM jurisdiction_versions WHERE status='draft' AND effective_at IS NOT NULL AND effective_at<=? ORDER BY effective_at,id",
            (now.isoformat(timespec="seconds"),),
        ).fetchall()
        for draft in due:
            conn.execute(
                "UPDATE jurisdiction_versions SET status='superseded',superseded_at=? WHERE code=? AND status='effective'",
                (draft["effective_at"], draft["code"]),
            )
            conn.execute(
                "UPDATE jurisdiction_versions SET status='effective',published_at=? WHERE id=? AND status='draft'",
                (draft["effective_at"], draft["id"]),
            )
            self._audit(conn, None, draft["created_by"], "jurisdiction_rule.activated",
                        {"code": draft["code"], "version_no": draft["version_no"], "effective_at": draft["effective_at"]})
            activated.append(conn.execute("SELECT * FROM jurisdiction_versions WHERE id=?", (draft["id"],)).fetchone())
        return activated

    def _effective_rule(self, conn: sqlite3.Connection, code: str, at: datetime | None = None) -> sqlite3.Row | None:
        self._activate_due_drafts(conn, at)
        moment = (at or self.now()).isoformat(timespec="seconds")
        return conn.execute(
            "SELECT * FROM jurisdiction_versions WHERE code=? AND status='effective' AND effective_at<=? ORDER BY version_no DESC,id DESC LIMIT 1",
            (code, moment),
        ).fetchone()

    def _rule_row(self, conn: sqlite3.Connection, version_id: int) -> sqlite3.Row:
        row = conn.execute(
            """SELECT jv.*, j.name AS jurisdiction_name FROM jurisdiction_versions jv
               JOIN jurisdictions j ON j.code=jv.code WHERE jv.id=?""",
            (version_id,),
        ).fetchone()
        if not row:
            raise DomainError("规则版本不存在", 404)
        return row

    @staticmethod
    def _rule_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["minor_guardian_required"] = bool(data["minor_guardian_required"])
        data["agent_authority_required"] = bool(data["agent_authority_required"])
        return data

    def configure_jurisdiction(self, actor: str, role: str, code: str, name: str,
                               response_days: int, max_extension_days: int,
                               minor_guardian_required: bool = True,
                               agent_authority_required: bool = True) -> dict[str, Any]:
        """兼容旧接口：首次配置立即生效；内容未变时幂等返回；内容变更必须走带原因的新版本。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "配置地区规则")
        code, name = code.strip().upper(), name.strip()
        response_days, max_extension_days = self._validate_rule_params(response_days, max_extension_days)
        if not code or not name:
            raise DomainError("地区代码和名称不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = self._effective_rule(conn, code)
            pending = conn.execute(
                "SELECT id FROM jurisdiction_versions WHERE code=? AND status='draft'", (code,)
            ).fetchone()
            if current is None and pending:
                raise DomainError("该地区已有未生效草案，请先撤回或等待其生效", 409)
            if current is None:
                conn.execute("INSERT OR IGNORE INTO jurisdictions(code,name) VALUES(?,?)", (code, name))
                now = self.now_text()
                cur = conn.execute(
                    """INSERT INTO jurisdiction_versions(code,version_no,status,response_days,max_extension_days,
                       minor_guardian_required,agent_authority_required,change_reason,effective_at,created_by,created_at,published_at)
                       VALUES(?,1,'effective',?,?,?,?,'首次建立地区规则',?,?,?,?)""",
                    (code, response_days, max_extension_days, int(bool(minor_guardian_required)),
                     int(bool(agent_authority_required)), now, actor, now, now),
                )
                self._audit(conn, None, actor, "jurisdiction_rule.published",
                            {"code": code, "version_no": 1, "effective_at": now})
                return self._rule_dict(self._rule_row(conn, cur.lastrowid))
            if (current["response_days"] == response_days
                    and current["max_extension_days"] == max_extension_days
                    and bool(current["minor_guardian_required"]) == bool(minor_guardian_required)
                    and bool(current["agent_authority_required"]) == bool(agent_authority_required)):
                conn.execute("UPDATE jurisdictions SET name=? WHERE code=?", (name, code))
                return self._rule_dict(current)
            raise DomainError("地区规则已发布不能原地修改，请使用规则补正接口填写原因后生成新版本", 409)

    def create_rule_draft(self, actor: str, role: str, code: str, response_days: int,
                          max_extension_days: int, effective_at: str, reason: str = "",
                          minor_guardian_required: bool = True,
                          agent_authority_required: bool = True,
                          name: str = "") -> dict[str, Any]:
        """为地区创建新版本草案，到 effective_at 才发布并用于新案件；补正必须带原因。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "建立规则草案")
        code = code.strip().upper()
        name = name.strip()
        response_days, max_extension_days = self._validate_rule_params(response_days, max_extension_days)
        if not code:
            raise DomainError("地区代码不能为空")
        if not reason.strip():
            raise DomainError("规则补正必须填写变更原因")
        effective_dt = parse_time(effective_at)
        if effective_dt <= self.now():
            raise DomainError("生效时间必须晚于当前时间")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._activate_due_drafts(conn)
            region = conn.execute("SELECT * FROM jurisdictions WHERE code=?", (code,)).fetchone()
            if region is None:
                if not name:
                    raise DomainError("新地区首次建立规则时必须提供名称")
                conn.execute("INSERT INTO jurisdictions(code,name) VALUES(?,?)", (code, name))
            elif name:
                conn.execute("UPDATE jurisdictions SET name=? WHERE code=?", (name, code))
            pending = conn.execute(
                "SELECT id FROM jurisdiction_versions WHERE code=? AND status='draft'", (code,)
            ).fetchone()
            if pending:
                raise DomainError("该地区已有未生效草案，请先撤回或等待其生效", 409)
            next_no = conn.execute(
                "SELECT COALESCE(MAX(version_no),0)+1 AS n FROM jurisdiction_versions WHERE code=?", (code,)
            ).fetchone()["n"]
            cur = conn.execute(
                """INSERT INTO jurisdiction_versions(code,version_no,status,response_days,max_extension_days,
                   minor_guardian_required,agent_authority_required,change_reason,effective_at,created_by,created_at)
                   VALUES(?,?,'draft',?,?,?,?,?,?,?,?)""",
                (code, next_no, response_days, max_extension_days, int(bool(minor_guardian_required)),
                 int(bool(agent_authority_required)), reason.strip(),
                 effective_dt.isoformat(timespec="seconds"), actor, self.now_text()),
            )
            self._audit(conn, None, actor, "jurisdiction_rule.draft_created",
                        {"code": code, "version_no": next_no, "effective_at": effective_dt.isoformat(timespec="seconds"),
                         "reason": reason.strip()})
            return self._rule_dict(self._rule_row(conn, cur.lastrowid))

    def withdraw_rule_draft(self, actor: str, role: str, version_id: int, reason: str = "") -> dict[str, Any]:
        """仅未生效草案可撤回；发布后的规则不能撤回。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "撤回规则草案")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._activate_due_drafts(conn)
            row = conn.execute("SELECT * FROM jurisdiction_versions WHERE id=?", (version_id,)).fetchone()
            if not row:
                raise DomainError("规则版本不存在", 404)
            if row["status"] != "draft":
                raise DomainError("只有未生效草案可以撤回", 409)
            conn.execute(
                "UPDATE jurisdiction_versions SET status='withdrawn',withdrawn_by=?,withdrawn_at=?,withdraw_reason=? WHERE id=? AND status='draft'",
                (actor, self.now_text(), reason.strip(), version_id),
            )
            self._audit(conn, None, actor, "jurisdiction_rule.draft_withdrawn",
                        {"code": row["code"], "version_no": row["version_no"], "reason": reason.strip()})
            return self._rule_dict(self._rule_row(conn, version_id))

    def list_rules(self, actor: str, role: str, code: str = "") -> list[dict[str, Any]]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._activate_due_drafts(conn)
            sql = ("""SELECT jv.*, j.name AS jurisdiction_name FROM jurisdiction_versions jv
                      JOIN jurisdictions j ON j.code=jv.code""")
            params: tuple[Any, ...] = ()
            if code.strip():
                sql += " WHERE jv.code=?"
                params = (code.strip().upper(),)
            sql += " ORDER BY jv.code,jv.version_no DESC,id DESC"
            return [self._rule_dict(r) for r in conn.execute(sql, params).fetchall()]

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
                    (subject_ref.strip(), region.strip().upper(), int(bool(is_minor)), sha256_text(contact.strip().lower()), self.now_text()),
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
            existing = conn.execute("SELECT * FROM requests WHERE idempotency_key=?", (idempotency_key.strip(),)).fetchone()
            if existing:
                return {"idempotent": True, "request": dict(existing)}
            subject = conn.execute("SELECT * FROM data_subjects WHERE id=?", (subject_id,)).fetchone()
            if not subject:
                raise DomainError("数据主体不存在", 404)
            rule = self._effective_rule(conn, subject["region"])
            if not rule:
                raise DomainError("数据主体所在地区尚无生效处理规则", 409)
            if subject["is_minor"] and rule["minor_guardian_required"] and requester_kind != "guardian":
                raise DomainError("未成年人请求必须由监护人提出", 403)
            if requester_kind == "authorized_agent" and rule["agent_authority_required"] and not (agent_authority_ref or "").strip():
                raise DomainError("授权代理必须提供有效授权引用", 403)
            now_dt = self.now()
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
                    """INSERT INTO requests(request_no,subject_id,request_type,status,jurisdiction,rule_version_id,requester_kind,agent_authority_ref,
                       idempotency_key,duplicate_of,submitted_at,due_date,original_due_date,created_by,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (request_no.strip(), subject_id, request_type, status, subject["region"], rule["id"], requester_kind,
                     (agent_authority_ref or "").strip() or None, idempotency_key.strip(), duplicate_of,
                     now, due, due, actor, now),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("请求编号已存在", 409) from exc
            request_id = cur.lastrowid
            self._audit(conn, request_id, actor, "request.created",
                        {"type": request_type, "duplicate_of": duplicate_of,
                         "rule_version_id": rule["id"], "rule_version_no": rule["version_no"],
                         "rule_effective_at": rule["effective_at"]})
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
                (self.now_text(), actor, self.now_text(), request_id, expected_version),
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
            conn.execute("UPDATE requests SET assigned_to=?,version=version+1,updated_at=? WHERE id=? AND version=?", (assignee.strip(), self.now_text(), request_id, expected_version))
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
                    (request_id, system_name.strip(), data_category.strip(), owner_team.strip(), self.now_text(), self.now_text()),
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
                 int(bool(third_party_exception)), status, note.strip(), self.now_text(), location_id),
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
            req = self._request(conn, request_id)
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("当前请求不能延期", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            rule = self._bound_rule(conn, req)
            if req["extension_days"] > 0:
                raise DomainError("每个请求只能延期一次", 409)
            if days <= 0 or days > rule["max_extension_days"]:
                raise DomainError("延期天数超出受理时规则版本的上限（v%s：%s 天）" % (rule["version_no"], rule["max_extension_days"]), 409)
            due = (parse_time(req["due_date"]) + timedelta(days=days)).isoformat(timespec="seconds")
            conn.execute(
                "UPDATE requests SET status='extended',due_date=?,extension_days=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (due, days, self.now_text(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "request.extended",
                        {"days": days, "reason": reason.strip(), "due_date": due,
                         "rule_version_no": rule["version_no"], "max_extension_days": rule["max_extension_days"]})
            return dict(self._request(conn, request_id))

    @staticmethod
    def _bound_rule(conn: sqlite3.Connection, req: sqlite3.Row) -> sqlite3.Row:
        rule = conn.execute(
            """SELECT jv.*, j.name AS jurisdiction_name FROM jurisdiction_versions jv
               JOIN jurisdictions j ON j.code=jv.code WHERE jv.id=?""",
            (req["rule_version_id"],),
        ).fetchone()
        if not rule:
            raise DomainError("案件未绑定受理时的规则版本，无法判断时限", 409)
        return rule

    def recalculate_due_date(self, actor: str, role: str, request_id: int,
                             expected_version: int, reason: str) -> dict[str, Any]:
        """按案件绑定的受理时规则版本重算到期日（基础时限 + 已核准延期），不采用任何后发规则。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "重算到期日")
        if not reason.strip():
            raise DomainError("重算原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] not in OPEN_STATUSES:
                raise DomainError("已结案件不能重算到期日", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            rule = self._bound_rule(conn, req)
            base = parse_time(req["submitted_at"]) + timedelta(days=rule["response_days"])
            new_due = (base + timedelta(days=req["extension_days"])).isoformat(timespec="seconds")
            conn.execute(
                "UPDATE requests SET due_date=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (new_due, self.now_text(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "request.due_recalculated",
                        {"reason": reason.strip(), "due_date": new_due,
                         "rule_version_no": rule["version_no"], "original_due_date": req["original_due_date"]})
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
            conn.execute("UPDATE requests SET status='response_ready',version=version+1,updated_at=? WHERE id=? AND version=?", (self.now_text(), request_id, expected_version))
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
                (response_summary.strip(), self.now_text(), request_id, expected_version),
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
            conn.execute("UPDATE requests SET status='rejected',denial_reason=?,version=version+1,updated_at=? WHERE id=? AND version=?", (reason.strip(), self.now_text(), request_id, expected_version))
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

    def _enrich_request(self, conn: sqlite3.Connection, item: dict[str, Any]) -> dict[str, Any]:
        """在案件上附带其采用的规则版本信息，供页面展示。"""
        row = conn.execute(
            """SELECT jv.*, j.name AS jurisdiction_name FROM jurisdiction_versions jv
               JOIN jurisdictions j ON j.code=jv.code WHERE jv.id=?""",
            (item.get("rule_version_id"),),
        ).fetchone()
        if row:
            item["rule_version"] = self._rule_dict(row)
            item["rule_version_label"] = "%s v%s" % (row["code"], row["version_no"])
        return item

    def _rule_changes(self, conn: sqlite3.Connection, code: str) -> list[dict[str, Any]]:
        """该地区的每一次规则变更（含草案、生效、被取代、撤回），按时间排列。"""
        rows = conn.execute(
            """SELECT jv.*, j.name AS jurisdiction_name FROM jurisdiction_versions jv
               JOIN jurisdictions j ON j.code=jv.code
               WHERE jv.code=? ORDER BY jv.version_no""",
            (code,),
        ).fetchall()
        return [self._rule_dict(r) for r in rows]

    def get_request(self, actor: str, role: str, request_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._activate_due_drafts(conn)
            req = self._request(conn, request_id)
            if role in {"supervisor", "auditor"}:
                pass
            elif role == "privacy_officer" and req["assigned_to"] == actor:
                pass
            elif role == "intake" and req["created_by"] == actor:
                pass
            else:
                raise DomainError("无权查看该权利请求", 403)
            locations = [dict(r) for r in conn.execute("SELECT * FROM data_locations WHERE request_id=? ORDER BY id", (request_id,)).fetchall()]
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline WHERE request_id=? ORDER BY id", (request_id,)).fetchall()]
            request = self._enrich_request(conn, dict(req))
            rule_changes = self._rule_changes(conn, req["jurisdiction"])
            return {"request": request, "locations": locations, "timeline": timeline, "rule_changes": rule_changes}

    def queue(self, actor: str, role: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._activate_due_drafts(conn)
            rows = self._visibility(actor, role, conn)
            now = self.now()
            result = []
            for row in rows:
                item = dict(row)
                item["overdue"] = parse_time(item["due_date"]) < now and item["status"] in OPEN_STATUSES
                result.append(self._enrich_request(conn, item))
        return result

    def state(self, actor: str = "", role: str = "viewer") -> dict[str, Any]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._activate_due_drafts(conn)
            rows = self._visibility(actor, role, conn)
            requests = []
            locations = []
            now = self.now()
            for row in rows:
                item = dict(row)
                item["overdue"] = parse_time(item["due_date"]) < now and item["status"] in OPEN_STATUSES
                requests.append(self._enrich_request(conn, item))
                locations.extend(dict(r) for r in conn.execute("SELECT * FROM data_locations WHERE request_id=? ORDER BY id", (row["id"],)).fetchall())
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline ORDER BY id DESC LIMIT 300").fetchall()]
            jurisdictions = [dict(r) for r in conn.execute("SELECT * FROM jurisdictions ORDER BY code").fetchall()]
            rule_versions = [self._rule_dict(r) for r in conn.execute(
                """SELECT jv.*, j.name AS jurisdiction_name FROM jurisdiction_versions jv
                   JOIN jurisdictions j ON j.code=jv.code
                   ORDER BY jv.code,jv.version_no DESC,id DESC""").fetchall()]
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
            elif path == "/api/jurisdictions/versions":
                query = urlparse(self.path).query
                code = ""
                if query:
                    for part in query.split("&"):
                        if part.startswith("code="):
                            code = part.split("=", 1)[1]
                self._send(200, {"versions": self.service.list_rules(actor, role, code)})
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
            elif path == "/api/jurisdictions/versions/draft":
                result = self.service.create_rule_draft(actor, role, **data)
            elif path == "/api/jurisdictions/versions/withdraw":
                result = self.service.withdraw_rule_draft(actor, role, **data)
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
                result = self.service.recalculate_due_date(actor, role, **data)
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
