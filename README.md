# 个人数据权利请求处理系统

标准库实现的跨地区数据访问、更正、删除、撤回同意和限制处理请求后台，使用 SQLite 保存案件、数据位置、时限和审计时间线。

## 运行

要求 Python 3.11+（当前 Python 3.9 环境亦可）。

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8210`，数据库默认 `privacy_requests.db`。可用 `--db`、`--host`、`--port` 修改。

## 主要接口

使用 `X-User`、`X-Role` 请求头。角色有 `intake`、`privacy_officer`、`supervisor`、`auditor`。

- `GET /health`、`GET /api/state`、`GET /api/queue`、`GET /api/requests/{id}`
- `POST /api/jurisdictions`：配置地区规则。首次配置立即生效为 v1；之后修订必须传 `change_reason` 和未来的 `effective_at`，生成 `draft` 草案，到点后才用于新案件
- `GET /api/jurisdictions?code=XX`：查看地区全部规则版本（任何角色可查）；草案到生效时间在任一写/读操作时自动发布
- `POST /api/jurisdictions/withdraw`：主管撤回未生效草案（`version_id`、`reason`），已发布版本不可撤回或原地改
- `POST /api/requests/recalculate`：主管按案件受理时绑定的规则版本重算到期日（`request_id`、`expected_version`、可选 `reason`），原到期日保持不变
- `POST /api/subjects`：保存不含明文联系方式的索引
- `POST /api/requests`：创建权利请求，支持幂等键和30天重复请求识别；受理时绑定当时已生效的规则版本（`rule_version_id`），延期、重算、详情均按该版本判断
- `POST /api/requests/verify`、`POST /api/requests/assign`
- `POST /api/locations`、`POST /api/locations/classify`：多系统定位和第三方/保留分类
- `POST /api/requests/extend`、`POST /api/requests/prepare`
- `POST /api/requests/fulfill`、`POST /api/requests/reject`

### 规则版本语义

- 版本状态：`draft`（未生效草案，可撤回）→ `active`（当前生效，已不可改）→ `superseded`（被新版本替换，只读）；撤回后为 `withdrawn`。
- 新案件只在受理时读取当时 `active` 版本，并把 `rule_version_id` 固化到案件上；后续地区再调整不影响已建案件的响应天数、延期上限和未成年人/代理要求。
- `original_due_date` 为受理时承诺的到期日，任何流程都不改写；延期只改 `due_date`，重算以原到期日加已批延期天数为准。
- 案件详情 `GET /api/requests/{id}` 返回 `rule_version`（采用版本快照）和 `rule_changes`（该地区每次规则变更）。
- 旧库（仅有单行 `jurisdictions`）首次启动时自动迁移为 v1 并回填存量案件绑定。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖完整查阅请求、第三方遮蔽、未成年人/代理限制、重复与幂等、延期上限、删除法律保留、权限拒绝、版本冲突，以及规则草案/生效/撤回/补正、案件按受理版本延期与重算、旧库迁移。

## 局限

身份依赖请求头，联系方式只存哈希；请求正文、证据文件和实际回复文件未实现加密存储；地区规则是可配置模板，不构成法律意见；删除是流程判定，不会自动调用外部业务系统执行清除。
