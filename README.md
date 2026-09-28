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
- `POST /api/jurisdictions`：首次配置立即生效；对已发布地区只允许幂等提交相同内容，改动会被拒绝（409）
- `POST /api/jurisdictions/versions/draft`：规则补正，带 `reason` 原因生成新版本草案，`effective_at` 到点后才生效并用于新案件
- `POST /api/jurisdictions/versions/withdraw`：撤回未生效草案（`version_id`，可附撤回原因）；生效后的版本不能撤回或原地修改
- `GET /api/jurisdictions/versions?code=CN`：查询某地区全部历史版本（草案/生效中/已被取代/已撤回）
- `POST /api/subjects`：保存不含明文联系方式的索引
- `POST /api/requests`：创建权利请求，受理时绑定当前已生效的规则版本，支持幂等键和30天重复请求识别
- `POST /api/requests/verify`、`POST /api/requests/assign`
- `POST /api/locations`、`POST /api/locations/classify`：多系统定位和第三方/保留分类
- `POST /api/requests/extend`：延期，上限按案件绑定的受理时规则版本判断
- `POST /api/requests/recalculate`：按绑定版本重算到期日（基础时限 + 已核准延期），不改原到期日
- `POST /api/requests/prepare`
- `POST /api/requests/fulfill`、`POST /api/requests/reject`

## 地区规则版本语义

- 每个地区的规则是一条**只追加**的版本链（`jurisdiction_versions`），版本号地区内递增。
- 新版本只先存为草案；到期自动发布，同时旧生效版本标记为「已被取代」。历史版本永久保留，可通过版本接口和案件详情查阅。
- 案件记录 `rule_version_id`（受理时生效的版本）；延期上限、身份/代理要求、重算到期日始终使用该版本，后续补正不影响在办案件，`original_due_date` 永不改变。
- 案件详情和队列返回 `rule_version` / `rule_version_label` 及该地区的 `rule_changes`；规则生命周期事件写入审计时间线。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖完整查阅请求、第三方遮蔽、未成年人/代理限制、重复与幂等、延期上限、删除法律保留、权限拒绝和版本冲突，以及地区规则草案/生效/撤回/补正、案件绑定版本、按旧版本延期与重算。

## 局限

身份依赖请求头，联系方式只存哈希；请求正文、证据文件和实际回复文件未实现加密存储；地区规则是可配置模板，不构成法律意见；删除是流程判定，不会自动调用外部业务系统执行清除。
