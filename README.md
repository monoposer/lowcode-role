# lowcode-role

基于 **DSL + OPA** 的授权控制面：通过 HTTP API 配置角色与策略，编译为 Rego bundle，由 OPA 做 allow/deny 决策。不生成 PostgreSQL RLS SQL，策略在应用层通过 `/v1/authorize` 生效。

## 架构

```
┌─────────────┐     CRUD      ┌──────────────────┐
│  Admin /    │ ────────────► │  role-server     │
│ DisplayGround│              │  (:8080)         │
└─────────────┘               └────────┬─────────┘
                                       │ publish bundle
                                       ▼
                              ┌──────────────────┐
                              │  .bundle/out     │
                              │  main.rego       │
                              │  generated.rego  │
                              │  role_grants.json│
                              └────────┬─────────┘
                                       │ -w watch
                                       ▼
┌─────────────┐   authorize   ┌──────────────────┐
│  业务服务    │ ────────────► │  OPA (:8181)     │
└─────────────┘               └──────────────────┘
                                       ▲
                              ┌────────┴─────────┐
                              │  PostgreSQL      │
                              │  roles/policies  │
                              └──────────────────┘
```

**两层授权：**

| 层次 | 配置 | 作用 |
|------|------|------|
| 静态 ACL | `roles.static_permissions` | 粗粒度 RBAC，如 `orders:select`、`*:*` |
| DSL 策略 | `policies`（`kind: dsl`） | 表 / 行 / 列 / CRUD 细粒度规则 |

发布（`POST /v1/releases`）后 **无需重启**；OPA 以 `-w` 热加载 bundle。

## 快速开始

### 依赖

- Go 1.22+
- Docker（Postgres + OPA）
- 可选：`opa` CLI（publish 时做 `opa check`）

### 启动

```bash
make docker-up    # Postgres + OPA
make run          # role-server :8080
```

### 测试后台

打开 [http://localhost:8080/displayground/](http://localhost:8080/displayground/) — 配置角色、DSL 策略、发布 bundle、测试 authorize。

### Smoke

```bash
make smoke
```

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/lowcode_role?sslmode=disable` | PostgreSQL |
| `LISTEN_ADDR` | `:8080` | HTTP 监听地址 |
| `OPA_BASE_URL` | `http://127.0.0.1:8181` | OPA 决策 API |
| `BUNDLE_OUT_DIR` | `./.bundle/out` | bundle 输出目录 |
| `BASE_REGO_PATH` | `./rego/role/main.rego` | 静态 ACL 基础 Rego |
| `OPA_EXECUTABLE` | `opa` | 本地 `opa check` 二进制 |
| `ROLE_CACHE_TTL_MS` | `200` | authorize 决策缓存 TTL |

## DSL v1 格式

唯一策略类型：`kind: "dsl"`，`body.version` 必须为 `1`。

**规范（JSON Schema）：**

- 文件：[spec/dsl/v1.schema.json](spec/dsl/v1.schema.json)
- 说明：[spec/dsl/README.md](spec/dsl/README.md)
- HTTP：`GET /v1/dsl/schema`

```json
{
  "version": 1,
  "resource": {
    "type": "db",
    "schema": "public",
    "table": "orders"
  },
  "operations": {
    "select": {
      "when": [
        {
          "left": "input.request.resource.row.user_id",
          "op": "eq",
          "right": "input.user.sub"
        }
      ]
    },
    "insert": {
      "check": [
        {
          "left": "input.request.resource.row.user_id",
          "op": "eq",
          "right": "input.user.sub"
        }
      ]
    }
  },
  "fields": {
    "amount":  { "select": true, "insert": false },
    "user_id": { "select": true, "insert": true }
  }
}
```

| 字段 | 说明 |
|------|------|
| `operations.select/delete.when` | 行级过滤（读/删） |
| `operations.insert/update.check` | 写入校验 |
| `operations.update.when` | 更新时的行过滤 |
| `fields.{col}.{select\|insert\|update}` | 列级 ACL |

条件 `op` 支持：`eq`、`neq`、`in`。`right` 可为 Rego 引用（`input.*`）或字面量。

## 策略生命周期

```
1. POST /v1/policies          创建 DSL（status=draft）
2. POST /v1/roles/{id}/policies  绑定角色
3. POST /v1/policies/{id}/compile  编译预览（可选）
4. PATCH /v1/policies/{id}    status=published
5. POST /v1/releases          发布 bundle → OPA 热加载
```

Draft 策略不参与 publish；只有 **published + 已绑定角色** 的策略进入 bundle。

## API 概览

| 方法 | 路径 | 说明 |
|------|------|------|
| GET/POST | `/v1/roles` | 角色 CRUD |
| GET/POST | `/v1/policies` | DSL 策略 CRUD |
| POST | `/v1/policies/{id}/compile` | 编译 DSL → Rego |
| POST | `/v1/dsl/compile-preview` | 预览编译（不保存） |
| GET | `/v1/dsl/schema` | DSL v1 JSON Schema |
| POST/DELETE | `/v1/roles/{id}/policies` | 绑定/解绑策略 |
| POST/GET/DELETE | `/v1/principals/{type}/{id}/roles` | 主体角色绑定 |
| POST | `/v1/authorize` | 授权决策 |
| GET/POST | `/v1/releases` | 当前 revision / 发布 |
| GET | `/metrics` | Prometheus |
| GET | `/displayground/` | 测试后台 |

请求头 `X-Actor` 用于审计；`X-Role-Revision` 用于跳过过期缓存。

## Authorize 请求格式

```json
{
  "user": {
    "sub": "user-001",
    "roles": ["authenticated"]
  },
  "request": {
    "action": "select",
    "resource": {
      "type": "db",
      "schema": "public",
      "table": "orders",
      "row": { "user_id": "user-001", "amount": 100 },
      "fields": ["amount", "status"]
    }
  }
}
```

响应：`{ "allow": true, "cache": "hit|miss", "revision": 1 }`

> **注意**：`/v1/authorize` 不查 `principal_roles` 表；调用方需自行解析主体 → 角色名，传入 `user.roles`。

## 项目结构

```
cmd/server/           入口
internal/
  api/                REST + DisplayGround
  lowcode/            DSL v1 → Rego 编译器
  bundle/             bundle 发布（原子替换）
  opa/                OPA HTTP 客户端
  db/                 PostgreSQL + schema.sql
  cache/              决策 TTL 缓存
rego/role/            静态 ACL 基础 Rego（`package role`）
scripts/              k6 压测
```

## 开发

```bash
make tidy
make test
make build
make k6          # 需安装 k6
```

## Cursor / AI 辅助

- [`AGENTS.md`](AGENTS.md) — Agent 工作指引
- [`.cursor/rules/`](.cursor/rules/) — 项目级 Cursor 规则

## License

Private / internal use.
