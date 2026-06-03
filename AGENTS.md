# AGENTS.md — lowcode-role

本文件供 Cursor Agent 在本仓库中协作时使用。

## 项目是什么

Go 授权控制面：**API 配置 DSL 策略 → 编译 Rego → OPA bundle → `/v1/authorize` 决策**。不是 Postgres RLS，不生成 SQL policy。

## 核心约束

1. **策略只有一种 kind：`dsl`**。不要重新引入 `rego` / `lowcode` / `rls` policy kind。
2. **DSL 只有 v1**（`body.version == 1`）。编译入口：`internal/lowcode/compiler.go`。
3. **Rego 是编译产物**，不是用户配置格式。用户只通过 JSON DSL + API 配置。
4. **Publish 后无需重启** OPA（docker-compose 已配 `-w` watch）。
5. **最小 diff**：只改与任务相关的文件，匹配现有 chi + pgx 风格。

## 目录职责

| 路径 | 职责 |
|------|------|
| `internal/api/` | HTTP 路由、handlers、DisplayGround 静态页 |
| `internal/lowcode/` | DSL 类型定义 + Rego 编译 |
| `spec/dsl/v1.schema.json` | DSL v1 JSON Schema 规范 |
| `internal/bundle/` | 从 DB 快照生成 OPA bundle，原子 publish |
| `rego/role/main.rego` | 静态 ACL（`role_grants.json`） |
| `internal/db/migrations/schema.sql` | **唯一** schema 文件 |
| `internal/opa/` | 调用 OPA `data.role.allow` |

## 改 DSL 时

- 改 `document.go`（类型）和 `compiler.go`（代码生成） together
- 补/改 `compiler_test.go`
- 同步更新 `README.md` DSL 示例
- DisplayGround（`internal/api/displayground/index.html`）若涉及表单字段需一并更新
- Publish 路径：`publisher.buildGenerated` → 只处理 `kind == "dsl"`

## 改 API 时

- 路由在 `internal/api/server.go` 的 `Router()`
- 新 handler 可拆到独立文件（如 `dsl.go`）
- 审计：`audit(ctx, actor, action, entityType, entityID, payload)`
- 创建 policy 默认 `kind=dsl`

## 改数据库时

- 只编辑 `internal/db/migrations/schema.sql`
- `db.go` embed 该文件，启动时 `CREATE IF NOT EXISTS` — 无版本化 migration 链
- 已有库 schema 变更需用户手动处理

## 测试

```bash
go test ./internal/lowcode/...
go test ./...
make build
make smoke   # 需 docker-up + make run
```

## 禁止

- 不要添加 PostgreSQL RLS SQL 生成
- 不要添加 `data_models` 表或独立模型 registry（字段定义在 DSL body 内）
- 不要引入 gRPC / 新框架，除非明确要求
- 不要 commit 除非用户要求

## 授权决策输入约定

- 静态 ACL：`resource.type` + `request.action`（如 `orders:select`）
- DSL db 资源：`resource.type=db`，含 `schema`、`table`、`row`、`fields`
- `user.roles` 由调用方传入，服务不查 `principal_roles` 做 authorize
