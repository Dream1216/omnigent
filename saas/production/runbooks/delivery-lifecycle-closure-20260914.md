# next SaaS 交付功能接入记录（2026-09-14）

交付目标是当前 next SaaS 主线的候选实现。旧版本的持久任务、原子入队和显式回滚规则已迁入当前 App/DCP 边界。**当前记录不是完整真实端到端通过证明，也不是生产上线记录。**

## 固定基线与交付范围

- App 基线：`1b9c67585d2d4934494b745a61ebbf437c352268`，仓库 `Dream1216/omnigent`。
- DCP 基线：`41719a8f8889463e870083903850bdde50639ef7`，仓库 `Dream1216/omnigent-deployment-control-plane`。
- 两个隔离分支均为 `codex/delivery-lifecycle-closure-20260914`。
- 历史参考 M1：`61c57a491960840c7c766f2cd4fbdee0c407230c`。保留构建成功后发布与事件原子入队规则，不恢复旧 App ORM 的部署写权限。
- 最终提交、文件哈希和测试日志由本轮验收目录中的 `candidate-manifest.json` 与 `acceptance.md` 固定。

DCP 是唯一发布权威。App 使用当前 Cookie 身份、租户/空间/项目成员关系和项目权限，生成有效期 60 秒的 RS256 委托凭据。客户端不能决定 tenant、actor 或实际目标环境；旧格式提交的制品地址必须匹配同一项目的成功 Build。生产提升与回滚另外通过专用 mTLS 服务实时检查成员状态和 `environment.manage`。

## 已实现

1. `POST /v1/deliveries` 持久化交付意图；协调器持续执行已验证 Snapshot → OCI → Build → Release Preview。浏览器关闭不终止任务；租约到期或被替换后旧 Worker 不能提交状态。
2. Release、ReleasePreview 和各自 outbox/audit 在同一事务中创建。提交后确认丢失可按稳定幂等键重放；较旧构建不能覆盖较新的预览意图。
3. 构建取消持久化后调用执行器的 cancel 接口，执行器确认终态后再结算；失败或取消可发起新的构建并保留原记录。
4. 提升沿用已经验证的制品和源码摘要。回滚明确指定历史 release，检查当前环境 generation、作用域、历史成功事件和时间方向；支持失败版本恢复。涉及数据库迁移的派生操作拒绝自动执行。
5. `/saas/delivery` 提供登录、项目选择、源码快照构建、发布确认、历史版本回滚、状态/错误/重试，以及现有 SaaS Run Preview 的打开/停止入口。Onboarding 和项目管理页面增加入口。
6. 生产历史按环境查询，避免被较多预览记录挤出分页。发布预览按环境、generation、Git revision 自动查找已验证的域名；拒绝过期租约、过期证书、旧版本域名和不隔离的 origin。
7. App 内置 DCP OpenAPI 快照，readiness 比较规范化哈希；页面静态资源和契约随 Python wheel 分发。

## 五项补齐

- `/deployments` 书签进入当前工作台；原 `/v1/deployments` 和 `/v1/builds` 请求由当前 Cookie/RBAC 解析项目并委托 DCP。旧 session/context 请求从已完成且属于当前用户的 Run 解析源码。审批/执行遵循 DCP 自动入队和现行策略，响应包含 `execution_mode=dcp_managed`；外部审批等待、失效 generation 与越权仍按具体原因拒绝。
- 工作台和实际 ChatPage Composer 均接入会话入口。PreviewControl 可以启动、打开、停止当前会话的 SaaS Run Preview，并跳转到该会话的构建来源。
- 私有 mTLS `/checkpoints/export` 使用 Run 对应 Worktree 的不可变 recovery artifact，核验归属、当前成员权限、内容摘要与 repository binding；用配置的只读 Git mirror 验证并补齐 thin bundle 的基线。DCP `/v1/source-snapshots/from-checkpoint` 重新打包、扫描并独立 HEAD 核对上传对象。它是独立的 `saas-checkpoint-v1` 权威，不伪造 Runner grant 或 export receipt。
- DCP migration `0026_delivery_cancel_intent` 持久化提前取消。已持有租约的协调器若完成 Build 创建，后续步骤会接回同一 Build 并取消；发布的原子事务检查取消标记。存在取消意图时拒绝数据库降级。
- Host Build Agent v2 提供非阻塞 submit/observe/cancel、完整请求绑定 HMAC、持久状态、进程组终止以及专属 BuildKit 容器和缓存卷清理。清理未确认时保持处理中。命令为 DCP 包的 `omnigent-host-build-agent`，支持旧 gzip 与当前 DCP zstd 快照。

## 真实环境交付边界
- 真实 Snapshot Runner/OCI 仓库、Build/Tekton、受保护 GitOps/Argo、域名/TLS 供应与清理必须在隔离目标上用同一对 App/DCP 候选镜像验证。测试替身的成功响应不是运行中容器、DNS或真实预览 HTTP 的证据。
- 实际聊天页组件、Cookie/JWT/DCP、真实 mTLS 检查点和独立 Docker 取消均有本地测试；真实 Runner/Gateway child Run、生产域名与 GitOps/Argo 全链路仍须在目标环境按下述步骤验收。
- 当前改动位于候选分支；不能据此声称已经合入远程 main 或上线 next.jxhh.com。

## 部署配置（先用于隔离验收）

App 启用 `OMNIGENT_SAAS_CAPABILITIES` 中的 `delivery`，并设置 `OMNIGENT_SAAS_DELIVERY_CONFIG_FILE`。配置与私钥必须是当前服务用户拥有的绝对路径普通文件、权限 0600 或更严，不接受符号链接。

配置结构示例（必须换成隔离环境的实际绑定，不包含密钥正文）：

```json
{
  "endpoint": "https://dcp.delivery-test.example",
  "issuer": "https://app.delivery-test.example/saas/delivery",
  "key_id": "delivery-candidate",
  "private_key_file": "/run/secrets/delivery-signing.pem",
  "ca_file": "/run/secrets/delivery-ca.pem",
  "repository_mirrors": {"repository-binding-key": "/srv/delivery-mirrors/project.git"},
  "projects": [{
    "tenant_id": "00000000-0000-4000-8000-000000000001",
    "space_id": "00000000-0000-4000-8000-000000000002",
    "project_id": "00000000-0000-4000-8000-000000000003",
    "name": "隔离验收项目",
    "preview_environment": "delivery-preview",
    "production_environment": "delivery-promotion-test"
  }]
}
```

DCP 的 App workload profile 使用上述 issuer、`/saas/delivery/.well-known/jwks.json` 和 audience `omnigent-deployment-control-plane`。在既有 formal identity 环境保留 human broker，并使用相互独立且权限不交叉的 workload profile；不要为了接入关闭 formal identity、容量或配额治理。

App 所需委托权限集合：`build:read`、`build:create`、`build:cancel`、`snapshot:read`、`snapshot:create`、`snapshot:promote`、`deployment:read`、`deployment:create`、`deployment:promote`、`deployment:rollback`、`domain:read`。每个请求只签发其所需子集。

生产动作回查使用独立监听器：

```bash
python -m saas.delivery.authorization
```

它读取现有 production server 配置，并要求 `OMNIGENT_SAAS_DCP_AUTH_TLS_CERT_FILE`、`OMNIGENT_SAAS_DCP_AUTH_TLS_KEY_FILE`、`OMNIGENT_SAAS_DCP_AUTH_TLS_CLIENT_CA_FILE`。端口 8444 强制客户端证书。客户端 CA 应仅签发 DCP 回查客户端；不能共用允许其他 workload 的通用 CA。DCP `DCP_AUTHORIZATION_URL` 指向此私有监听器的 `/authorize`。该端点不挂到公网 Cookie 服务。

## 升级与恢复顺序

1. 固定两个镜像 digest、实际项目和隔离目标，记录已有服务及回退版本。
2. 在隔离数据库执行 DCP migrations `0025_delivery_continuation` 和 `0026_delivery_cancel_intent`，刷新非 owner 应用角色授权并验证 forced RLS。新协调器通过受限 SECURITY DEFINER 函数领取队列；Build/Release Worker 权限不扩大。
3. 部署匹配版本 DCP API/协调器与原有执行器，保留治理与供应链检查；再部署 App 与专用授权回查服务。
4. App readiness 必须验证 DCP 契约一致。最后才执行下列真人与真实执行验收。
5. 应用恢复可停止接收新交付并停协调器，但必须保留意图、执行记录和 outbox。旧 DCP 严格 schema 版本检查不能直接运行在新库上。数据库降级在存在任何交付或取消记录时主动拒绝；有数据时应保留新 schema 并前向修复，不能删记录强行降级。

## 可复验的本地检查

App（指定匹配的 DCP checkout；不设置时跨仓库测试会明确跳过）：

```bash
OMNIGENT_DCP_SOURCE=/absolute/path/to/omnigent-deployment-control-plane \
  python -m pytest -q tests/saas/test_delivery_http.py \
  tests/saas/test_delivery_authorization_transport.py tests/saas/test_delivery_config.py \
  tests/saas/test_delivery_checkpoint.py tests/saas/test_delivery_legacy.py
```

跨仓库验收解释器还需安装 DCP 的 `pathspec` 和 `zstandard` 依赖。实际 ChatPage 入口可运行 `cd web && pnpm exec vitest run src/pages/ChatPage.composer.test.tsx`。

DCP：

```bash
PYTHONPATH=src:. python -m pytest -q tests/contract/test_delivery_workflow.py \
  tests/contract/test_release_derivation.py tests/contract/test_api_contract.py
PYTHONPATH=src:. DCP_DATABASE_URL='<isolated owner database URL>' \
  python -m pytest -q tests/integration/test_delivery_postgres.py
ruff check src
mypy src/omnigent_dcp
```

真实验收操作：登录项目 → 导出当前 Run 的可信源码快照 → 构建版本 A → 打开预览并核对内容/digest → 提升至测试生产目标 → 构建并提升不同制品 B → 明确选择 A 回滚 → 验证实际运行 digest 回到 A。重复提交、刷新/关闭浏览器、重启协调器、旧 generation、失效成员、无权限账号、另一租户/项目和过期预览均需覆盖。记录构建、签名 GitOps、Argo 观察、实际 HTTP 和审计事件中的同一组 ID/digest。
