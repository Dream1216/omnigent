# 阿里云 Agent Sandbox P1～P5 执行记录

目标：按 `omnigent-aliyun-agent-sandbox-integration-plan-2026-10-31.zh-CN.md` 完成极速版接入、测试、持续修复及生产发布。P6 容器版不在本次必需交付中。

## 实施基线

- 实施分支：`codex/aliyun-sandbox-p1-p5-20261031`。
- 源码目录：`/Users/dream/Projects/omnigent-aliyun-sandbox-20261031`。
- 起点：实际生产提交 `dc1e9a9735d4c996b74e601ed7f4ecb49e83f9ec`。
- 线上地址：`https://next.jxhh.com`。
- 公开版本证据：`2026-10-31/p1-current-state.json`。
- 当前阶段：P1 进行中，已启动 P2 的基础镜像准备。
- 生产发布：未执行。生产原有两个 provider 保持不变。

## 已完成工作

1. 通过 `/saas/version` 和当前 Kubernetes Deployment 注解核对生产版本；Server、Host 就绪，三节点 Ready。
2. 建立独立工作区，保留其他任务的源码、集群配置与活动构建。
3. 固定候选 E2B SDK 2.31.0，仅变更该包版本；uv 对已有 marker 的重新计算单独保留在 diff 中。
4. 实际安装包含 SaaS、E2B、开发测试依赖的完整 Omnigent 环境；`uv lock --check` 通过。
5. 新建有界实时探针：只向已核对的杭州 TLS Endpoint 发送凭据，拒绝共享权限、软链接、硬链接、重复配置和异常模板。
6. 探针在独立 SDK 环境及完整应用环境各运行成功，实例均已终止确认。包含创建、重连、超时、后台进程及 kill、非零退出码、中文文件、1 MiB 二进制文件。
7. 90 项定向回归通过，包括 15 项探针凭据检查、原租户沙箱身份和 E2B launcher 回归。初始 Ruff 报告的宽泛异常捕获和格式问题已修复，后续 Ruff、格式、Pyrefly 检查通过。
8. 核对官方 Base Runtime 的 manifest digest；在 exec-a 的 Docker 缓存中按该 digest 拉取基础镜像，未修改生产工作负载。
9. 103 项现有 SaaS 生产装配/配置回归通过。探针补充 Node 版本校验后，19 项相关测试通过；真实云端确认 Node 为 20.20.2，低于应用的 22.13 要求。
10. 新增使用已核对基础镜像、固定 Node 镜像和冻结应用依赖的候选 Host Dockerfile。尚未完成构建、系统包输入冻结、扫描或模板验收。

## 当前必须解决的差异

| 差异 | 权威来源 | 所需工作 |
|---|---|---|
| SaaS 生产校验拒绝 e2b provider | `saas/production/server.py` | 增加明确的云沙箱配置校验，保留原 profile 的拒绝行为 |
| 租户身份装配只有两个 Kubernetes launcher | `saas/production/tenant_sandbox.py` | 云沙箱必须继承请求上下文中的租户/工作区，不读取全局用户身份 |
| 回连、模型网关使用集群内 HTTP 名称 | 生产 ConfigMap 的相关非敏感字段 | 新增受控 TLS 路径，验证认证、失效、续签和重连 |
| 原模型 authority 通过 Secret 挂载 | `platform_model_sandbox_host.py` | 云端设计受限模型访问和安全交付，避免发送平台管理凭据 |
| Base Runtime 没有 Omnigent/tmux/bwrap | 两份真实云端探针 inventory | 构建新 Host 模板并验证内部隔离 |
| 本机 Docker VM 的 DNS 指向不可用 ::1 | 实际 pull 错误 | 保留原 VM 配置，改用可达的独立构建路径 |

## 后续顺序

1. 完成 Host 镜像构建和真实 MicroVM 自检；固定镜像、源码及依赖证据。
2. 完成 SaaS 云 provider 身份、外部回连和模型访问适配，补齐负向权限与生命周期测试。
3. 进行 CLI/managed 真实模型任务闭环，再实施 OSS 跨实例持久化。
4. 完成配额、观测、取消/超时/故障/重启、灰度、回退和生产证明。

阶段结论以逐项证据为准，不将 90 项本地回归或基础 SDK 成功视为 P3/P4/P5 已通过。

## 复核命令

```bash
uv sync --frozen --extra saas --extra e2b --group dev --no-default-groups
uv lock --check
.venv/bin/python -m pytest tests/saas/test_aliyun_sandbox_probe.py \
  tests/saas/test_tenant_sandbox.py tests/onboarding/sandboxes/test_e2b.py -q
.venv/bin/python -m saas.scripts.aliyun_sandbox_probe \
  --env-file /Users/dream/.config/omnigent/aliyun-poc.env \
  --report-dir saas/acceptance/aliyun/2026-10-31
```

最后一条会创建并清理一个 240 秒 TTL 沙箱。现场凭据不在本目录，报告不包含密钥。不同执行产生不同报告名，不覆盖历史结果。
