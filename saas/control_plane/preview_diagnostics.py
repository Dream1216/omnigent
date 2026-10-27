"""Content-blind recovery hints for authenticated preview controls."""

_HINTS = {
    "authentication_required": "登录已失效，请重新登录后重试。",
    "delivery_not_configured": "发布服务尚未配置，请联系管理员。",
    "preview_project_binding_missing": "当前会话未绑定发布项目，请在“构建与发布”页完成绑定。",
    "preview_scope_unavailable": "没有可用的项目预览权限，请联系项目管理员。",
    "delivery_scope_unavailable": "没有可用的项目预览权限，请联系项目管理员。",
    "preview_source_unavailable": "当前会话暂无成功运行，请先完成运行并生成构建产物。",
    "preview_checkpoint_unavailable": "检查点产物缺失，请重新构建并生成包含 dist 的检查点。",
    "preview_artifact_unavailable": (
        "静态产物目录缺失或不可读，请重新构建并生成包含 dist 的检查点。"
    ),
    "preview_entry_unavailable": "静态入口缺失、为空或不可读，请检查 dist/index.html 后重新构建。",
    "preview_supervisor_health_failed": "静态服务健康检查失败，请检查构建日志和入口文件。",
}


def preview_diagnostic(code: str) -> str:
    return _HINTS.get(code, "预览暂不可用，请检查构建日志后重试。")
