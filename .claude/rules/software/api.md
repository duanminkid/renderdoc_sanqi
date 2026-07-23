---
description: API 代码规则 — REST 设计、分页、错误处理、认证
globs:
  - "src/api/**"
  - "src/routes/**"
  - "src/controllers/**"
  - "src/handlers/**"
alwaysApply: false
---

# API 代码规范

## REST 设计
- 资源命名用复数名词
- HTTP 方法语义正确（GET/POST/PUT/DELETE）
- 版本化 API（/v1/ 或 header）

## 分页
- 列表接口默认分页
- 使用 cursor-based 分页（推荐）或 offset-based
- 响应包含分页元数据

## 错误处理
- 统一错误响应格式：{ error: { code, message, details? } }
- HTTP 状态码语义正确
- 不暴露内部错误细节给客户端

## 认证授权
- 每个端点检查认证状态
- 权限检查在业务逻辑前
- 敏感操作记录审计日志

## 输入验证
- 请求体/查询参数必须验证
- 使用 schema validation（zod/joi/pydantic）
- 验证失败返回 400 及具体原因
