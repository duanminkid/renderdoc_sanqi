---
description: 软件测试规范 — TDD 流程、80% 覆盖率、fixture 模式
globs:
  - "tests/**"
  - "**/*.test.*"
  - "**/*.spec.*"
alwaysApply: false
---

# 软件测试规范

## TDD 流程
1. 先写测试（RED）→ 2. 运行失败验证 → 3. 最小实现（GREEN）→ 4. 重构（IMPROVE）

## 覆盖率
- 最低 80% 行覆盖率
- 核心业务逻辑 90%+
- 不追求 100%（成本收益递减）

## 测试类型
- **单元测试**：单独函数/类，mock 外部依赖
- **集成测试**：数据库、API、中间件集成
- **E2E 测试**：关键用户流程（Playwright）

## 测试原则
- 测试行为不测试实现
- 一个测试只验证一件事
- 测试名描述场景和期望：`test_<what>_<condition>_<expected>`
- 修复 Bug 前先写复现测试

## Fixture 和数据
- Builder/factory 模式构造测试数据
- 不依赖数据库的特定状态
- 测试后清理（或 transaction rollback）
- 共享 fixture 放在 conftest 中
