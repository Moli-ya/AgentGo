# ADR-0005：结构化知识情报摄取与双 Agent 复核

- 状态：Accepted
- 日期：2026-07-10

## 背景

现有知识库只有内置规则、来源元数据、文本 Chunk 和 FTS5 检索，不能结构化保存公开情报和 PoC 中的厂商、产品、影响版本、HTTP 地址及核心请求体。直接把原文交给扫描 Agent 或执行器会引入 Prompt Injection、凭据泄漏和未经审核执行 PoC 的风险。

## 决策

- 知识摄取采用 `原始来源 -> 结构化候选 -> 人工发布索引` 三层数据；
- IntelligenceExtractorAgent 使用 Knowledge Profile 提取固定 `vulnerability-intel.v1` Schema；
- IntelligenceReviewerAgent 使用 Verifier Profile 独立检查来源一致性、字段缺失和危险内容；
- 两个 Agent 通过 ModelGateway 调用，分别记录 Prompt 版本、Profile、输入输出哈希、Token、耗时、父运行引用和状态；
- 原始内容入库前执行凭据模式脱敏和命令式内容检测；
- HTTP 请求保存为 `unsafeToExecute=true` 的惰性模板，Authorization、Cookie 和 Token 使用占位符；
- LLM 只能形成候选，不能自动发布；只有人工发布后才写入 `knowledge_chunks` 和 FTS5；
- 扫描期 KnowledgeAgent 只读取已发布记录，导入原文和待审核候选不进入扫描上下文；
- 当前只支持粘贴或用户主动选择本地文本文件，来源 URL 只作为元数据，不自动抓取。

## 数据表

- `knowledge_imports`：脱敏原文、来源类型、内容哈希、检测标记、状态和 Profile 路由；
- `knowledge_intelligence`：厂商、产品、漏洞类型、标识、影响版本、请求模板、确认规则、修复和字段来源；
- `knowledge_agent_runs`：Extractor/Reviewer 的可审计运行记录；
- `knowledge_docs` / `knowledge_chunks`：继续承担来源治理和已发布检索索引。

## 安全边界

- 导入内容、模型输出和请求模板始终是不可信数据；
- 原始 PoC 不执行、不自动连接来源 URL、不直接交给 Runner；
- Schema 强制每个请求模板 `unsafeToExecute=true`；
- 发布不等于授权执行，后续任何验证仍必须经过 Scan Scope、SecurityPolicy、预算和 Evidence 链；
- 没有来源依据的字段必须使用 `Unknown` 或空数组，不能由模型猜测。

## 后续工作

- 受控 URL/Git 来源获取与独立网络出口策略；
- 厂商、产品和别名的规范化实体表；
- 冲突来源对比、版本时间线和批量审核；
- Knowledge 摄取消融评测与字段级准确率基准。
