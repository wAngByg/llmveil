# LLMVeil 发布前文案草案

本文档只用于发布前审稿。不要把任何个人 token、账号、私有上游地址或密钥写入仓库说明、Release Notes、Issue 模板或示例配置。

## 项目名称

- 显示名称：LLMVeil
- 建议仓库名：llmveil
- Python 包名：llmveil
- 命令行名称：llmveil

## GitHub About 简介

中文：

```text
本地隐私脱敏与响应审计网关：在请求发往兼容文本聊天 API 前替换敏感信息，并在响应返回本地 agent 前审计潜在投毒指令。
```

English:

```text
Local privacy redaction and response-audit gateway for compatible text-chat APIs before they reach local agents.
```

## GitHub Topics 建议

```text
privacy
redaction
llm
gateway
relay
security
agent-safety
output-policy
openai-compatible
anthropic-compatible
python
zero-dependency
```

## README 顶部短介绍

中文：

```text
LLMVeil 是一个运行在用户本地的隐私保护与响应审计网关。它会在请求发往上游模型或中转服务前，把检测到的敏感内容替换成本地占位符；当响应返回后，再在本地还原占位符，并在输出策略未关闭时，先审计潜在的提示注入、密钥外传、危险命令、依赖投毒和外部上传指令，再交给本地 agent。

LLMVeil 默认不依赖第三方运行时包，不上传遥测，不内置厂商密钥，也不会把可逆占位符映射发送给上游。它适合作为本地 agent 的一道可审计防线，也可以集成到团队已有的网关或 agent 工作流中。

默认模式使用本地规则、敏感字段名、常见格式和用户提供的精确值做字符串替换；严格模式会增加更宽的上下文启发式识别，用来覆盖名字、街道、单位、年龄、生日等更自然语言化的敏感信息。上游返回内容按不可信输入处理；当输出策略未关闭时，响应交给本地 agent 前会先审计潜在投毒、危险命令、依赖安装和隐私外传指令。

LLMVeil 最适合正在使用不完全可信中转站、同时又有可信 reviewer 端点和脱敏需求的用户。如果没有脱敏需求，可以直接使用已有的成熟 SDK、代理或网关工具；如果没有使用中转站，而是直接使用可信端点，可以只开启 balanced 简单脱敏，不必默认开启 strict 脱敏或防投毒链路。

配置方式以文件为主：用户从 `examples/trusted-direct.config.env`、`examples/untrusted-relay.config.env`、`examples/strict-privacy.config.env` 中选择一个模板，复制到自己的私有目录后修改。第一版不默认启动 Web 配置面板，避免给隐私网关额外增加本地攻击面。

高级规则按需开启，不默认全开。比如钱包/链上私钥类 64 位 hex 检测通过 `LLMVEIL_REDACT_WALLET_KEYS=on` 显式开启；默认关闭，避免把普通哈希、校验和或 commit 相关内容误判为钱包私钥。
```

English:

```text
LLMVeil is a local privacy and response-audit gateway. It replaces detected sensitive values with local placeholders before requests are sent to an upstream model or relay, restores placeholders locally when responses return, and audits returned content before it reaches a local agent unless output policy is explicitly disabled.

LLMVeil has no required third-party runtime dependencies, sends no telemetry, includes no provider keys, and never forwards the reversible placeholder map upstream. It is intended as an auditable safety layer for local agents and team gateway workflows.

The default mode uses local rules, sensitive field names, common formats, and user-provided exact values for string replacement. Strict mode adds broader contextual heuristics for natural-language private details such as names, streets, organizations, ages, and birthdays. Returned upstream content is treated as untrusted and is audited before it reaches the local agent unless the user explicitly sets `LLMVEIL_OUTPUT_POLICY=off` for a trusted-direct setup.

LLMVeil is most useful when a user has an untrusted relay, trusted reviewer endpoints, and a real redaction need. If there is no redaction need, existing mature SDKs, proxies, or gateway tools may be simpler. If the user is calling a trusted endpoint directly, balanced redaction alone is usually enough; strict redaction and the poisoning gate do not need to be enabled by default.

Configuration is file-first: users choose one template from `examples/trusted-direct.config.env`, `examples/untrusted-relay.config.env`, or `examples/strict-privacy.config.env`, copy it into a private directory, and edit it. The first release does not start a web configuration panel by default, avoiding an extra local attack surface for a privacy gateway.

Advanced checks are opt-in rather than all enabled by default. For example, 64-hex wallet/private-key redaction is enabled with `LLMVEIL_REDACT_WALLET_KEYS=on`; it is off by default to avoid treating ordinary hashes, checksums, or commit-related values as wallet keys.
```

## 首版 Release 标题

中文：

```text
LLMVeil v.0.1.20260617.1：本地隐私脱敏、响应审计与可信 reviewer 网关
```

English:

```text
LLMVeil v.0.1.20260617.1: local redaction, response audit, and trusted reviewer gateway
```

## 首版 Release Notes 草案

中文：

```text
这是 LLMVeil 的首个公开预览版本。

LLMVeil 是一个本地运行的隐私保护与响应审计网关，面向需要连接兼容文本聊天 API 的本地 agent 工作流。它会在请求发送到上游之前进行本地脱敏，在响应返回后本地还原占位符，并在输出策略未关闭时，在响应交给本地 agent 之前执行输出策略审计。

主要能力：

- 支持 OpenAI-compatible 与 Anthropic-compatible 文本聊天接口。
- 支持同协议转发与基础跨协议转换。
- 支持 balanced / strict 两档脱敏与输出策略。
- 适合“不完全可信中转站 + 可信 reviewer 端点 + 脱敏需求”的场景；如果只是可信端点直连，可以只开 balanced 简单脱敏。
- 提供可信端点直连、不可信中转站、严格隐私三套配置模板；第一版使用配置文件，不默认启动 Web 面板。
- 钱包/链上私钥类 64 位 hex 检测默认关闭，可通过 `LLMVEIL_REDACT_WALLET_KEYS=on` 显式开启。
- 支持邮箱、手机号、URL、域名、token、账号、密码、生日、地址、单位、人名等常见敏感信息的本地规则脱敏。
- 默认按命中字典、敏感字段、常见格式和用户提供精确值做字符串替换；严格模式增加上下文启发式识别，用来覆盖更自然语言化的敏感信息。
- 支持用户提供精确敏感值文件和请求级额外脱敏值。
- 支持本地响应审计，覆盖提示注入、密钥外传、远程脚本执行、危险删除、权限放宽、安装依赖、上传日志/源码/密钥等高风险模式。
- 支持多个用户自配的可信 reviewer 模型端点，并支持聚合策略和 fail-closed 失败策略。便宜可信模型即使生成能力不如主模型，也可以用来审计代码、依赖、命令和隐私外传风险。
- 支持 feedback JSONL，本地记录误报、漏报、确认拦截和确认放行，不保存原始响应正文。
- 支持健康检查、就绪检查、Prometheus 文本指标、请求 ID、可选结构化访问日志、有界并发和过载 503。
- 运行时只使用 Python 标准库，无必需第三方运行时依赖。

重要边界：

- LLMVeil 的脱敏和投毒检测是本地规则与启发式策略，不保证识别所有隐私或所有攻击。
- 如果将 LLMVeil 暴露给个人机器以外的环境，请启用本地认证，保护 redaction map，监控指标，并谨慎处理日志。
- 不要提交 API key、本地 redaction map、私有 reviewer 配置或任何真实用户数据。
```

English:

```text
This is the first public preview release of LLMVeil.

LLMVeil is a local privacy and response-audit gateway for agent workflows that call compatible text-chat APIs. It redacts sensitive values before requests are sent upstream, restores placeholders locally when responses return, and audits returned content before it reaches the local agent unless output policy is explicitly disabled.

Highlights:

- OpenAI-compatible and Anthropic-compatible text-chat endpoints.
- Same-protocol forwarding and basic cross-protocol conversion.
- Balanced and strict redaction/output-policy profiles.
- Intended for the combination of an untrusted relay, trusted reviewer endpoints, and a real redaction need. For direct trusted endpoints, balanced redaction alone is usually enough.
- Includes trusted-direct, untrusted-relay, and strict-privacy config templates. The first release is config-file first and does not start a web panel by default.
- 64-hex wallet/private-key redaction is off by default and can be enabled with `LLMVEIL_REDACT_WALLET_KEYS=on`.
- Local rule-based redaction for common sensitive values such as emails, phone numbers, URLs, domains, tokens, accounts, passwords, birthdays, addresses, organizations, and names.
- Default string replacement uses local dictionaries, sensitive field names, common formats, and user-provided exact values. Strict mode adds broader contextual heuristics for natural-language private details.
- User-provided exact redaction values through a local file or request header.
- Local response audit for prompt injection, credential exfiltration, remote script execution, destructive commands, broad permission changes, package installation, and upload/exfiltration instructions.
- Context-aware dependency install handling: exact user-requested packages may pass, but typosquats, URL/git installs, registry/index overrides, runner tools, system package managers, and upload/exec flags remain blocked by default.
- Optional user-configured trusted reviewer model endpoints with aggregation and fail-closed failure handling. A cheaper trusted model may be weaker at generation but still useful for auditing code, dependencies, commands, and privacy-exfiltration risks.
- Local feedback JSONL for false positives, false negatives, confirmed blocks, and confirmed allows without storing raw response text.
- Health/readiness endpoints, Prometheus text metrics, request IDs, optional structured access logs, bounded concurrency, and overload 503 responses.
- Python standard-library runtime with no required third-party runtime dependencies.

Important boundaries:

- LLMVeil uses local rules and heuristics. It cannot guarantee detection of every private value or every attack.
- Remote upstream and remote reviewer endpoints must use HTTPS; plain HTTP is only for localhost loopback testing or local trusted reviewers.
- If LLMVeil is exposed beyond a personal machine, enable local authentication, protect redaction maps, monitor metrics, and handle logs carefully.
- Do not commit API keys, local redaction maps, private reviewer configs, or real user data.
```

## 发布前检查清单

- README 顶部中文与英文介绍已确认。
- `pyproject.toml` 项目名仍为 `llmveil`。
- 不写入任何个人 token、账号、真实密钥或私有上游地址。
- 发布前重新运行测试与敏感痕迹扫描。
- 创建 GitHub 仓库后再补真实仓库 URL、Security contact 和首个 tag。
