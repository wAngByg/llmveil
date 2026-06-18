# Roadmap

LLMVeil is intentionally small: a local, auditable text-chat relay with best-effort redaction and a local output policy gate. The project should stay usable without runtime third-party packages.

## Current Scope

- OpenAI-compatible and Anthropic-compatible text-chat relay endpoints.
- Best-effort request redaction using patterns, labeled fields, sensitive keys, and user-provided exact values.
- `balanced` and `strict` profiles for tuning redaction coverage and output blocking.
- Local reversible placeholder storage.
- Local output policy before returning upstream responses to the local client.
- Dual-protocol response checks: raw upstream payload, restored payload, final converted payload, response keys, and model-list responses.
- Optional trusted reviewer model endpoints with local aggregation before returning responses.
- Reviewer payload minimization with default redacted review text, transient strict reviewer redaction, sanitized reviewer metadata, no reviewer reason echo to clients, strict reviewer JSON parsing, remote HTTPS enforcement, and fail-closed default reviewer failures.
- Local feedback JSONL for user and agent labels without storing raw response text.
- Connection validation and local config-file writing through `llmveil configure`, without storing API key values.
- Bounded per-process request concurrency, TCP backlog tuning, overload `503` responses, request ids, health/readiness endpoints, Prometheus text metrics, and optional structured access logs.
- Direct script mode with Python standard library only.

## Near-Term

- Expand local output policy fixtures with red-team examples for prompt override, credential exfiltration, external data sending, dependency poisoning, download-and-execute patterns, destructive commands, and encoding tricks.
- Add more profile fixtures that compare balanced and strict behavior for false positives and privacy coverage.
- Add `audit-file` support for JSONL test cases and summary counts by category.
- Add a custom rules file for local allow/deny patterns without editing source code.
- Add per-category severity overrides so users can choose what blocks, annotates, or passes.
- Add optional local JSONL audit logging that records category and severity without storing raw secrets.
- Add reviewer weighting, per-reviewer categories, and offline replay over feedback records.
- Add optional global reviewer concurrency limits for deployments that use slow or rate-limited reviewer endpoints.

## Later

- Add optional request-side local audit before forwarding to the upstream relay.
- Add optional action-audit mode for agents that want to check shell commands, package changes, network requests, and file operations before execution.
- Add a local trust policy file for allowed domains, allowed package managers, and protected paths.
- Add canary-token leak detection that remains local and disabled by default.
- Add optional pluggable classifier hooks for users who choose to bring their own local model or scanner, while keeping the default install dependency-free.
- Add a deployment guide for process managers, reverse proxies, local authentication, metrics collection, log handling, private storage hygiene, and upgrade workflow.

## Non-Goals

- No claim of complete prompt-injection protection.
- No built-in cloud scanning service.
- No required ML model or embedding database.
- No execution of returned instructions.
- No replacement for an agent's own tool-call permission system.
- No promise that one configuration is right for every deployment environment.
