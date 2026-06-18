# Security and Supply Chain

LLMVeil is designed to be installed from auditable GitHub source.

No install method can prove absolute safety on its own. The project aims to make review practical: pin a source ref, inspect the code, install without runtime dependencies, and run local tests before trusting a release.

## Install Policy

- Prefer `git clone` plus a pinned tag or full commit SHA.
- If using `pip`, install from a pinned GitHub tag or commit with `--no-deps`.
- Do not use remote shell installers such as `curl ... | sh`.
- Do not install from unofficial mirrors, repackaged archives, or opaque binaries.
- Review `relay_gateway.py`, `llmveil.py`, `pyproject.toml`, and `README.md` before trusting a release.

Example:

```bash
python -m pip install --no-deps "git+https://github.com/wAngByg/llmveil.git@<tag-or-full-commit-sha>"
python -m llmveil self-test
python -m pip check
```

PowerShell:

```powershell
python -m pip install --no-deps "git+https://github.com/wAngByg/llmveil.git@<tag-or-full-commit-sha>"
python -m llmveil self-test
python -m pip check
```

## Dependency Policy

- No runtime third-party Python packages are required.
- No vendored third-party source is included.
- No bundled binary artifacts are required.
- No dynamic plugin loading is used.
- No subprocesses are launched by the gateway.
- Runtime network calls are made only to `LLMVEIL_UPSTREAM_BASE_URL` and, when trusted reviewers are enabled, to reviewer `base_url` values in `LLMVEIL_REVIEWERS_FILE`. Remote reviewer URLs are rejected by default unless `allow_remote: true` is set. Remote reviewers must use HTTPS.
- The built-in `/metrics`, `/health`, and `/ready` endpoints are local HTTP endpoints and do not make network calls.
- Binding outside localhost requires `LLMVEIL_LOCAL_API_KEY` or `LLMVEIL_LOCAL_API_KEY_ENV`; the process fails closed without local authentication.

Python packaging may use local packaging tools to build a wheel or create the `llmveil` console command. That packaging step is separate from runtime gateway behavior.

## Local Secrets

- Never commit upstream API keys, local API keys, redaction maps, or private redaction files.
- Keep `LLMVEIL_HOME` private. It contains reversible placeholder mappings.
- Use a pinned release and a fresh virtual environment when testing an untrusted fork.

## Trusted Reviewer Endpoints

- Reviewer models are disabled unless the user configures `LLMVEIL_REVIEWERS_FILE`.
- Reviewer endpoint keys should be provided through environment variables referenced by `api_key_env`, not written directly into the config file.
- Remote reviewer URLs are rejected unless the config sets `allow_remote: true`; remote restored payload review also requires `allow_private_payload: true`.
- The default reviewer payload is `redacted`, which preserves placeholders and applies a second transient strict redaction pass to agent-visible response strings before reviewer calls. That pass also applies configured exact redactions and private values already replaced in the current request. Use `restored` only when the reviewer endpoint is trusted to see private content.
- Reviewer `reason` text is treated as untrusted and is not returned to the local client. Headers and error bodies use sanitized reviewer names, decisions, categories, and reason codes.
- Feedback is local JSONL. It does not upload telemetry, ignores raw response text, redacts the optional note before writing, and drops metadata that looks like a secret, token, email, phone number, ID number, or placeholder.
- Metrics contain counters, gauges, and aggregate latency only. They do not include prompts, responses, placeholder mappings, API keys, upstream URLs, reviewer reasons, or feedback notes.
- Structured access logs are disabled by default. When enabled, they log request metadata such as remote address, sanitized request id, method, normalized path, status, and response size. They do not log request or response bodies, raw query strings, or the original HTTP request line.

## Production Storage Boundary

The local JSONL writer is protected against in-process thread interleaving. Keep JSONL files in a private per-user or per-deployment directory, and treat reversible placeholder mappings as sensitive data.

## Saved Configs

`llmveil configure` validates the upstream relay and configured reviewers before writing a local `config.env`. It stores the name of an API-key environment variable through `LLMVEIL_UPSTREAM_API_KEY_ENV`; it does not store the API key value. If validation fails, the config file is not written. Config files loaded by LLMVeil reject direct secret keys such as `LLMVEIL_UPSTREAM_API_KEY` and `LLMVEIL_LOCAL_API_KEY`.

## Reporting Issues

Please report security issues privately to the project maintainers once a public maintainer contact exists. Until then, open a minimal issue without private data and ask for a private contact path.
