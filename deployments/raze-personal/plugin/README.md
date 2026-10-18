# Default-profile personal Claude subscription — activated as an alternative

Deployment status: own personal Pro OAuth verified and securely handed off from an isolated workstation login; temporary workstation credential retired before server inference. `claude-policy.json` privately pins the owner-confirmed identity/organization and plan. Sonnet 5.5 and Opus 5.5 public tool-free probes passed through Hermes provider registry; `/api/model/options` on the running gateway reports this provider authenticated with two models after control-socket hot reload. Default remains `openai-codex / gpt-6.1-sol`; no delegation or auxiliary migration. Near-limit context and invoice/overage behavior are unverified. Evidence: `/home/hermes/outputs/personal-claude-activation/summary.json`.


This is a deployment-specific, fail-closed copy of the hardened adapter, not the generic upstream plugin. The provider ID remains `claude-subscription-directsdk-experimental`. Nothing here enables the plugin or changes model routing.

## Fixed ownership and paths

- Hermes owner HOME: `/home/hermes/.hermes`
- Native CLI HOME: `/home/hermes/.hermes/claude-home`
- Native config: `/home/hermes/.hermes/claude-config`
- Runtime: `/home/hermes/.hermes/claude-runtime`
- Official Linux binary: `/home/hermes/.hermes/claude-home/.local/share/claude/versions/2.1.292`
- SHA-256: `a967e7b1d8b4e47ee421d5433027880347952b0c0857abf880e2c942a4ec93b3`

The binary digest establishes integrity, not identity, plan, entitlement, pricing or billing. `profile_policy.py` pins these paths. Any bound secret scope must carry this exact owner HOME, including the default owner's turns inside a multiplexer. A standalone default process may run without a scope; it still must provide the exact three `PATH_KEYS`. Bound scopes never borrow missing path selectors from ambient variables. Foreign profile homes and unstamped/foreign bound scopes are rejected.

Only a minimal constructed child environment is passed to the native CLI. API keys, injected OAuth tokens, backend selectors, proxies, loader overrides and foreign config/command paths are rejected. No alternate auth store, launcher, upstream endpoint or profile is adopted. Native Authorization must match the current private OAuth credential, reread for native rotation; the admission thread validates within the captured request ContextVar context. Upstream is exactly `https://api.anthropic.com`. Usage fetching is disabled with no credential read or HTTP fallback.

## Activation prerequisites — owner/parent session only

This preparation does **not** perform these steps or create their state:

1. Review the adapter and establish private owner-only directories (`0700`) at the pinned CLI HOME, config and runtime paths. Verify the official binary before invoking it.
2. Perform the owner's own OAuth through that binary with the minimal scoped child environment and explicit `auth login --claudeai`. Do not use another profile's credentials, `setup-token`, an API key or an ambient CLI.
3. Read the official scoped `auth status --json`, require successful exit and `loggedIn: true`, `authMethod: claude.ai`, `apiProvider: firstParty`, and the exact config directory. Obtain the owner's confirmation of personal `pro` or `max` status, actual email and organization field paths/values. Do not guess identity or infer entitlement from tokens or catalog metadata.
4. Only after that review, create `/home/hermes/.hermes/claude-policy.json` as a regular owner-owned `0600` file. Required fields: `activated` (literal boolean true only after approval), `subscription_type` (exact `pro` or `max` matching auth status), nonempty `approved_models` list of exact route IDs, and `identity_pins` with exactly `email` and `organization`, each containing `path` (nonempty list of actual CLI JSON keys) and `value` (confirmed string). This repository deliberately contains no real policy or identity template.
5. Ensure the native `/home/hermes/.hermes/claude-config/.credentials.json` is a regular owner-owned `0600` file, containing only the native `claudeAiOauth` top-level record. Let native CLI own refresh.
6. With separate approval, set only the default profile's three path selectors (see `profile_policy.PATH_KEYS`), enable the plugin, and verify live provider visibility after reload. Default model routing remains unchanged unless separately requested. Discovery requires a valid activated identity/plan policy too; setup status is only a scoped auth diagnostic, not activation proof.
7. Any live inference/entitlement or UI/gateway verification needs a separate approved minimal test. Offline synthetic success is not proof of subscription billing or real model availability.

Do not run plugin CLI commands during preparation: they may trigger deferred Hermes updates. Do not modify another profile.

## Offline acceptance

From this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 /home/hermes/.hermes/hermes-agent/venv/bin/python -m pytest tests/test_personal_isolation.py tests/test_personal_provider.py -q -o addopts='-p no:cacheprovider --import-mode=importlib' --basetemp=/home/hermes/.hermes/cache/scratch/personal-claude-pytest
```

These deployment tests use synthetic fixtures only, block subprocess launches and network connections, and exercise scope ownership, personal plan/identity/config validation, private paths, pinned binary tampering, explicit models, minimal environments, native headers, admission-thread context capture, discovery rejection, and public provider entrypoints. The admission context test opens a local listening socket but makes no connection or upstream request. Core's lazy git-version metadata probe is suppressed in the provider fixture; auth state is not opened.

Inherited upstream tests/evals are retained for reference, **not certified** against this deployment. Many assume arbitrary fake CLI commands, arbitrary endpoints, ambient usage tokens and broader model catalogs which this hardened deployment deliberately rejects. `UPSTREAM_README.md`, `AGENTS.md`, and `CHANGELOG.md` describe the upstream project; they do not authorize changing this deployment's isolation, models, activation or routing.
