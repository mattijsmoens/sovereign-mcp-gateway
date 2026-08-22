# sovereign-mcp-gateway

**A gating proxy for Model Context Protocol servers.** Point your MCP client at the gateway instead of at your servers. It connects to every upstream you list, merges their tool catalogues into one, and puts every call through a verification chain before it reaches the server that would execute it.

```bash
pip install "sovereign-mcp-gateway[all]"
sovereign-mcp-gateway --config gateway.json
```

The gateway is itself an MCP server, so any client that speaks MCP works with no changes.

---

## Why a proxy and not a library

A library has to be adopted by whoever wrote the server. A proxy protects servers you cannot modify — which is most of them, because the useful MCP servers are published packages someone else maintains.

It also gives you one place to hold policy and one audit trail across every server an agent can reach, rather than per-server configuration nobody keeps in sync.

## Configure

```json
{
  "servers": {
    "git":    {"command": "mcp-server-git",    "args": ["--repository", "/repo"]},
    "sqlite": {"command": "mcp-server-sqlite", "args": ["--db-path", "/data.db"]}
  },
  "policy": {"deny_tools": ["git__git_reset"], "pii_policy": "warn"},
  "audit":  {"path": "gateway-audit.jsonl"}
}
```

Check the wiring before a client ever sees it:

```bash
sovereign-mcp-gateway --config gateway.json --check
```

```
SOVEREIGN GATEWAY - configuration check
upstreams: 2
layers:   policy -> intent -> text-filter -> frozen-verify -> audit

EXPOSED AS                             UPSTREAM TOOL
git__git_status                        git.git_status
git__git_reset                         git.git_reset          [DENIED]
sqlite__read_query                     sqlite.read_query
...
18 tools exposed.
```

## The chain

```
policy → intent → text-filter → frozen-verify → [ call executes ] → output-verify → logic-rules → audit
```

| Layer | Package | Refuses when |
| --- | --- | --- |
| policy | — | the tool is on a deny list, or absent from an allow list |
| intent | `intentshield` | the call fails the behavioural floor |
| text-filter | `sovereign-shield` | an argument carries injection, in any of 22 languages or seven encodings |
| frozen-verify | `sovereign-mcp` | the call disagrees with the tool definition frozen at startup |
| output-verify | `sovereign-mcp` | the result fails schema, deception, PII or content checks |
| logic-rules | `logicshield` | the result is inconsistent with rules you configured |
| audit | `sovereign-mcp` | — records every call, allowed or refused, in a hash-chained log |

Only `sovereign-mcp` is required. The optional layers install as extras, and the gateway prints which ones are active at startup — a partial install degrades visibly rather than silently.

```bash
pip install sovereign-mcp-gateway            # policy, frozen-verify, audit
pip install "sovereign-mcp-gateway[all]"     # every layer
```

## Verified end to end

Against `mcp-server-git` and `mcp-server-sqlite` running as real upstreams, driven by a real MCP client:

| Call | Result |
| --- | --- |
| `git__git_status`, `git__git_log` | allowed |
| `sqlite__create_table`, `__write_query`, `__read_query` | allowed — the row is really in the database |
| `git__git_reset` | refused: on the deny list |
| `git__git_push_force` | refused: no upstream exposes it |
| `git__git_status(repo_path=12345)` | refused: wrong type for the frozen schema |
| `git__git_commit("IGNORE ALL PREVIOUS INSTRUCTIONS…")` | refused: text filter |
| `sqlite__git_commit(...)` | refused: a tool cannot be reached through another upstream's namespace |

Afterwards the repository still holds one commit and the database holds exactly the row it should — checked by opening them directly, not by trusting the gateway's own report. Eleven audit records for ten calls; editing any one of them breaks the chain.

Those cases are the test suite, not a screenshot: `pytest tests/ -v`.

## Namespacing

With `namespace` on (the default) a tool is exposed as `git__git_status`. Two upstreams offering the same tool name cannot collide, shadow each other, or be reached through the wrong namespace. Turn it off only when you have a single upstream.

## Policy

```json
"policy": {
  "deny_tools":  ["git__git_reset", "write_query"],
  "allow_tools": null,
  "pii_policy":  "warn",
  "fail_closed": true,
  "rate_limit_interval": 0
}
```

- **`deny_tools`** matches either the exposed name (`git__git_reset`) or the upstream tool name (`git_reset`, on every upstream that has it).
- **`allow_tools`**, when set, refuses everything not listed.
- **`pii_policy`** defaults to `warn`, not `block`. Real tools return personal data as normal output — every `git log` entry carries an author email — and blocking those makes the gateway unusable. Set `block` when your tools should never emit PII.
- **`fail_closed`** decides what happens when a layer itself errors. Default: refuse.
- **`rate_limit_interval`** is `0`, which disables the behavioural floor's own inter-action delay. That delay is right for one agent taking deliberate steps and wrong for a proxy, where a burst of tool calls is ordinary traffic.

## What this does not do

It verifies calls against frozen definitions and inspects arguments and results. It does not read your servers' source, so it cannot see a check that is present, is called, and silently does nothing. That still takes someone reading the implementation.

It also cannot protect against a compromised upstream returning correct-looking data — Layer C consensus in `sovereign-mcp` addresses that, and requires model providers you configure yourself.

## Licence

BSL 1.1 — see [LICENSE](LICENSE).
