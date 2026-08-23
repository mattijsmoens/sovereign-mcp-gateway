<!-- mcp-name: io.github.mattijsmoens/sovereign-mcp-gateway -->

# sovereign-mcp-gateway

**A gating proxy for Model Context Protocol servers.** Point your MCP client at the gateway instead of at your servers. It connects to every upstream you list, merges their tool catalogues into one, and puts every call through a verification chain before it reaches the server that would execute it.

[![Built on patent-pending components](https://img.shields.io/badge/built%20on-patent--pending%20components-brightgreen.svg)]()

```bash
pip install sovereign-mcp-gateway
sovereign-mcp-gateway --init          # writes gateway.json from the servers you already run
sovereign-mcp-gateway --config gateway.json --check
```

`--init` reads the MCP configuration you already have (Claude Desktop, Claude Code, Cursor, VS Code or Windsurf) and writes a `gateway.json` that proxies those same servers, so the first run produces a working config rather than a configuration error. It will not import the gateway's own entry, because that would make it proxy itself.

The gateway is itself an MCP server, so any client that speaks MCP works with no changes.

That base install is a working gateway. Four optional extras add further layers on top — see [Installing](#installing).

---

## What it stops

An agent reads a GitHub issue whose body carries an instruction aimed at the model rather than at you. It is persuaded, and calls `git_commit`.

| | commits after | injected commit present |
| --- | --- | --- |
| straight to `mcp-server-git` | 2 | yes |
| through the gateway | 1 | no |

Same tool, same arguments, same server. The difference is whether anything was in a position to refuse.

Read the walkthrough: **[Your agent reads an issue](docs/your-agent-reads-an-issue.md)** — or run it:

```bash
pip install "sovereign-mcp-gateway[all]" mcp-server-git
python examples/poisoned_issue.py
```

## Why a proxy and not a library

A library has to be adopted by whoever wrote the server. A proxy protects servers you cannot modify — which is most of them, because the useful MCP servers are published packages someone else maintains.

It also gives you one place to hold policy and one audit trail across every server an agent can reach, rather than per-server configuration nobody keeps in sync.

## Configure

### Start from what you already run

```
$ sovereign-mcp-gateway --init

Wrote gateway.json

  imported 3 servers from Claude Desktop
    /Users/you/Library/Application Support/Claude/claude_desktop_config.json
  imported 1 server from VS Code (project)

  upstreams: fetch, git, sqlite, time

  skipped:
    sovereign - this gateway - importing it would proxy itself
    notion    - no command, probably a remote/SSE server
    git       - already imported from another client
```

Four things it will not do: import itself, import a remote server it cannot launch as a subprocess, overwrite an existing file without `--force`, or write a `deny_tools` list you did not choose. It writes the file, tells you what it took and what it left, and stops.

Pass `--config PATH` alongside `--init` to write somewhere other than `./gateway.json`.

After running it, replace those servers in your client with a single entry for the gateway. Leaving both means your agent talks to them directly as well as through the proxy, and the audit trail will only show half the traffic.


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
| text-filter | `sovereign-shield` | an argument carries injection, in any of 21 languages or seven encodings |
| frozen-verify | `sovereign-mcp` | the call disagrees with the tool definition frozen at startup |
| output-verify | `sovereign-mcp` | the result fails schema, deception, PII or content checks |
| logic-rules | `logicshield` | the result is inconsistent with rules you configured |
| audit | `sovereign-mcp` | — records every call, allowed or refused, in a hash-chained log |

## Installing

The base install is a working gateway, not a stub:

```bash
pip install sovereign-mcp-gateway
```

That gives you **policy → frozen-verify → audit**, which already refuses a tool no upstream exposes, an argument of the wrong type, an undeclared parameter, a tool on your deny list, and prompt injection in an argument. Nothing else needed.

Each extra adds a layer on top:

| Extra | Adds | Worth it when |
| --- | --- | --- |
| `[text]` | `sovereign-shield` — a deeper pass over string arguments: 21 languages, and seven-variant decoding for payloads hidden in base64, hex, ROT13, leetspeak or reversed text | Your agents read text from anywhere you don't control. The base install catches `IGNORE ALL PREVIOUS INSTRUCTIONS`; it will not catch the same sentence base64-encoded, or written in Dutch |
| `[intent]` | `intentshield` — a behavioural floor applied regardless of which tool was called: shell bans, delete bans, credential URLs, malware syntax | You want a backstop that doesn't depend on getting every tool's schema right |
| `[rules]` | `logicshield` — consistency rules you write for tool *output* | You can express what a correct result looks like. Does nothing until you set `output_rules` |
| `[consensus]` | `requests` — needed by Layer C's HTTP providers | You're enabling N-model consensus with a hosted provider |

Combine what you want, or take everything:

```bash
pip install "sovereign-mcp-gateway[text]"             # one extra
pip install "sovereign-mcp-gateway[text,intent]"      # several
pip install "sovereign-mcp-gateway[all]"              # every layer
```

All four extras are small pure-Python packages — `[all]` adds no compiled dependencies and no service to run.

**A partial install degrades visibly.** The gateway prints its active layers at startup, so you can always see what is actually running:

```
layers:   policy -> frozen-verify -> audit                                  # base
layers:   policy -> intent -> text-filter -> frozen-verify -> audit         # [all]
```

If a layer isn't on that line, it isn't running — whatever you think you installed.

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


## Layer C: N-model consensus

Every other layer is deterministic and local. Layer C is the exception: it asks several **independent** models to extract the same structured document from a tool's result, canonicalises each answer, and compares the SHA-256 hashes. Agreement is decided by hash, not by prose.

It is off unless configured, because it is the only layer that costs money and latency per call, and the only one that sends tool output to a model.

```json
{
  "servers": { "...": {} },
  "consensus": {
    "providers": [
      {"type": "local", "model": "llama3.1:8b"},
      {"type": "local", "model": "qwen2.5:7b", "base_url": "http://localhost:11434/v1"},
      {"type": "openrouter", "model": "anthropic/claude-3.5-sonnet",
       "api_key_env": "OPENROUTER_API_KEY"}
    ]
  }
}
```

Two provider types: **`local`** (any OpenAI-compatible endpoint — Ollama, vLLM, LM Studio; `base_url` defaults to `http://localhost:11434/v1`) and **`openrouter`** (the key is read from the named environment variable, never written in the config).

Three rules the gateway enforces at startup rather than discovering at runtime:

- **At least two providers.** One model cannot disagree with itself; a consensus of one reports agreement on every call, which is worse than no layer because it looks like verification.
- **No duplicate models.** Two instances of the same model agreeing is not independent verification.
- **A missing API key refuses to start.** It does not fall back to running without the layer.

All providers run at `temperature = 0`, enforced in the constructor.

### Check your models agree before you trust the layer

`--check` runs **one real consensus call** against your configured models and tells you what happened. This matters more than it sounds:

```
LAYER C  - probing the configured models with one real call
--------------------------------------------------------------
  OK. The configured models produced identical documents.
  Layer C will pass ordinary output rather than refusing it.
```

Consensus compares canonical hashes, so two models that are both *semantically* right but structurally different never agree. A weaker model that echoes the schema back —

```json
{"branch": {"type": "string", "value": "main"}}   instead of   {"branch": "main"}
```

— mismatches on every call, forever, and the gateway refuses everything with a reason that correctly reads "the models disagreed". Because they did.

The probe distinguishes the three outcomes:

| | means |
| --- | --- |
| **OK** | the models produced identical documents; the layer is usable |
| **MISMATCH** | they disagree on a trivial document and will refuse every call — replace a model, or drop the section |
| **provider unreachable** | nothing was verified; a key, a model ID or an endpoint is wrong |

Install `sovereign-mcp-gateway[consensus]` or `[all]` — the HTTP providers need `requests`, which the core library deliberately does not depend on.

`--check` also lists the active layers, so you can confirm at a glance:

```
layers:   policy -> intent -> text-filter -> frozen-verify -> consensus -> audit
```

If `consensus` is absent from that line, it is not running, whatever the config says.

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
- **`entropy_policy`** defaults to `warn`. The text filter's entropy heuristic hunts for encoded payloads hidden in prose, but tool arguments are routinely structured — paths, identifiers, hashes — where high entropy is normal. A temporary directory path alone was enough to have a legitimate call refused. Set `block` when your arguments really are prose.

## What this does not do

It verifies calls against frozen definitions and inspects arguments and results. It does not read your servers' source, so it cannot see a check that is present, is called, and silently does nothing. That still takes someone reading the implementation.

It also cannot protect against a compromised upstream returning correct-looking data — Layer C consensus in `sovereign-mcp` addresses that, and requires model providers you configure yourself.

## Licence

**Business Source License 1.1** — see [LICENSE](LICENSE).

The source is public. You may read it, modify it, create derivative works and
use it for development, evaluation and any other non-production purpose at no
cost.

**Production use is also free** for an individual, or an organisation of four
or fewer people — that is written into the licence as an Additional Use Grant,
not just stated here. Larger organisations need a commercial licence.

Each version converts to Apache 2.0 on its Change Date, four years after
publication.

To license it for production, or to ask whether your use needs one:
**contact@sovereign-shield.net**
