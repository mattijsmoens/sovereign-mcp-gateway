# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-08-22

### Fixed

- **A high-entropy argument is no longer mistaken for an encoded payload.**
  CI refused a legitimate call with `text filter: argument 'repo_path' -
  High-entropy input detected. Possible encoded payload.` The argument was a
  temporary directory path.

  The entropy heuristic exists to find payloads hidden in prose. Tool
  arguments are routinely structured — paths, identifiers, hashes, query
  strings — where high entropy is normal. Measured before fixing: ordinary
  paths, SQL statements and git SHAs pass, but temp paths with random-looking
  segments were refused on Linux and Windows alike, so any deployment passing
  a path containing a hash or a UUID would have hit it.

  Entropy findings now warn rather than refuse, behind `policy.entropy_policy`
  (`"warn"` by default; `"block"` restores the previous behaviour). Every other
  text-filter finding still refuses, and injection detection is unchanged.

### Added

- `policy.entropy_policy`, validated at startup like the other policy fields.
- Six regression tests, including the exact path shape that failed in CI and a
  companion asserting an injected argument is still refused.
- **`contact@sovereign-shield.net`** for commercial licensing, in the README
  and in the package metadata. BSL requires a licence for production use; until
  now there was no stated way to obtain one.

## [0.1.1] — 2026-08-22

### Added

- Listed in the official **MCP Registry** as
  `io.github.mattijsmoens/sovereign-mcp-gateway`, so clients and the
  aggregators (mcp.so, Smithery, Glama, PulseMCP) can discover it.
- `server.json`, validated against the live registry before publishing.
- `--config` declared as a required named argument with a filepath variable, so
  clients prompt for the path rather than launching with nothing.
- The [poisoned-issue walkthrough](docs/your-agent-reads-an-issue.md) and its
  runnable A/B, `examples/poisoned_issue.py`.

### Fixed

- The licence named the wrong work. It had been carried over from
  `sovereign-mcp` and still read `Licensed Work: sovereign-mcp` with that
  project's Change Date. Now names this package, with a Change Date four years
  from its own first publication.

### Note

0.1.1 exists because the registry proves ownership of a PyPI package by finding
an `mcp-name:` marker in the package description, and PyPI does not accept a
re-upload of an existing version. The code is otherwise identical to 0.1.0.

## [0.1.0] — 2026-08-22

First release.

### Added

- A gating proxy for MCP servers. Point a client at the gateway instead of at
  your servers; it connects to every upstream, merges their catalogues, and runs
  each call through a chain before it reaches the server that would execute it.

      policy → intent → text-filter → frozen-verify
          → [ the call executes upstream ]
          → output-verify → logic-rules → audit

- **Namespacing**, on by default: a tool is exposed as `git__git_status`, so two
  upstreams cannot collide, shadow each other, or be reached through the wrong
  namespace.
- **Policy**: `deny_tools` and `allow_tools`, matching either the exposed name
  or the upstream tool name.
- **Audit**: every call, allowed or refused, in a hash-chained log across all
  upstreams.
- `--check`, which connects, prints the merged catalogue with denied tools
  marked, and exits.
- Optional layers as extras — `[intent]`, `[text]`, `[rules]`, `[all]`. The
  gateway prints which are active at startup, so a partial install degrades
  visibly rather than silently.

### Decisions worth recording

- **The behavioural floor's 0.5 s inter-action delay is off by default.** It
  suits one agent taking deliberate steps and not a proxy, where a burst of
  tool calls is ordinary traffic — with it on, every call after the first was
  refused. Configurable via `policy.rate_limit_interval`.
- **`pii_policy` defaults to `warn`, not `block`.** Real tools return personal
  data as normal output; every `git log` entry carries an author email.

[0.1.2]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.1.2
[0.1.1]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.1.1
[0.1.0]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.1.0
