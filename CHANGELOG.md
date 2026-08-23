# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] — 2026-08-23

### Changed

- The README's language-coverage figure said 22; the actual count in
  `sovereign-shield`'s keyword table is **21**. Corrected in both places it
  appeared.
- Added a **built on patent-pending components** badge. The gateway composes the
  libraries that implement FrozenNamespace and N-model consensus rather than
  implementing either itself, so it does not claim those applications as its own.

No code changes.

## [0.2.1] — 2026-08-22

### Fixed

- **An encoded payload is no longer waved through.** `entropy_policy="warn"`
  was added in 0.1.2 so that legitimate file paths containing hashes or UUIDs
  stopped being refused as "possible encoded payload". But a bare base64 blob
  that decodes to an injection is *also* reported as entropy rather than as
  injection — so ignoring every entropy finding let it past.

  Found by attacking a clean full install: a base64-encoded
  `IGNORE ALL PREVIOUS INSTRUCTIONS` was allowed and the commit landed.

  An entropy finding is now only ignorable if the value does not decode into
  something the filter refuses for another reason. Base64, base32 and hex are
  attempted; anything that fails to decode, or decodes to non-printable bytes,
  is skipped, so hashes and paths are unaffected.

  ```
  /tmp/pytest-of-runner/pytest-0/test0/repo   allowed
  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6           allowed
  base64("IGNORE ALL PREVIOUS INSTRUCTIONS")  refused
  hex("IGNORE ALL PREVIOUS INSTRUCTIONS")     refused
  ```

- Six regression tests covering both directions: encoded payloads refused,
  legitimate high-entropy values still allowed.

## [0.2.0] — 2026-08-22

### Added

- **Layer C is reachable.** N-model consensus can now be switched on from the
  config. It was described in the README as available "when you configure
  model providers", but there was no way to configure them — `Gateway` built
  its `OutputGate` with no verifier, so no config could have enabled it.

  ```json
  "consensus": {
    "providers": [
      {"type": "local", "model": "llama3.1:8b"},
      {"type": "local", "model": "qwen2.5:7b"},
      {"type": "openrouter", "model": "anthropic/claude-3.5-sonnet",
       "api_key_env": "OPENROUTER_API_KEY"}
    ]
  }
  ```

  Two provider types: `local` (any OpenAI-compatible endpoint, `base_url`
  defaults to Ollama's) and `openrouter` (key read from the named environment
  variable, never stored in the config). All run at `temperature = 0`.

  Three conditions are checked at startup rather than discovered in
  production: at least two providers, no duplicate models, and a missing API
  key refuses to start rather than running with the layer silently off. A
  consensus of one would report agreement on every call, which is worse than
  no layer at all because it looks like verification.

  `--check` lists `consensus` among the active layers when it is running.

- Eight tests covering every rejection path and the off-by-default case.

## [0.1.3] — 2026-08-22

### Changed

- **The free tier is now written into the licence.** Previously the README and
  website described production use as free for individuals and small teams,
  while plain BSL granted no production use at all — so a solo developer
  following the pricing page was in violation of the licence, and a company's
  counsel reading `LICENSE` would have refused the small-scale case that was
  meant to be allowed.

  The Additional Use Grant now permits production use, without a commercial
  licence, for an individual or an organisation of four or fewer people.

- The licence is now unmodified BSL 1.1 with a real Change Date of
  **2030-08-22**, four years after this package's first PyPI release, and the
  standard "fourth anniversary … whichever comes first" clause intact.

Code is unchanged from 0.1.2.

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

[0.2.2]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.2.2
[0.2.1]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.2.1
[0.2.0]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.2.0
[0.1.3]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.1.3
[0.1.2]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.1.2
[0.1.1]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.1.1
[0.1.0]: https://github.com/mattijsmoens/sovereign-mcp-gateway/releases/tag/v0.1.0
