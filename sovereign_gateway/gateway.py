"""A gating proxy for Model Context Protocol servers.

Point your MCP client at the gateway instead of at your servers. It connects to
every upstream you list, merges their tool catalogues into one, and puts every
tool call through a verification chain before it reaches the server that would
execute it.

    sovereign-mcp-gateway --config gateway.json

The gateway is itself an MCP server, so any client that speaks MCP can use it
with no changes.

Why a proxy rather than a library
---------------------------------
A library has to be adopted by whoever wrote the server. A proxy protects
servers you did not write and cannot modify - which is most of them, since the
useful MCP servers are published packages. It also gives one place to hold
policy and one audit trail across every server an agent can reach, instead of
per-server configuration nobody keeps in sync.

The chain, in order
-------------------
1. **Policy** - is this tool allowed at all? (allow/deny lists, per upstream)
2. **Action gate** - IntentShield, when installed: does this action pass the
   behavioural floor?
3. **Text inspection** - SovereignShield's InputFilter, when installed: the
   22-language pipeline with multi-decode, applied to string arguments. Adds
   encoded and multilingual coverage the deterministic detectors lack.
4. **Frozen verification** - the sovereign-mcp gate: registration, integrity,
   input schema, injection, value constraints, permissions.
5. *the call executes upstream*
6. **Output verification** - schema, deception, PII, content safety, and
   LogicShield rules when configured.
7. **Audit** - one hash-chained record per call, across every upstream.

Steps 2, 3 and 6's LogicShield rules are optional. `pip install
"sovereign-mcp-gateway[all]"` installs every layer; without them the gateway
still runs and reports at startup which layers are active.

Configuration
-------------
    {
      "servers": {
        "git":    {"command": "mcp-server-git", "args": ["--repository", "/repo"]},
        "sqlite": {"command": "mcp-server-sqlite", "args": ["--db-path", "/db"]}
      },
      "policy": {
        "deny_tools":  ["git_push", "sqlite__write_query"],
        "allow_tools": null,
        "pii_policy":  "warn",
        "namespace":   true
      },
      "audit": {"path": "gateway-audit.jsonl"}
    }

With `namespace` on (the default) a tool appears as `git__git_status`, so two
upstreams exposing the same tool name cannot collide or shadow each other.
"""

import json
import logging
import os
import sys
from contextlib import AsyncExitStack

from sovereign_mcp.output_gate import OutputGate
from sovereign_mcp.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

try:
    from mcp import ClientSession, StdioServerParameters, types
    from mcp.client.stdio import stdio_client
    from mcp.server.lowlevel import Server
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "sovereign-mcp-gateway needs the official MCP SDK.\n"
        "    pip install sovereign-mcp-gateway"
    ) from exc

#: Separator between upstream name and tool name. Double underscore keeps the
#: result a valid identifier and is unlikely to appear in a real tool name.
NAMESPACE_SEP = "__"

DEFAULT_POLICY = {
    "deny_tools": [],
    "allow_tools": None,      # None means "everything not denied"
    "pii_policy": "warn",
    "risk_level": "HIGH",
    "namespace": True,
    "fail_closed": True,
    # 0 disables the behavioural floor's own inter-action delay. A proxy sees
    # legitimate bursts; the per-tool limits in the frozen registry are the
    # right place to throttle.
    "rate_limit_interval": 0,
    # The text filter's entropy heuristic looks for encoded payloads hidden in
    # prose. Tool arguments are frequently structured - paths, identifiers,
    # hashes, query strings - where high entropy is normal and expected, so
    # applying a prose detector to them produces false refusals. A temporary
    # directory path is enough to trip it. Warn by default; "block" restores
    # the strict behaviour for deployments whose arguments really are prose.
    "entropy_policy": "warn",
}


class GatewayError(Exception):
    """Configuration or startup failure, phrased for an operator."""


# ---------------------------------------------------------------------------
# Optional layers - present only if the sibling packages are installed
# ---------------------------------------------------------------------------

def _load_input_filter():
    """SovereignShield's multilingual text pipeline, if available."""
    try:
        from sovereign_shield import InputFilter
    except Exception:                                   # noqa: BLE001
        return None
    try:
        return InputFilter()
    except Exception as exc:                            # noqa: BLE001
        logger.warning("InputFilter unavailable: %s", exc)
        return None


def _load_intent_shield():
    """IntentShield's behavioural floor, if available.

    Uses `CoreSafety.audit_action` directly rather than the `IntentShield`
    facade, because the facade applies a 0.5s minimum interval between
    actions. That is right for one agent taking deliberate steps and wrong
    for a proxy: an agent issuing a normal burst of tool calls would have
    every call after the first rejected as rate limited. The gateway does its
    own rate limiting through the frozen registry, so the interval is
    disabled here and exposed as `policy.rate_limit_interval` for anyone who
    wants it back.
    """
    try:
        from intentshield import CoreSafety
    except Exception:                                   # noqa: BLE001
        return None
    return CoreSafety


def _load_logic_shield(rules_config):
    """LogicShield, if available and rules were configured."""
    if not rules_config:
        return None
    try:
        from logicshield import LogicShield, Rule
    except Exception:                                   # noqa: BLE001
        logger.warning("LogicShield rules configured but the package is not "
                       "installed; output rules will not run.")
        return None
    rules = []
    for spec in rules_config:
        factory = getattr(Rule, spec.get("rule", ""), None)
        if factory is None:
            logger.warning("Unknown LogicShield rule %r - skipped", spec.get("rule"))
            continue
        try:
            rules.append(factory(*spec.get("args", []), **spec.get("kwargs", {})))
        except Exception as exc:                        # noqa: BLE001
            logger.warning("Rule %r could not be built: %s", spec.get("rule"), exc)
    return LogicShield(rules) if rules else None


def _load_consensus(spec):
    """Build Layer C from config, or return None when it is not configured.

    Layer C asks several independent models to extract the same structured
    document from a tool's output, canonicalises each answer and compares the
    hashes. It is the only layer that talks to a model, so it is off unless
    asked for, and it is the only one that adds latency and cost per call.

    Config shape::

        "consensus": {
          "providers": [
            {"type": "local",      "model": "llama3.1:8b"},
            {"type": "local",      "model": "qwen2.5:7b",
             "base_url": "http://localhost:11434/v1"},
            {"type": "openrouter", "model": "anthropic/claude-3.5-sonnet",
             "api_key_env": "OPENROUTER_API_KEY"}
          ]
        }

    At least two providers are required - a single model cannot disagree with
    itself, and a "consensus" of one would report agreement on every call.
    """
    if not spec:
        return None
    providers_spec = spec.get("providers") or []
    if len(providers_spec) < 2:
        raise GatewayError(
            "consensus.providers needs at least two entries; got %d. One model "
            "cannot disagree with itself, so a single provider would report "
            "agreement on every call." % len(providers_spec))

    try:
        from sovereign_mcp.consensus import (
            ConsensusVerifier, LocalMCPProvider, OpenRouterMCPProvider)
    except Exception as exc:                            # noqa: BLE001
        raise GatewayError("Layer C is configured but unavailable: %s" % exc)

    built, seen = [], set()
    for entry in providers_spec:
        kind = (entry.get("type") or "").lower()
        model = entry.get("model")
        if not model:
            raise GatewayError("each consensus provider needs a `model`.")
        if model in seen:
            raise GatewayError(
                "consensus provider %r is listed twice. Agreement between two "
                "instances of the same model is not independent verification."
                % model)
        seen.add(model)
        if kind == "local":
            built.append(LocalMCPProvider(
                model, base_url=entry.get("base_url", "http://localhost:11434/v1")))
        elif kind == "openrouter":
            env = entry.get("api_key_env", "OPENROUTER_API_KEY")
            key = os.environ.get(env)
            if not key:
                raise GatewayError(
                    "consensus provider %r needs an API key in $%s, which is "
                    "not set. Refusing to start rather than silently running "
                    "without Layer C." % (model, env))
            built.append(OpenRouterMCPProvider(model, key))
        else:
            raise GatewayError(
                "unknown consensus provider type %r - expected 'local' or "
                "'openrouter'." % entry.get("type"))

    return ConsensusVerifier(built[0], built[1],
                             consensus_models=built[2:] or None)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:

    def __init__(self, data, source="<dict>"):
        self.source = source
        servers = data.get("servers")
        if not isinstance(servers, dict) or not servers:
            raise GatewayError(
                "No upstream servers configured. `servers` must be a mapping of "
                "name -> {command, args}, and at least one is required.")
        self.servers = {}
        for name, spec in servers.items():
            if NAMESPACE_SEP in name:
                raise GatewayError(
                    "Upstream name %r may not contain %r - it is the namespace "
                    "separator." % (name, NAMESPACE_SEP))
            if not isinstance(spec, dict) or not spec.get("command"):
                raise GatewayError(
                    "Upstream %r needs a `command`." % name)
            self.servers[name] = spec

        self.policy = dict(DEFAULT_POLICY)
        self.policy.update(data.get("policy") or {})
        if self.policy["pii_policy"] not in ("block", "warn", "off"):
            raise GatewayError(
                "policy.pii_policy must be 'block', 'warn' or 'off', got %r"
                % self.policy["pii_policy"])
        if self.policy["entropy_policy"] not in ("block", "warn"):
            raise GatewayError(
                "policy.entropy_policy must be 'block' or 'warn', got %r"
                % self.policy["entropy_policy"])
        self.audit_path = (data.get("audit") or {}).get("path")
        self.logic_rules = data.get("output_rules") or []
        self.consensus = data.get("consensus") or None

    @classmethod
    def load(cls, path):
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            raise GatewayError("No such config file: %s" % path)
        except json.JSONDecodeError as exc:
            raise GatewayError("Config file %s is not valid JSON: %s" % (path, exc))
        return cls(data, source=path)


# ---------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------

class Gateway:
    """Holds the upstream sessions, the merged catalogue and the gate."""

    def __init__(self, config):
        self.config = config
        self.sessions = {}          # upstream name -> ClientSession
        self.routes = {}            # exposed name -> (upstream, real tool name)
        self.tools = []             # merged catalogue, as exposed
        self.gate = None
        self._input_filter = None
        self._intent = None
        self._logic = None
        self._consensus = None
        self._audit = None

    # -- startup --------------------------------------------------------

    async def connect(self, stack):
        """Open every upstream session and build the merged catalogue."""
        from sovereign_mcp.integrations.mcp_sdk import _to_frozen_schema, _schema_of

        namespace = self.config.policy["namespace"]
        registry = ToolRegistry()

        for name, spec in self.config.servers.items():
            params = StdioServerParameters(
                command=spec["command"],
                args=list(spec.get("args") or []),
                env=spec.get("env"),
                cwd=spec.get("cwd"),
            )
            try:
                read_stream, write_stream = await stack.enter_async_context(
                    stdio_client(params))
                session = await stack.enter_async_context(
                    ClientSession(read_stream, write_stream))
                await session.initialize()
                listed = await session.list_tools()
            except Exception as exc:                    # noqa: BLE001
                raise GatewayError(
                    "Upstream %r failed to start or speak MCP.\n"
                    "  command: %s %s\n"
                    "  error:   %s: %s\n\n"
                    "Check the command runs on its own and stays running."
                    % (name, spec["command"], " ".join(spec.get("args") or []),
                       type(exc).__name__, str(exc)[:200])) from exc

            self.sessions[name] = session
            for tool in listed.tools:
                exposed = (name + NAMESPACE_SEP + tool.name) if namespace else tool.name
                if exposed in self.routes:
                    raise GatewayError(
                        "Tool name collision on %r. Two upstreams expose it and "
                        "namespacing is off; set policy.namespace to true."
                        % exposed)
                self.routes[exposed] = (name, tool.name)
                self.tools.append(_rename(tool, exposed))
                registry.register_tool(
                    name=exposed,
                    description=tool.description or "",
                    input_schema=_to_frozen_schema(_schema_of(tool, "input")),
                    output_schema=_to_frozen_schema(_schema_of(tool, "output")),
                    risk_level=self.config.policy["risk_level"],
                )
            logger.info("upstream %r: %d tools", name, len(listed.tools))

        if self.config.audit_path:
            from sovereign_mcp.audit_log import AuditLog
            self._audit = AuditLog(self.config.audit_path)

        self._consensus = _load_consensus(self.config.consensus)
        self.gate = OutputGate(
            registry.freeze(),
            consensus_verifier=self._consensus,
            audit_log=self._audit,
            pii_policy=self.config.policy["pii_policy"],
        )
        self._input_filter = _load_input_filter()
        self._intent = _load_intent_shield()
        self._logic = _load_logic_shield(self.config.logic_rules)

        logger.info(
            "gateway ready: %d tools across %d upstreams | layers: %s",
            len(self.tools), len(self.sessions), ", ".join(self.active_layers()))

    def active_layers(self):
        layers = ["policy", "frozen-verify"]
        if self._intent:
            layers.insert(1, "intent")
        if self._input_filter:
            layers.insert(-1, "text-filter")
        if self._consensus:
            layers.append("consensus")
        if self._logic:
            layers.append("logic-rules")
        if self._audit:
            layers.append("audit")
        return layers

    # -- the chain ------------------------------------------------------

    def _policy_check(self, exposed_name):
        policy = self.config.policy
        upstream, real = self.routes.get(exposed_name, (None, None))
        candidates = {exposed_name, real}
        denied = set(policy["deny_tools"] or ())
        if candidates & denied:
            return "policy: %r is on the deny list" % exposed_name
        allowed = policy["allow_tools"]
        if allowed is not None and not (candidates & set(allowed)):
            return "policy: %r is not on the allow list" % exposed_name
        return None

    def _text_check(self, arguments):
        """SovereignShield's pipeline over string arguments."""
        if not self._input_filter:
            return None
        for key, value in (arguments or {}).items():
            if not isinstance(value, str) or not value:
                continue
            try:
                is_safe, reason, _ = self._input_filter.process(value)
            except Exception as exc:                    # noqa: BLE001
                # A filter that errors must not silently pass traffic.
                if self.config.policy["fail_closed"]:
                    return "text filter failed on %r: %s" % (key, exc)
                logger.warning("text filter error on %r: %s", key, exc)
                continue
            if is_safe:
                continue
            if self._is_entropy_only(reason):
                logger.info(
                    "entropy signal on %r allowed by entropy_policy=%r: %s",
                    key, self.config.policy["entropy_policy"], reason)
                continue
            return "text filter: argument %r - %s" % (key, reason)
        return None

    def _is_entropy_only(self, reason):
        """Is this refusal only the entropy heuristic, and are we ignoring it?

        Matched on the reason text because the filter reports a string rather
        than a structured code. That is fragile by nature: if the wording
        changes upstream this stops matching and the gateway becomes stricter,
        not laxer - which is the safe direction for a match to fail in.
        """
        if self.config.policy["entropy_policy"] != "warn":
            return False
        return "entropy" in (reason or "").lower()

    def _intent_check(self, exposed_name, arguments):
        if not self._intent:
            return None
        # The payload the floor inspects is the call rendered as text: the
        # tool name plus its arguments. That is what a shell ban, a delete
        # ban or a credential-URL check needs to see.
        payload = "%s %s" % (
            exposed_name,
            " ".join(str(v) for v in (arguments or {}).values()))
        try:
            ok, reason = self._intent.audit_action(
                "MCP_TOOL_CALL", payload,
                rate_limit_interval=self.config.policy["rate_limit_interval"])
        except Exception as exc:                        # noqa: BLE001
            if self.config.policy["fail_closed"]:
                return "action gate failed: %s" % exc
            logger.warning("action gate error: %s", exc)
            return None
        return None if ok else "action gate: %s" % reason

    def _logic_check(self, result_dict):
        if not self._logic:
            return None
        try:
            outcome = self._logic.validate(result_dict, {})
        except Exception as exc:                        # noqa: BLE001
            logger.warning("output rules error: %s", exc)
            return None
        if getattr(outcome, "valid", True):
            return None
        return "output rules: %s" % "; ".join(getattr(outcome, "errors", []))[:200]

    def _record(self, exposed_name, accepted, layer, reason=""):
        """One audit line per call, allowed or refused."""
        if not self._audit:
            return
        try:
            self._audit.log_verification(
                exposed_name, accepted, layer, 0.0, reason)
        except Exception as exc:                        # noqa: BLE001
            logger.warning("audit write failed for %s: %s", exposed_name, exc)

    async def call(self, exposed_name, arguments):
        """Run the chain and, if it passes, forward to the upstream."""
        import anyio
        from sovereign_mcp.integrations.mcp_sdk import _as_dict

        arguments = dict(arguments or {})

        if exposed_name not in self.routes:
            reason = "unknown tool %r - not exposed by this gateway" % exposed_name
            self._record(exposed_name, False, "routing", reason)
            return _blocked(reason)

        for layer, check in (("policy", self._policy_check(exposed_name)),
                             ("intent", self._intent_check(exposed_name, arguments)),
                             ("text_filter", self._text_check(arguments))):
            if check:
                self._record(exposed_name, False, layer, check)
                return _blocked(check)

        pre = await anyio.to_thread.run_sync(
            lambda: self.gate.verify_call(exposed_name, input_params=arguments))
        if not pre.accepted:
            self._record(exposed_name, False, pre.layer, pre.reason)
            return _blocked("%s: %s" % (pre.layer, pre.reason))

        upstream, real_name = self.routes[exposed_name]
        session = self.sessions[upstream]
        try:
            result = await session.call_tool(real_name, arguments)
        except Exception as exc:                        # noqa: BLE001
            logger.warning("upstream %r failed on %r: %s", upstream, real_name, exc)
            reason = ("upstream %r could not complete the call: %s"
                      % (upstream, str(exc)[:160]))
            self._record(exposed_name, False, "upstream", reason)
            return _blocked(reason)

        as_dict = _as_dict(result)
        post = await anyio.to_thread.run_sync(
            lambda: self.gate.verify(exposed_name, as_dict, input_params=arguments))
        if not post.accepted:
            self._record(exposed_name, False, post.layer, post.reason)
            return _blocked("%s: %s" % (post.layer, post.reason))

        logic = self._logic_check(as_dict)
        if logic:
            self._record(exposed_name, False, "logic_rules", logic)
            return _blocked(logic)

        self._record(exposed_name, True, "passed", "")
        return result


def _rename(tool, exposed):
    """A copy of an upstream tool definition under its exposed name."""
    data = tool.model_dump(by_alias=True)
    data["name"] = exposed
    return type(tool).model_validate(data)


def _blocked(reason):
    logger.warning("gateway declined: %s", reason)
    return types.CallToolResult(
        content=[types.TextContent(
            type="text",
            text="BLOCKED by SovereignShield gateway: %s\n"
                 "This tool call was not executed. Do not retry it unchanged."
                 % reason)],
        isError=True,
    )


# ---------------------------------------------------------------------------
# Serving - the two SDK lines register handlers differently
# ---------------------------------------------------------------------------

def _register(server, gateway):
    """Register tools/list and tools/call on either SDK line.

    1.x keeps a public `request_handlers` dict keyed by request type, with
    handlers taking the whole request. 2.x uses `add_request_handler(method,
    params_type, handler)` with handlers taking `(ctx, params)`.
    """
    adder = getattr(server, "add_request_handler", None)

    if callable(adder):                                  # SDK 2.x
        async def list_handler(ctx, params):
            return types.ListToolsResult(tools=gateway.tools)

        async def call_handler(ctx, params):
            return await gateway.call(params.name, params.arguments)

        adder("tools/list", types.PaginatedRequestParams, list_handler)
        adder("tools/call", types.CallToolRequestParams, call_handler)
        return

    async def list_handler_1x(req):                      # SDK 1.x
        return types.ServerResult(types.ListToolsResult(tools=gateway.tools))

    async def call_handler_1x(req):
        result = await gateway.call(req.params.name, req.params.arguments)
        return types.ServerResult(result)

    server.request_handlers[types.ListToolsRequest] = list_handler_1x
    server.request_handlers[types.CallToolRequest] = call_handler_1x


async def serve(config, name="sovereign-gateway"):
    """Connect the upstreams and serve the gateway over stdio."""
    from mcp.server.stdio import stdio_server

    server = Server(name)
    gateway = Gateway(config)

    async with AsyncExitStack() as stack:
        await gateway.connect(stack)
        _register(server, gateway)
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream,
                server.create_initialization_options())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

USAGE = """sovereign-mcp-gateway - a gating proxy for MCP servers

  sovereign-mcp-gateway --config gateway.json

Your client talks to the gateway; the gateway talks to your servers, and every
tool call goes through the verification chain first.

Options
  --config PATH   Gateway configuration (required).
  --check         Connect, build the catalogue, print it and exit. Use this to
                  confirm the config before pointing a client at it.
  --verbose       Log each declined call and the active layers.

Example config
  {
    "servers": {
      "git": {"command": "mcp-server-git", "args": ["--repository", "/repo"]}
    },
    "policy": {"deny_tools": ["git__git_push"], "pii_policy": "warn"},
    "audit":  {"path": "gateway-audit.jsonl"}
  }
"""


def main(argv=None):
    import anyio

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0

    config_path, check, verbose = None, False, False
    while argv:
        arg = argv.pop(0)
        if arg == "--config":
            config_path = argv.pop(0) if argv else None
        elif arg == "--check":
            check = True
        elif arg == "--verbose":
            verbose = True
        else:
            sys.stderr.write("Unknown option: %s\n\n%s" % (arg, USAGE))
            return 2

    if not config_path:
        sys.stderr.write("--config is required.\n\n%s" % USAGE)
        return 2

    # Logs go to stderr: stdout carries the MCP protocol.
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        config = Config.load(config_path)
    except GatewayError as exc:
        sys.stderr.write("\nCONFIGURATION ERROR\n%s\n" % exc)
        return 2

    if check:
        return _check(config)

    try:
        anyio.run(lambda: serve(config))
    except GatewayError as exc:
        sys.stderr.write("\nSTARTUP FAILED\n%s\n" % exc)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


#: A deliberately trivial document for the startup probe. Two models that
#: cannot agree on this will never agree on real tool output, and every call
#: through the gateway would be refused.
_PROBE_SCHEMA = {"branch": {"type": "string"}, "clean": {"type": "boolean"}}
_PROBE_OUTPUT = {"text": "On branch main\nnothing to commit, working tree clean"}


def probe_consensus(verifier):
    """Run one real consensus call and report whether the models agree.

    Layer C compares canonical hashes of each model's structured answer, so
    two models that are both semantically correct but structurally different
    never agree. A weaker model that echoes the schema back -
    ``{"branch": {"type": "string", "value": "main"}}`` rather than
    ``{"branch": "main"}`` - produces a permanent mismatch, and every call is
    then refused for a reason that correctly reads "the models disagreed",
    because they did.

    Without this probe the first sign of a bad pairing is production refusing
    everything. It costs one real call per configured model.

    Returns (status, detail) where status is "agree", "mismatch" or "error".
    """
    try:
        result = verifier.verify(_PROBE_OUTPUT, _PROBE_SCHEMA)
    except Exception as exc:                            # noqa: BLE001
        return "error", "%s: %s" % (type(exc).__name__, str(exc)[:200])
    if getattr(result, "match", False):
        return "agree", ""
    reason = getattr(result, "reason", "") or ""
    # The verifier distinguishes these in its reason string: a provider that
    # could not be reached reads "Model N (...) error: ...", while a genuine
    # disagreement reads "Consensus MISMATCH: ...". Both refuse, correctly,
    # but only one of them means "look at your config".
    kind = "error" if " error: " in reason else "mismatch"
    return kind, reason[:220]


def _check(config):
    """Dry run: connect, list, report, exit."""
    import anyio

    async def run():
        gateway = Gateway(config)
        async with AsyncExitStack() as stack:
            await gateway.connect(stack)
            return gateway

    try:
        gateway = anyio.run(run)
    except GatewayError as exc:
        sys.stderr.write("\nSTARTUP FAILED\n%s\n" % exc)
        return 2
    except BaseException as exc:                        # noqa: BLE001
        inner = exc
        while getattr(inner, "exceptions", None):
            inner = inner.exceptions[0]
        if isinstance(inner, GatewayError):
            sys.stderr.write("\nSTARTUP FAILED\n%s\n" % inner)
        else:
            sys.stderr.write("\nSTARTUP FAILED\n  %s: %s\n"
                             % (type(inner).__name__, str(inner)[:300]))
        return 2

    print("=" * 74)
    print("SOVEREIGN GATEWAY - configuration check")
    print("=" * 74)
    print("config:   %s" % config.source)
    print("upstreams: %d" % len(gateway.sessions))
    print("layers:   %s" % " -> ".join(gateway.active_layers()))
    print()
    print("%-38s %s" % ("EXPOSED AS", "UPSTREAM TOOL"))
    print("-" * 74)
    denied = set(config.policy["deny_tools"] or ())
    for exposed in sorted(gateway.routes):
        upstream, real = gateway.routes[exposed]
        mark = "  [DENIED]" if ({exposed, real} & denied) else ""
        print("%-38s %s.%s%s" % (exposed[:38], upstream, real, mark))
    if gateway._consensus is not None:
        print()
        print("LAYER C  - probing the configured models with one real call")
        print("-" * 74)
        status, detail = probe_consensus(gateway._consensus)
        if status == "agree":
            print("  OK. The configured models produced identical documents.")
            print("  Layer C will pass ordinary output rather than refusing it.")
        elif status == "mismatch":
            print("  MISMATCH on a trivial document. These models will refuse")
            print("  every call, and the reason will read as disagreement.")
            print("  " + detail)
            print()
            print("  Usually one model echoes the schema instead of filling it.")
            print("  Replace it, or remove the consensus section to run without")
            print("  Layer C rather than with a layer that refuses everything.")
        else:
            print("  A provider could not be reached, so nothing was verified.")
            print("  " + detail)

    print()
    print("%d tools exposed. Point your MCP client at:" % len(gateway.routes))
    print("    sovereign-mcp-gateway --config %s" % config.source)
    return 0


if __name__ == "__main__":
    sys.exit(main())
