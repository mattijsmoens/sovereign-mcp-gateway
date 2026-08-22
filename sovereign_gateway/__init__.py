"""A gating proxy for Model Context Protocol servers.

    sovereign-mcp-gateway --config gateway.json

See `sovereign_gateway.gateway` for the chain and the configuration format.
"""

__version__ = "0.1.2"

__all__ = ["Config", "Gateway", "GatewayError", "serve", "main"]


def __getattr__(name):
    # Lazy so `import sovereign_gateway` does not require the MCP SDK just to
    # read the version.
    if name in __all__:
        from sovereign_gateway import gateway
        return getattr(gateway, name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
