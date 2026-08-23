"""`--init` builds a gateway.json from the MCP config the user already has.

The gateway is a proxy, so without a config listing upstreams it exits with a
configuration error on first launch. Every distribution channel (the MCP
registry, Claude Code plugins, .mcpb bundles) assumes "install it and it runs",
and that mismatch turns installs into uninstalls. `--init` closes it.

Four behaviours are worth pinning, and three of them are traps:

* importing the gateway's own entry would make it proxy itself, which is easy to
  hit on a second `--init` after the client has been pointed at the gateway;
* remote/SSE entries have no `command`, so they cannot be launched as a
  subprocess and must be skipped rather than written out broken;
* the same server usually appears in more than one client, and a duplicate name
  would silently overwrite;
* a name containing the namespace separator would collide with the
  `upstream__tool` scheme.
"""

import json
import os
import tempfile
import unittest

from sovereign_gateway import gateway as gw


class InitTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.tmp)
        self._env = {k: os.environ.get(k) for k in ("HOME", "APPDATA", "USERPROFILE")}
        # Point discovery at an empty home so a developer's real Claude Desktop
        # config cannot leak into the assertions.
        empty = os.path.join(self.tmp, "empty-home")
        os.makedirs(empty)
        for k in ("HOME", "APPDATA", "USERPROFILE"):
            os.environ[k] = empty

    def tearDown(self):
        os.chdir(self.cwd)
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _write_cursor(self, servers):
        os.makedirs(os.path.join(self.tmp, ".cursor"), exist_ok=True)
        with open(os.path.join(self.tmp, ".cursor", "mcp.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"mcpServers": servers}, fh)

    def _config(self):
        with open(os.path.join(self.tmp, "gateway.json"), encoding="utf-8") as fh:
            return json.load(fh)

    # ------------------------------------------------------------------ paths

    def test_writes_a_template_when_nothing_is_configured(self):
        self.assertEqual(gw.main(["--init"]), 0)
        cfg = self._config()
        self.assertTrue(cfg["servers"], "template must contain example servers")
        # And it must be a config the gateway itself accepts.
        gw.Config.load("gateway.json")

    def test_imports_servers_from_a_client_config(self):
        self._write_cursor({
            "git": {"command": "mcp-server-git", "args": ["--repository", "/r"]},
            "sqlite": {"command": "mcp-server-sqlite"},
        })
        self.assertEqual(gw.main(["--init"]), 0)
        cfg = self._config()
        self.assertEqual(sorted(cfg["servers"]), ["git", "sqlite"])
        self.assertEqual(cfg["servers"]["git"]["args"], ["--repository", "/r"])
        gw.Config.load("gateway.json")

    # ------------------------------------------------------------------ traps

    def test_never_imports_itself(self):
        """Importing the gateway's own entry would proxy the gateway."""
        self._write_cursor({
            "git": {"command": "mcp-server-git"},
            "sovereign": {"command": "sovereign-mcp-gateway",
                          "args": ["--config", "gateway.json"]},
        })
        gw.main(["--init"])
        servers = self._config()["servers"]
        self.assertIn("git", servers)
        self.assertNotIn("sovereign", servers)
        for spec in servers.values():
            self.assertNotIn("sovereign-mcp-gateway", spec.get("command", ""))

    def test_skips_entries_with_no_command(self):
        """Remote/SSE servers cannot be launched as a subprocess."""
        self._write_cursor({
            "git": {"command": "mcp-server-git"},
            "remote": {"url": "https://example.com/sse"},
        })
        gw.main(["--init"])
        self.assertEqual(sorted(self._config()["servers"]), ["git"])

    def test_sanitises_the_namespace_separator(self):
        self._write_cursor({"weird%sname" % gw.NAMESPACE_SEP: {"command": "x"}})
        gw.main(["--init"])
        for name in self._config()["servers"]:
            self.assertNotIn(gw.NAMESPACE_SEP, name)
        # a name carrying the separator would break upstream__tool addressing
        gw.Config.load("gateway.json")

    def test_duplicate_names_across_clients_are_not_overwritten(self):
        self._write_cursor({"git": {"command": "mcp-server-git", "args": ["--first"]}})
        os.makedirs(os.path.join(self.tmp, ".vscode"), exist_ok=True)
        with open(os.path.join(self.tmp, ".vscode", "mcp.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"servers": {"git": {"command": "mcp-server-git",
                                           "args": ["--second"]}}}, fh)
        gw.main(["--init"])
        servers = self._config()["servers"]
        self.assertEqual(list(servers), ["git"])
        self.assertEqual(servers["git"]["args"], ["--first"],
                         "the first client seen should win, not the last")

    # ---------------------------------------------------------------- safety

    def test_refuses_to_overwrite_without_force(self):
        gw.main(["--init"])
        with open("gateway.json", encoding="utf-8") as fh:
            before = fh.read()
        self.assertEqual(gw.main(["--init"]), 2)
        with open("gateway.json", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before, "file was modified anyway")

    def test_force_overwrites(self):
        gw.main(["--init"])
        self.assertEqual(gw.main(["--init", "--force"]), 0)

    def test_honours_an_explicit_path(self):
        self.assertEqual(gw.main(["--init", "--config", "custom.json"]), 0)
        self.assertTrue(os.path.exists("custom.json"))
        self.assertFalse(os.path.exists("gateway.json"))

    def test_malformed_client_config_does_not_crash(self):
        os.makedirs(os.path.join(self.tmp, ".cursor"), exist_ok=True)
        with open(os.path.join(self.tmp, ".cursor", "mcp.json"), "w",
                  encoding="utf-8") as fh:
            fh.write("{ this is not json")
        self.assertEqual(gw.main(["--init"]), 0)
        gw.Config.load("gateway.json")


if __name__ == "__main__":
    unittest.main()
