import json
import tempfile
import unittest
from unittest.mock import patch

from ida_pro_mcp.idalib_pool_manager import InstanceInfo, InstanceManager
from ida_pro_mcp import idalib_pool_server


class _FakeProcess:
    pid = 1234
    returncode = None

    def poll(self):
        return None

    def send_signal(self, _signal):
        return None

    def wait(self, timeout=None):
        return 0

    def kill(self):
        return None


class _FakeResponse:
    status = 200

    def read(self):
        return b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'


class _FakeHTTPConnection:
    instances = []

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.requests = []
        self.closed = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def request(self, method, path, body, headers):
        self.requests.append((method, path, json.loads(body), headers))

    def getresponse(self):
        return _FakeResponse()

    def close(self):
        self.closed = True


class InstanceTransportTests(unittest.TestCase):
    def test_auto_uses_tcp_when_unix_sockets_are_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("ida_pro_mcp.idalib_pool_manager._supports_unix_sockets", return_value=False):
                manager = InstanceManager(tmp, instance_transport="auto")

        self.assertEqual(manager.instance_transport, "tcp")

    def test_explicit_unix_fails_when_unix_sockets_are_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("ida_pro_mcp.idalib_pool_manager._supports_unix_sockets", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "Unix domain sockets"):
                    InstanceManager(tmp, instance_transport="unix")

    def test_tcp_spawn_assigns_unique_backend_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = InstanceManager(tmp, instance_transport="tcp", backend_host="127.0.0.1")
            with patch.object(manager, "_find_free_tcp_port", return_value=49152):
                with patch.object(manager, "_wait_for_ready"):
                    with patch("ida_pro_mcp.idalib_pool_manager.ensure_idadir", return_value=None):
                        with patch(
                            "ida_pro_mcp.idalib_pool_manager.subprocess.Popen",
                            return_value=_FakeProcess(),
                        ) as popen:
                            inst = manager.spawn()
                            try:
                                cmd = popen.call_args.args[0]
                                self.assertEqual(inst.transport, "tcp")
                                self.assertEqual(inst.host, "127.0.0.1")
                                self.assertEqual(inst.port, 49152)
                                self.assertIn("--host", cmd)
                                self.assertIn("127.0.0.1", cmd)
                                self.assertIn("--port", cmd)
                                self.assertIn("49152", cmd)
                                self.assertNotIn("--unix-socket", cmd)
                            finally:
                                getattr(inst, "_log_file").close()

    def test_forward_raw_uses_tcp_endpoint(self):
        _FakeHTTPConnection.reset()
        with tempfile.TemporaryDirectory() as tmp:
            manager = InstanceManager(tmp, instance_transport="tcp")
            inst = InstanceInfo(
                index=7,
                process=_FakeProcess(),
                log_path="unused.log",
                host="127.0.0.1",
                port=49153,
            )
            request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            with patch(
                "ida_pro_mcp.idalib_pool_manager.http.client.HTTPConnection",
                _FakeHTTPConnection,
            ):
                response = manager.forward_raw(inst, request)

        self.assertEqual(response["result"], {"ok": True})
        self.assertEqual(len(_FakeHTTPConnection.instances), 1)
        conn = _FakeHTTPConnection.instances[0]
        self.assertEqual(conn.host, "127.0.0.1")
        self.assertEqual(conn.port, 49153)
        self.assertTrue(conn.closed)
        self.assertEqual(conn.requests[0][0:2], ("POST", "/mcp"))


class ZeromcpImportTests(unittest.TestCase):
    def test_pool_server_imports_without_unix_socket_support(self):
        self.assertTrue(hasattr(idalib_pool_server._mcp_mod, "McpServer"))


if __name__ == "__main__":
    unittest.main()
