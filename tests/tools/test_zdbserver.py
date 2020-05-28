# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.


# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================

import multiprocessing
import unittest
import xmlrpc

from os import path

import pytest

from zelos.tools.zdbserver import DEFAULT_PORT, create_server


DATA_DIR = path.join(
    path.dirname(path.abspath(__file__)), path.join("..", "data")
)


class Transport(xmlrpc.client.Transport):
    def __init__(self, use_datetime=False, use_builtin_types=False, timeout=1):
        super().__init__(
            use_datetime=use_datetime, use_builtin_types=use_builtin_types
        )
        self.timeout = timeout

    def make_connection(self, host):
        conn = super(Transport, self).make_connection(host)
        conn.timeout = self.timeout
        return conn


def server_process(target, srv_ready, srv_error):
    try:
        rpc_server = create_server(["--virtual_filename=test", target])
        srv_ready.set()
        rpc_server.serve_forever()
    except Exception as e:
        print("start_server Exception:", e)
        srv_error.set()
        srv_ready.set()


class TestZdbServer(unittest.TestCase):
    def start_server(
        self,
        server_url=f"http://localhost:{DEFAULT_PORT}",
        target=path.join(DATA_DIR, "static_elf_helloworld"),
    ) -> (multiprocessing.Process, xmlrpc.client.ServerProxy):

        srv_ready = multiprocessing.Event()
        srv_error = multiprocessing.Event()
        srv = multiprocessing.Process(
            target=server_process, args=(target, srv_ready, srv_error)
        )
        srv.start()
        srv_ready.wait(10)
        self.assertTrue(srv_ready.is_set())
        self.assertFalse(srv_error.is_set())

        rpc = xmlrpc.client.ServerProxy(
            server_url, transport=Transport(timeout=10)
        )

        return srv, rpc

    def stop_server(
        self, srv: multiprocessing.Process, rpc: xmlrpc.client.ServerProxy
    ) -> None:
        rpc.server_shutdown()
        srv.join(5)
        self.assertFalse(srv.is_alive())
        if srv.is_alive():
            srv.terminate()

    @pytest.mark.usefixtures("serial")
    def test_server_connect(self):
        proc, rpc = self.start_server()
        self.stop_server(proc, rpc)

    @pytest.mark.usefixtures("serial")
    def test_server_api(self):
        # Do this all in one test so we're not creating many
        # sub-processes.
        proc, zdb = self.start_server()
        zdb_exception = None

        try:
            self.assertEqual(
                zdb.get_filepath(),
                path.abspath(path.join(DATA_DIR, "static_elf_helloworld")),
            )

            # Test syscall breaks
            zdb.set_syscall_breakpoint("brk")
            break_state = zdb.run()
            del break_state["syscall"]["retval"]  # address may change
            self.assertEqual(
                str(break_state),
                "{'pc': '0x815b577', 'syscall': {'name': 'brk', 'args': "
                "[{'type': 'void*', 'name': 'addr', 'value': '0x0'}], "
                "'retval_register': 'eax'}, 'bits': 32}",
            )

            # Test syscall break argument values
            break_state = zdb.run()
            brk_target_addr = int(
                break_state["syscall"]["args"][0]["value"], 16
            )
            # Address may change, so just check it is non-zero
            self.assertNotEqual(0, brk_target_addr)

            zdb.remove_syscall_breakpoint("brk")

            # Test address breaks
            zdb.set_breakpoint("0x080eccf7", False)
            break_state = zdb.run()
            self.assertEqual(
                str(break_state),
                "{'pc': '0x80eccf7', 'syscall': {}, 'bits': 32}",
            )
            zdb.remove_breakpoint("0x080eccf7")

            # Test read/write register
            pc = int(zdb.read_register("pc"), 16)
            self.assertEqual(pc, 0x80ECCF7)
            zdb.write_register("pc", "0xdeadbeef")
            pc = int(zdb.read_register("eip"), 16)
            self.assertEqual(pc, 0xDEADBEEF)
            zdb.write_register("eip", "0x80eccf7")
            pc = int(zdb.read_register("pc"), 16)
            self.assertEqual(pc, 0x80ECCF7)

            ecx = int(zdb.read_register("ecx"), 16)
            self.assertEqual(ecx, 0x81E9CA0)

            # Test memory map list
            mappings = zdb.get_mappings()
            self.assertEqual(len(mappings), 21)
            mr = mappings[0]
            self.assertTrue("start_address" in mr)
            self.assertTrue("end_address" in mr)

            # Test memory write by modifying a `write` buffer just
            # before the syscall.
            zdb.set_breakpoint("0x08106b04", True)
            break_state = zdb.run()
            buf = zdb.read_register("edi")
            zdb.write_memory(buf, b"Hello World! I'm a Zelos Test!")

            # Test memory read, write (continued)
            zdb.set_syscall_breakpoint("write")
            break_state = zdb.run()
            buf = break_state["syscall"]["args"][1]["value"]
            count = int(break_state["syscall"]["args"][2]["value"], 16)
            stdout = zdb.read_memory(buf, count)
            self.assertEqual(stdout, b"Hello World! I'm a Zelos Test!")

            # Test watchpoint
            addr = 0x081E9934
            zdb.set_watchpoint(f"0x{addr:x}", True, True, False)
            break_state = zdb.run()
            self.assertEqual("0x81096f3", zdb.read_register("pc"))
            zdb.remove_watchpoint(f"0x{addr:x}")

            # Run until program end
            break_state = zdb.run()
            self.assertEqual(break_state, {})

            zdb.stop()

        except Exception as e:
            zdb_exception = e

        finally:
            self.stop_server(proc, zdb)

        if zdb_exception is not None:
            self.fail("test_server_api error: " + str(zdb_exception))


if __name__ == "__main__":
    unittest.main()
