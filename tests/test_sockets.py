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

import socket
import unittest

from os import path

from zelos import HookType, Zelos
from zelos.network.base_socket import BaseSocket


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ZelosTest(unittest.TestCase):
    def test_dga_example(self):
        z = Zelos(path.join(DATA_DIR, "dns_socket_test"), trace_off=True)
        syscalls_called = []

        def record_syscalls(z, syscall_name, args, return_value):
            syscalls_called.append(syscall_name)

        z.hook_syscalls(HookType.SYSCALL.AFTER, record_syscalls, "test_hook")

        z.start(timeout=3)

        self.assertIn("socket", syscalls_called)
        self.assertIn("connect", syscalls_called)
        self.assertIn("sendto", syscalls_called)
        self.assertIn("select", syscalls_called)
        self.assertIn("recvfrom", syscalls_called)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_base_socket(self):
        s = BaseSocket(
            None, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP
        )

        s.setsockopt(0, 1, False)
        self.assertFalse(s.getsockopt(0, 1))
        s.set_nonblock(True)
        self.assertTrue(s.is_nonblock())
        s.connect(("127.0.0.1", 1))
        self.assertEqual(len(s.history["connect"]), 1)
        self.assertEqual(s.host, "127.0.0.1")
        self.assertEqual(s.port, 1)
        self.assertEqual(s.close(), None)
        s.bind(("127.0.0.2", 2))
        self.assertEqual(len(s.history["bind"]), 1)
        self.assertEqual(s.host, "127.0.0.2")
        self.assertEqual(s.port, 2)
        self.assertEqual(s.listen(), 0)
        self.assertEqual(s.accept(), 0)
        self.assertEqual(s.peek(), b"0")
        self.assertEqual(s.send(bytes(1)), 1)
        self.assertEqual(s.recv(1, 0), b"0")
        self.assertEqual(s.recvfrom(1), (b"0", socket.AF_INET, "127.0.0.2", 2))
        self.assertEqual(s.sendto(bytes(1), (None, None)), 1)
        self.assertEqual(len(s.history["sendto"]), 1)
        self.assertEqual(s.shutdown(0), None)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
