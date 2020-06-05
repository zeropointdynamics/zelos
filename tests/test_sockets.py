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

import unittest

from os import path

from zelos import HookType, Zelos


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


def main():
    unittest.main()


if __name__ == "__main__":
    main()
