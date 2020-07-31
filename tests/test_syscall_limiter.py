# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.


# <http://www.gnu.org/licenses/>.
# ======================================================================

import io
import unittest

from os import path
from unittest.mock import patch

from zelos import Zelos


# from zelos.api.zelos_api import ZelosCmdline

DATA_DIR = path.dirname(path.abspath(__file__))


class SyscallLimiterTest(unittest.TestCase):
    def test_syscall_limit(self):
        z = Zelos(
            path.join(DATA_DIR, "data", "dynamic_elf_helloworld"),
            syscall_limit=5,
        )
        z.start()
        self.assertEqual(z.plugins.syscalllimiter.syscall_cnt, 5)

    def test_thread_limit(self):
        z = Zelos(
            path.join(DATA_DIR, "data", "dynamic_elf_helloworld"),
            syscall_thread_limit=5,
        )
        z.start()
        self.assertEqual(z.plugins.syscalllimiter.syscall_cnt, 5)

    def test_syscall_callback(self):
        z = Zelos(
            path.join(DATA_DIR, "data", "dynamic_elf_helloworld"),
            rep_syscall_print_limit=5,
        )
        syscall_name = "brk"
        args = None
        retval = None

        for _ in range(4):
            z.plugins.syscalllimiter._syscall_callback(
                z, syscall_name, args, retval
            )
        self.assertTrue(z.internal_engine.kernel.should_print_syscalls)

        z.plugins.syscalllimiter._syscall_callback(
            z, syscall_name, args, retval
        )
        self.assertFalse(z.internal_engine.kernel.should_print_syscalls)

        with patch("sys.stdout", new=io.StringIO()) as stdout:
            z.internal_engine.kernel.print("Test")
            z.plugins.trace.trace_syscalls(z, syscall_name, args, retval)
            self.assertEqual(stdout.getvalue(), "")

        different_syscall_name = "mmap"
        z.plugins.syscalllimiter._syscall_callback(
            z, different_syscall_name, args, retval
        )
        self.assertTrue(z.internal_engine.kernel.should_print_syscalls)

    def test_syscall_callback_rep_0(self):
        z = Zelos(
            path.join(DATA_DIR, "data", "dynamic_elf_helloworld"),
            rep_syscall_print_limit=0,
        )
        syscall_name = "brk"
        args = None
        retval = None

        z.plugins.syscalllimiter._syscall_callback(
            z, syscall_name, args, retval
        )
        self.assertTrue(z.internal_engine.kernel.should_print_syscalls)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
