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

# import io
import unittest

from os import path

from zelos import Zelos


# from zelos.api.zelos_api import ZelosCmdline

DATA_DIR = path.dirname(path.abspath(__file__))


class SyscallLimiterTest(unittest.TestCase):
    def test_syscall_limit(self):
        z = Zelos(
            path.join(DATA_DIR, "data", "static_elf_helloworld"),
            syscall_limit=5,
        )
        z.start()
        self.assertEqual(
            z.internal_engine.plugins.syscalllimiter.syscall_cnt, 5
        )

    def test_thread_limit(self):
        z = Zelos(
            path.join(DATA_DIR, "data", "static_elf_helloworld"),
            syscall_thread_limit=5,
        )
        z.start()
        self.assertEqual(
            z.internal_engine.plugins.syscalllimiter.syscall_cnt, 5
        )

    # def test_syscall_limit_plugin(self):

    #     filepath = path.join(DATA_DIR, "data", "static_elf_helloworld")
    #     z = ZelosCmdline(f"--syscall_limit 5 {filepath}")
    #     z.start()

    #     self.assertEqual(
    #         z.internal_engine.plugins.syscalllimiter.syscall_cnt, 5
    #     )


def main():
    unittest.main()


if __name__ == "__main__":
    main()
