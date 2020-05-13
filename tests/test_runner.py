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

from __future__ import absolute_import

import unittest

from os import path

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class RunnerTest(unittest.TestCase):
    def test_run_to_addr(self):
        z = Zelos(path.join(DATA_DIR, "dynamic_elf_helloworld"))
        z.internal_engine.thread_manager.swap_with_thread("main")

        z.plugins.runner.run_to_addr(0x0B01B3CA)
        self.assertEqual(z.thread.getIP(), 0x0B01B3CA)

    def test_stop_when(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.internal_engine.thread_manager.swap_with_thread("main")

        def stop():
            # stop when we reach `uname` at 0x81356e2
            if z.regs.getIP() == 0x81356E2:
                return True

        z.plugins.runner.stop_when(stop)
        z.start()
        self.assertEqual(z.thread.getIP(), 0x081356E2)

    def test_run_to_ret(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.internal_engine.thread_manager.swap_with_thread("main")

        z.step()
        z.plugins.runner.next_ret()
        self.assertEqual(str(z.thread.getIP()), str(0x08048B80))

    def test_run_to_next_write(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.internal_engine.thread_manager.swap_with_thread("main")

        z.plugins.runner.next_write(0xFF08EDD0)
        t = z.thread
        self.assertEqual(
            t.getIP(), 0x8135778, f"IP is 0x{t.getIP():x} vs. 0x8135778"
        )


def main():
    unittest.main()


if __name__ == "__main__":
    main()
