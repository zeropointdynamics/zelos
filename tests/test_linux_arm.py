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
import os
import unittest

from os import path

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ZelosTest(unittest.TestCase):
    def test_static_elf_verbose(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"))
        z.internal_engine.set_verbose(True)
        z.internal_engine.trace.threads_to_print.add("none")
        z.internal_engine.start(timeout=3)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_static_elf(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"))
        z.internal_engine.trace.threads_to_print.add("none")
        z.internal_engine.start(timeout=10)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_dynamic_elf(self):
        if os.name == "nt":
            raise unittest.SkipTest(
                "Skipping `test_dynamic_elf`: "
                "Windows fatal exception: access violation"
            )
        z = Zelos(path.join(DATA_DIR, "dynamic_elf_arm_helloworld"))
        z.internal_engine.trace.threads_to_print.add("none")
        z.internal_engine.start(timeout=10)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )


def main():
    unittest.main()


if __name__ == "__main__":
    main()
