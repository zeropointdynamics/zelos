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

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ZelosTest(unittest.TestCase):
    def test_static_elf_unpatched(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), trace_off=True)
        z.start(timeout=3)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_static_elf(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), trace_off=True)
        z.start(timeout=3)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_dynamic_elf(self):
        z = Zelos(
            path.join(DATA_DIR, "ld-linux.so"),
            "./dynamic_elf_helloworld",
            trace_off=True,
        )
        z.internal_engine.files.add_file(
            path.join(DATA_DIR, "dynamic_elf_helloworld")
        )

        z.start(timeout=3)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_dynamic_elf_directly(self):
        z = Zelos(
            path.join(DATA_DIR, "dynamic_elf_helloworld"), trace_off=True
        )
        z.start(timeout=3)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_socket_elf(self):
        z = Zelos(
            path.join(DATA_DIR, "static-socket-x86-musl"), trace_off=True
        )
        z.internal_engine.network.disable_whitelist()
        z.start(timeout=5)

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_mmap1(self):
        z = Zelos(path.join(DATA_DIR, "call_mmap1_i386"), trace_off=True)
        z.start(timeout=5)
        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )


def main():
    unittest.main()


if __name__ == "__main__":
    main()
