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
from __future__ import absolute_import

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
import unittest

from unicorn import UC_ARCH_X86, UC_MODE_32, Uc

from zelos import Zelos
from zelos.memory import Memory, OutOfMemoryException, Section


class MemoryTest(unittest.TestCase):
    def test_memory_manager_map_anywhere(self):
        mm = Memory(Uc(UC_ARCH_X86, UC_MODE_32), None, 32)
        address1 = mm.map_anywhere(0x1000, "name1", "size1")

        self.assertEqual(
            mm.memory_info[address1],
            Section(mm.emu, address1, 0x1000, "name1", "size1", ""),
        )

        address2 = mm.map_anywhere(0x2000, "name2", "size2")

        self.assertEqual(
            mm.memory_info[address1],
            Section(mm.emu, address1, 0x1000, "name1", "size1", ""),
        )
        self.assertEqual(
            mm.memory_info[address2],
            Section(mm.emu, address2, 0x2000, "name2", "size2", ""),
        )

        mm.unmap(address1, 0x1000)
        self.assertNotIn(address1, mm.memory_info)
        self.assertEqual(
            mm.memory_info[address2],
            Section(mm.emu, address2, 0x2000, "name2", "size2", ""),
        )

    def test_map_anywhere_bounded(self):
        # Check mapping when given bounds
        mm = Memory(Uc(UC_ARCH_X86, UC_MODE_32), None, 32)
        min_addr = 0x10000
        max_addr = 0x12000
        address1 = mm.map_anywhere(
            0x1000,
            min_addr=min_addr,
            max_addr=max_addr,
            name="name1",
            kind="size1",
        )

        self.assertEqual(
            mm.memory_info[address1],
            Section(mm.emu, address1, 0x1000, "name1", "size1", ""),
        )
        self.assertGreaterEqual(address1, min_addr)
        self.assertLessEqual(address1, max_addr)

    def test_map_anywhere_bounded_preexisting_sections(self):
        mm = Memory(Uc(UC_ARCH_X86, UC_MODE_32), None, 32)
        mm.map(0x10000, 0x1000)
        mm.map(0x15000, 0x1000)
        min_addr = 0x12000
        max_addr = 0x14000
        address1 = mm.map_anywhere(
            0x1000,
            min_addr=min_addr,
            max_addr=max_addr,
            name="name1",
            kind="size1",
        )

        self.assertEqual(
            mm.memory_info[address1],
            Section(mm.emu, address1, 0x1000, "name1", "size1", ""),
        )
        self.assertGreaterEqual(address1, min_addr)
        self.assertLessEqual(address1, max_addr)

    def test_alloc_at(self):
        z = Zelos(None)
        mm = z.internal_engine.memory
        mm._alloc_at(
            "Test1",
            "test_mem",
            "main_module",
            0x400000,
            0x10000,
            min_addr=0x400000,
            max_addr=0x500000,
        )
        mm._alloc_at(
            "Test2",
            "test_mem",
            "main_module",
            0x400000,
            0x10000,
            min_addr=0x400000,
            max_addr=0x500000,
        )
        mm._alloc_at(
            "Test3",
            "test_mem",
            "main_module",
            0x410000,
            0x10000,
            min_addr=0x400000,
            max_addr=0x500000,
        )
        self.assertEqual(mm.memory_info[0x400000].name, "Test1")
        self.assertEqual(mm.memory_info[0x410000].name, "Test2")
        self.assertEqual(mm.memory_info[0x420000].name, "Test3")

    def test_read_int(self):
        z = Zelos(None)
        mm = z.internal_engine.memory
        mm.map(0x88880000, 0x1000)
        mm.write(0x88880000, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a")

        self.assertEqual(mm.read_int(0x88880000, 1), 0x01)
        self.assertEqual(mm.read_int(0x88880000, 2), 0x0201)
        self.assertEqual(mm.read_int(0x88880000, 4), 0x04030201)
        self.assertEqual(mm.read_int(0x88880000, 8), 0x0807060504030201)
        self.assertRaises(Exception, mm.read_int, 0x88880000, 3)

    def test_write_int(self):
        z = Zelos(None)
        mm = z.internal_engine.memory
        mm.map(0x88880000, 0x1000)
        mm.write(0x88880004, b"\x00\x00\x00\x00")

        mm.write_int(0x88880000, 0x0807060504030201)
        self.assertEqual(mm.read(0x88880000, 5), b"\x01\x02\x03\x04\x00")

        mm.write_int(0x88880000, 0x121110, 2)
        self.assertEqual(mm.read(0x88880000, 4), b"\x10\x11\x03\x04")

        mm.write_int(0x88880000, 0x0101, 1)
        self.assertEqual(mm.read(0x88880000, 2), b"\x01\x11")

    def test_read_writeint(self):
        z = Zelos(None)
        mm = z.internal_engine.memory

        address1 = mm.map_anywhere(0x1000, "name1", "size1")
        mm.write_int(address1, 10)
        self.assertEqual(10, z.internal_engine.memory.read_int(address1))

        self.assertEqual(10, mm.read_int(address1))

    def test_str_methods(self):
        z = Zelos(None)
        mm = z.internal_engine.memory
        mm.map(0x10000, 0x1000)
        mm.write(0x10000, b"\xff" * 0x100)
        mm.write_string(0x10004, "TestString")
        self.assertEqual(mm.read_string(0x10004), "TestString")
        self.assertEqual(
            mm.read(0x10004, len("TestString") + 2),
            "TestString\x00".encode() + b"\xff",
        )

        mm.write_string(0x10024, "TestString", terminal_null_byte=False)
        self.assertEqual(
            mm.read(0x10024, len("TestString") + 1),
            "TestString".encode() + b"\xff",
        )
        self.assertEqual(
            mm.read_string(0x10024, size=len("TestString")), "TestString"
        )

    def test_wstr_methods(self):
        z = Zelos(None)
        mm = z.internal_engine.memory
        mm.map(0x10000, 0x1000)
        mm.write(0x10000, b"\xff" * 0x100)
        mm.write_wstring(0x10004, "Test")
        self.assertEqual(
            mm.read(0x10004, len("Test") * 2 + 3),
            b"T\x00e\x00s\x00t\x00\x00\x00" + b"\xff",
        )
        self.assertEqual(mm.read_wstring(0x10004), "Test")

        mm.write_wstring(0x10024, "Test", terminal_null_byte=False)
        self.assertEqual(
            mm.read(0x10024, len("Test") * 2 + 1),
            "T\x00e\x00s\x00t\x00".encode() + b"\xff",
        )
        self.assertEqual(
            mm.read_wstring(0x10024, size=len("Test") * 2), "Test"
        )

    def test_memory_failure(self):
        z = Zelos(None)
        mm = z.internal_engine.memory
        z.internal_engine.thread_manager.logger.warning("Testing logging")

        with self.assertRaises(OutOfMemoryException):
            mm.map(0x1000, 1024 * 1024 * 1024 * 10)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
