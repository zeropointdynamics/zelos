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

from zelos import Zelos


class HeapManagerTest(unittest.TestCase):
    def test_alloc(self):
        z = Zelos(None)
        heap = z.internal_engine.memory.heap

        addr1 = heap.alloc(0x10, name="obj1")
        addr2 = heap.alloc(0x10, name="obj2")
        self.assertLessEqual(addr1 + 0x10, addr2)
        self.assertEqual(2, len(heap.heap_objects))

    def test_dealloc(self):
        z = Zelos(None)
        heap = z.internal_engine.memory.heap
        starting_offset = heap.current_offset

        # Don't dealloc past the beginning
        new_heap_start = heap.dealloc(0x10)
        self.assertEqual(starting_offset, new_heap_start)

        # dealloc when appropriate
        heap.alloc(0x100)
        new_current_offset = heap.dealloc(0xF0)
        self.assertEqual(starting_offset + 0x10, new_current_offset)

        # Dealloc when asking to go back to the beginning.
        new_current_offset = heap.dealloc(
            heap.current_offset - heap.heap_start
        )
        self.assertEqual(starting_offset, new_current_offset)

    def test_bug_alloc_is_aligned(self):
        # We should ensure that allocs are aligned, as some binaries
        # (helloVB6-native.exe) do not work with unaligned memory
        # allocs.
        z = Zelos(None)
        heap = z.internal_engine.memory.heap

        addr1 = heap.alloc(0x11, name="obj1")
        addr2 = heap.alloc(0x3, name="obj2")

        self.assertEqual(0, addr1 % 4)
        self.assertEqual(0, addr2 % 4)
        self.assertEqual(2, len(heap.heap_objects))

    def test_allocstr(self):
        z = Zelos(None)
        heap = z.internal_engine.memory.heap
        s1 = "We are the future"
        p_str, size = heap.allocstr(s1)
        self.assertEqual(size, len(s1) + 1)
        expected_s1 = z.internal_engine.memory.read_string(p_str)
        self.assertEqual(s1, expected_s1)

        s2 = "you best believe it"
        p_str, size = heap.allocstr(s2, is_wide=True)
        self.assertEqual(size, len(s2) * 2 + 2)
        expected_s2 = z.internal_engine.memory.read_wstring(p_str)
        self.assertEqual(expected_s2, s2)

        s3 = "this is it"
        size = z.internal_engine.memory.write_string(p_str, s3)
        self.assertEqual(size, len(s3) + 1)
        expected_s3 = z.internal_engine.memory.read_string(p_str)
        self.assertEqual(expected_s3, s3)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
