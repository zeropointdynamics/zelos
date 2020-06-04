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

from zelos import Zelos
from zelos.enums import ProtType


class EmuHelperTest(unittest.TestCase):
    def emu_init(self):
        z = Zelos(None)
        z.internal_engine.memory.clear()
        emu = z.internal_engine.emu
        return emu

    def test_emu_memory(self):
        emu = self.emu_init()
        emu.mem_map(0x1000, 0x3000, prot=ProtType.READ)
        emu.mem_map(0x4000, 0x1000, prot=ProtType.NONE, shared=True)
        self.assertEqual(2, len(emu.mem_regions()))
        mr1 = emu.mem_region(0x1000)
        data1 = bytes(b"A" * mr1.size)
        mr2 = emu.mem_region(0x4000)
        data2 = bytes(b"B" * mr2.size)
        emu.mem_write(mr1.address, data1)
        emu.mem_write(mr2.address, data2)
        self.assertGreater(mr2, mr1)
        self.assertNotEqual(mr1, mr2)
        self.assertEqual(str(mr1), "00001000-00004000 00003000 r-- private")
        self.assertEqual(str(mr2), "00004000-00005000 00001000 ---  shared")
        self.assertEqual(b"A", emu.mem_read(mr1.address, 1))
        self.assertEqual(b"A", emu.mem_read(0x1FFF, 1))
        self.assertEqual(b"A", emu.mem_read(0x2000, 1))
        self.assertEqual(b"A", emu.mem_read(0x2001, 1))
        self.assertEqual(b"A", emu.mem_read(0x2FFF, 1))
        self.assertEqual(b"A", emu.mem_read(0x1FFF, 1))
        self.assertEqual(b"AAA", emu.mem_read(0x2000, 3))
        self.assertEqual(b"AAA", emu.mem_read(0x1FFF, 3))
        self.assertEqual(data1, emu.mem_read(mr1.address, mr1.size))
        self.assertEqual(b"AABB", emu.mem_read(0x3FFE, 4))

        emu.mem_map_file(0xA00000000, __file__)
        mr3 = emu.mem_region(0xA00000000)
        file_data = b"# Copyright (C)"
        self.assertEqual(file_data, emu.mem_read(mr3.address, len(file_data)))


def main():
    unittest.main()


if __name__ == "__main__":
    main()
