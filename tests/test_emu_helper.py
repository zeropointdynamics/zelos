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
        self.assertEqual(b"AAA", emu.mem_read(0x1fff, 3))
        self.assertEqual(data1, emu.mem_read(mr1.address, mr1.size))
        self.assertEqual(b"AABB", emu.mem_read(0x3ffe, 4))

        emu.mem_map_file(0xA00000000, __file__)
        mr3 = emu.mem_region(0xA00000000)
        file_data = b"# Copyright (C)"
        self.assertEqual(file_data, emu.mem_read(mr3.address, len(file_data)))

    # def test_region_str(self):
    #     emu = self.emu_init()

    # def test_region_eq(self):
    #     emu = self.emu_init()

    # def test_region_lt(self):
    #     emu = self.emu_init()

    # def test_region_get_data(self):
    #     emu = self.emu_init()

    # def test_page_table_reset(self):
    #     emu = self.emu_init()

    # def test_page_table_add(self):
    #     emu = self.emu_init()

    # def test_page_table_remove(self):
    #     emu = self.emu_init()

    # def test_page_table_exists(self):
    #     emu = self.emu_init()

    # def test_page_table_get_page(self):
    #     emu = self.emu_init()

    # def test_page_table_read(self):
    #     emu = self.emu_init()

    # def test_page_table_write(self):
    #     emu = self.emu_init()

    # def test_emu_regmap(self):
    #     emu = self.emu_init()

    # def test_emu_bytes(self):
    #     emu = self.emu_init()

    # def test_emu_is_running(self):
    #     emu = self.emu_init()

    # def test_emu_getstack(self):
    #     emu = self.emu_init()

    # def test_emu_setstack(self):
    #     emu = self.emu_init()

    # def test_emu_popstack(self):
    #     emu = self.emu_init()

    # def test_emu_pushstack(self):
    #     emu = self.emu_init()

    # def test_emu_setSP(self):
    #     emu = self.emu_init()

    # def test_emu_getSP(self):
    #     emu = self.emu_init()

    # def test_emu_setFP(self):
    #     emu = self.emu_init()

    # def test_emu_getFP(self):
    #     emu = self.emu_init()

    # def test_emu_get_reg(self):
    #     emu = self.emu_init()

    # def test_emu_set_reg(self):
    #     emu = self.emu_init()

    # def test_emu_setIP(self):
    #     emu = self.emu_init()

    # def test_emu_getIP(self):
    #     emu = self.emu_init()

    # def test_emu_get_all_regs(self):
    #     emu = self.emu_init()

    # def test_emu_get_all_reg_vals(self):
    #     emu = self.emu_init()

    # def test_emu_get_regs(self):
    #     emu = self.emu_init()

    # def test_emu_dumpregs(self):
    #     emu = self.emu_init()

    # def test_emu_get_reg_string(self):
    #     emu = self.emu_init()

    # def test_emu_context_restore(self):
    #     emu = self.emu_init()

    # def test_emu_context_save(self):
    #     emu = self.emu_init()

    # def test_emu_start(self):
    #     emu = self.emu_init()

    # def test_emu_stop(self):
    #     emu = self.emu_init()

    # def test_emu_hook_add(self):
    #     emu = self.emu_init()

    # def test_emu_hook_del(self):
    #     emu = self.emu_init()

    # def test_emu_mem_map(self):
    #     emu = self.emu_init()

    # def test_emu_mem_map_file(self):
    #     emu = self.emu_init()

    # def test_emu_map_shared(self):
    #     emu = self.emu_init()

    # def test_emu_mem_unmap(self):
    #     emu = self.emu_init()

    # def test_emu_mem_protect(self):
    #     emu = self.emu_init()

    # def test_emu_mem_host_page(self):
    #     emu = self.emu_init()

    # def test_emu_mem_region(self):
    #     emu = self.emu_init()

    # def test_emu_mem_regions(self):
    #     emu = self.emu_init()

    # def test_emu_mem_read(self):
    #     emu = self.emu_init()

    # def test_emu_mem_write(self):
    #     emu = self.emu_init()

    # def test_emu_bb_count(self):
    #     emu = self.emu_init()

    # def test_emu_to_signed(self):
    #     emu = self.emu_init()

    def test_emu_pack(self):
        emu = self.emu_init()
        self.assertEqual(123, emu.unpack(emu.pack(123)))
        self.assertEqual(-1, emu.unpack(emu.pack(-1), signed=True))

    def test_emu_unpack(self):
        emu = self.emu_init()

    def test_create_emulator(self):
        emu = self.emu_init()


def main():
    unittest.main()


if __name__ == "__main__":
    main()
