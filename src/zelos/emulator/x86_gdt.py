# MIT License

# Copyright (c) 2017 Ryo ICHIKAWA

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ======================================================================

# Code in this file derived from:
# https://github.com/icchy/tracecorn/blob/master/unitracer/lib/segment.py
import struct

from zelos.util import align


class GDT_32(object):
    def __init__(self, memory, gdt_base=0x80000000, size=0x1000):
        self.emu = memory.emu

        memory.map(gdt_base, align(size), prot=0x3)
        self.emu.set_reg("gdtr", (0, gdt_base, size, 0x0))
        self.gdt_base = gdt_base
        self._init_gdt()

    @staticmethod
    def _gdt_entry(base, limit, flags):
        #  0:15 -> limit 0:15
        # 16:31 -> base 0:15
        # 32:39 -> base 16:23
        # 40:47 -> access
        # 48:51 -> limit 16:19
        # 52:55 -> flags
        # 56:63 -> base 24:31

        entry = limit & 0xFFFF
        entry |= (base & 0xFFFF) << 16
        entry |= ((base >> 16) & 0xFF) << 32
        entry |= (flags & 0xFF) << 40
        entry |= ((limit >> 16) & 0xF) << 48
        entry |= ((flags >> 8) & 0xF) << 52
        entry |= ((base >> 24) & 0xFF) << 56
        return struct.pack("<Q", entry)

    @staticmethod
    def gdt_entry_flags(gr, sz, pr, privl, ex, dc, rw, ac):
        flags = ac & 1
        flags |= (rw & 1) << 1
        flags |= (dc & 1) << 2
        flags |= (ex & 1) << 3
        flags |= 1 << 4
        flags |= (privl & 0b11) << 5
        flags |= (pr & 1) << 7
        flags |= (sz & 1) << 10
        flags |= (gr & 1) << 11
        return flags

    @staticmethod
    def _seg_selector(index, ti, rpl):
        #  0: 1 -> rpl
        #  2: 2 -> ti
        #  3:15 -> index

        sel = rpl
        sel |= ti << 2
        sel |= index << 3
        return sel

    def set_entry(self, index, base, limit, flags, ti=0, rpl=3):
        emu = self.emu
        gdt_base = self.gdt_base

        emu.mem_write(
            gdt_base + index * 8, self._gdt_entry(base, limit, flags)
        )
        return self._seg_selector(index, ti, rpl)

    # TODO: This probably has different incarnations on different
    # architectures (this is x86/x64 specific), also for different OSes
    def _init_gdt(self, teb_address=0x7FFDF000):
        # cs : 0x0023 (index:4)
        flags = self.gdt_entry_flags(
            gr=1, sz=1, pr=1, privl=3, ex=1, dc=0, rw=1, ac=1
        )
        selector = self.set_entry(4, 0x0, 0xFFFFFFFF, flags)
        self.emu.set_reg("cs", selector)

        # ds, es, gs : 0x002b (index:5)
        flags = self.gdt_entry_flags(
            gr=1, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1
        )
        selector = self.set_entry(5, 0x0, 0xFFFFFFFF, flags)
        self.emu.set_reg("ds", selector)
        self.emu.set_reg("es", selector)
        self.emu.set_reg("gs", selector)

        # ss
        flags = self.gdt_entry_flags(
            gr=1, sz=1, pr=1, privl=0, ex=0, dc=1, rw=1, ac=1
        )
        selector = self.set_entry(6, 0x0, 0xFFFFFFFF, flags, rpl=0)
        self.emu.set_reg("ss", selector)

        # fs : 0x0053 (index:10)
        flags = self.gdt_entry_flags(
            gr=0, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1
        )  # 0x4f3
        selector = self.set_entry(10, teb_address, 0xFFF, flags)
        self.emu.set_reg("fs", selector)
