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

import copy
import ctypes
import logging
import mmap
import os

from ctypes import memmove
from struct import pack, unpack
from typing import Dict, Iterable, List

from sortedcontainers import SortedDict

from zelos.enums import ProtType
from zelos.exceptions import (
    InvalidRegException,
    MemoryReadUnmapped,
    MemoryWriteUnmapped,
    OutOfMemoryException,
    ZelosLoadException,
)
from zelos.util import align, columnate


class MemoryRegion:
    """
    Represents a region of guest memory.
    """

    def __init__(
        self,
        emu,
        address: int,
        size: int,
        prot: int,
        name: str,
        kind: str,
        module_name: str,
        shared: bool = False,
        reserve: bool = False,
        host_address: int = None,
        managed_object: any = None,
    ):
        if address % 0x1000 != 0:
            raise ValueError("invalid argument: address not aligned")
        if size <= 0:
            raise ValueError("invalid argument: size invalid")
        size = align(size)
        self.emu = emu
        self.address = address
        self.size = size
        self.prot = prot
        self.name = name
        self.kind = kind
        self.module_name = module_name
        self.reserved = reserve
        self.shared = shared
        if host_address is None:
            self._managed_object = ctypes.create_string_buffer(size)
            host_pointer = ctypes.cast(
                self._managed_object, ctypes.POINTER(ctypes.c_char)
            )
            self.host_address = ctypes.addressof(host_pointer.contents)
        else:
            self.host_address = host_address
            self._managed_object = managed_object
        self.host_data = (ctypes.c_char * size).from_address(self.host_address)

    @property
    def start(self) -> int:
        return self.address

    @property
    def end(self) -> int:
        return self.address + self.size - 1

    def shrink(self, address: int, size: int):
        offset = address - self.address
        if (
            offset < 0
            or offset >= self.size
            or self.address + size >= self.end + 1
        ):
            raise ValueError(
                f"invalid argument: {address, size} out of bounds"
            )
        self.address = address
        self.size = size
        self.host_address = self.host_address + offset
        self.host_data = (ctypes.c_char * size).from_address(self.host_address)

    def __str__(self):
        if self.address + self.size <= 0xFFFFFFFF:
            area = f"{self.address:08x}-{self.address+self.size:08x}"
        else:
            area = f"{self.address:16x}-{self.address+self.size:16x}"
        size = f"{self.size:08x}"
        perms = ["-", "-", "-"]
        if self.prot & ProtType.READ != 0:
            perms[0] = "r"
        if self.prot & ProtType.WRITE != 0:
            perms[1] = "w"
        if self.prot & ProtType.EXEC != 0:
            perms[2] = "x"
        perms = "".join(perms)
        access = "private"
        if self.shared:
            access = " shared"
        info = [i for i in [self.module_name, self.name, self.kind] if i]
        info = ", ".join(info)
        s = [i for i in [area, size, perms, access, info] if i]
        s = " ".join(s)
        return s

    def __eq__(self, other):
        return (
            self.emu == other.emu
            and self.address == other.address
            and self.size == other.size
        )

    def __lt__(self, other):
        return self.address < other.address

    def get_data(self) -> bytearray:
        """
        Returns all data in the region.

        Returns:
            Data from the region.
        """
        return self.emu.mem_read(self.address, self.size)


class PageTable:
    """
    Maps host system pages to guest system pages. Enables directly
    reading and writing emulated memory without using the emulator
    memory API.
    """

    PAGE_MASK = 0xFFFFFFFFFFFFF000

    def __init__(self):
        self.reset()

    def reset(self):
        self._pages = dict()

    def add(self, section) -> None:
        """
        Add or replace pages from the given section to the page table.

        Args:
            section: the memory region to add.

        """
        for addr in range(section.address, section.end, 0x1000):
            self._pages[addr] = section

    def remove(self, section) -> None:
        """
        Remove pages from the given section from the page table

        Args:
            section: the memory region to remove.

        """
        for addr in range(section.address, section.end, 0x1000):
            del self._pages[addr]

    def exists(self, address: int) -> bool:
        """
        Checks if the address exists in the page table.

        Args:
            address: The address of the page to check.

        Returns:
            True if the address exists in the page table, False
                otherwise.

        """
        return address & PageTable.PAGE_MASK in self._pages

    def read(self, address: int, size: int) -> bytearray:
        """
        Reads `size` bytes of guest memory from `address`.

        Args:
            address: The address to read.
            size: The size of the data to fetch in bytes.

        Returns:
            The data at the specified address.

        """
        if size == 0:
            return bytearray()
        page_addr = address & PageTable.PAGE_MASK

        # Fast path if all data is on one page.
        try:
            mr = self._pages[page_addr]
            offset = address - mr.address
            if offset + size < mr.size:
                return mr.host_data[offset : offset + size]
        except (IndexError, ValueError):
            pass
        except KeyError:
            raise MemoryReadUnmapped(
                f"Read unmapped memory at address 0x{address:x}"
            )

        # Slow path if data spans multiple pages.
        data = bytearray()
        while size > 0:
            try:
                mr = self._pages[address & PageTable.PAGE_MASK]
            except KeyError:
                raise MemoryReadUnmapped(
                    f"Read unmapped memory at address 0x{address:x}"
                )
            offset = address - mr.address
            bytes_to_read = min(size, mr.size - offset)
            data += mr.host_data[offset : offset + bytes_to_read]
            size -= bytes_to_read
            address += bytes_to_read
        return data

    def write(self, address: int, data: bytes) -> None:
        """
        Writes `data` to guest memory at `address`.

        Args:
            address: The address to read.
            size: The size of the data to fetch in bytes.

        """
        if len(data) == 0:
            return
        page_addr = address & PageTable.PAGE_MASK

        # Fast path if all data is on one page.
        try:
            mr = self._pages[page_addr]
            offset = address - mr.address
            if offset + len(data) < mr.size:
                memmove(mr.host_address + offset, data, len(data))
                return
        except (IndexError, ValueError):
            pass
        except KeyError:
            raise MemoryWriteUnmapped(
                f"Write unmapped memory at address 0x{address:x}"
            )

        # Slow path if data spans multiple pages.
        size = len(data)
        data_offset = 0
        while size > 0:
            try:
                mr = self._pages[address & PageTable.PAGE_MASK]
            except KeyError:
                raise MemoryWriteUnmapped(
                    f"Write unmapped memory at address 0x{address:x}"
                )
            offset = address - mr.address
            bytes_to_write = min(size, mr.size - offset)
            memmove(
                mr.host_address + offset,
                data[data_offset : data_offset + bytes_to_write],
                bytes_to_write,
            )
            size -= bytes_to_write
            address += bytes_to_write
            data_offset += bytes_to_write


class IEmuHelper:
    """
    This is a class that serves as a wrapper around Unicorn, providing some
    additional functionality surrounding stacks and commonly used registers.
    Each architecture will need to implement their own subclass to provide the
    additional register information that is needed.

    Because there may be multiple threads sharing a single emu instance, prefer
    to access these methods through the Thread class.

    We chose to use string names for registers rather than an enum for quality
    of life reasons.
    """

    def __init__(self, zebracorn_engine, state):
        self.state = state
        self._uc = zebracorn_engine
        self._logger = logging.getLogger(__name__)
        self._is_running = False
        self._managed_ctype_buffers = dict()
        self._page_table = PageTable()
        self._regions = SortedDict()
        self._pack_fmt_little = [None] * 9
        self._pack_fmt_little[1] = "<B"
        self._pack_fmt_little[2] = "<H"
        self._pack_fmt_little[4] = "<I"
        self._pack_fmt_little[8] = "<Q"
        self._pack_fmt_big = [None] * 9
        self._pack_fmt_big[1] = ">B"
        self._pack_fmt_big[2] = ">H"
        self._pack_fmt_big[4] = ">I"
        self._pack_fmt_big[8] = ">Q"
        self._pack_fmt_signed_little = [None] * 9
        self._pack_fmt_signed_little[1] = "<b"
        self._pack_fmt_signed_little[2] = "<h"
        self._pack_fmt_signed_little[4] = "<i"
        self._pack_fmt_signed_little[8] = "<q"
        self._pack_fmt_signed_big = [None] * 9
        self._pack_fmt_signed_big[1] = ">b"
        self._pack_fmt_signed_big[2] = ">h"
        self._pack_fmt_signed_big[4] = ">i"
        self._pack_fmt_signed_big[8] = ">q"
        self._pack_bitmask = [None] * 9
        for i in range(len(self._pack_bitmask)):
            self._pack_bitmask[i] = 2 ** (i * 8) - 1

    @property
    def regmap(self):
        raise NotImplementedError()

    @property
    def bytes(self) -> int:
        return self.state.bytes

    @property
    def is_running(self) -> bool:
        return self._is_running

    def getstack(self, idx: int) -> int:
        sp = self.getSP()
        data = self.mem_read(sp + (idx * self.bytes), self.bytes)
        return self.unpack(data)

    def setstack(self, idx: int, val: int) -> None:
        sp = self.getSP()
        self.mem_write(sp + (idx * self.bytes), self.pack(val))

    def popstack(self) -> int:
        sp = self.getSP()
        data = self.unpack(self.mem_read(sp, self.bytes))
        self.setSP(sp + self.bytes)
        return data

    def pushstack(self, data: int) -> None:
        sp = self.getSP()
        self.mem_write(sp - self.bytes, self.pack(data))
        self.setSP(sp - self.bytes)

    def setSP(self, val: int) -> None:
        self.set_reg(self.sp_reg, val)

    def getSP(self) -> int:
        return self.get_reg(self.sp_reg)

    def setFP(self, val: int):
        self.set_reg(self.fp_reg, val)

    def getFP(self) -> int:
        return self.get_reg(self.fp_reg)

    def get_reg(self, reg_name: str) -> int:
        try:
            return self._uc.reg_read(self.regmap[reg_name])
        except KeyError:
            raise InvalidRegException(reg_name)

    def set_reg(self, reg_name: str, val: int) -> None:
        try:
            self._uc.reg_write(self.regmap[reg_name], val)
        except KeyError:
            raise InvalidRegException(reg_name)

    def setIP(self, val: int) -> None:
        self.set_reg(self.ip_reg, val)

    def getIP(self) -> int:
        return self.get_reg(self.ip_reg)

    def get_all_regs(self) -> List[str]:
        """
        Gets all registers for this architecture.
        Order of returned values is consistent between calls.
        """
        # Regmap may store aliases of registers, ensure that the emitted
        # list is unique
        reg_names = sorted(self.regmap.keys())
        # We sorted the reg_names so that the last repeat for a given
        # index is always taken.
        index_to_name = {self.regmap[name]: name for name in reg_names}
        unique_reg_names = index_to_name.values()
        # Make sure the order of registers returned is consistent
        return sorted(unique_reg_names)

    def get_all_reg_vals(self) -> Dict[str, int]:
        """
        Returns a dict of {reg_name:reg_val} for all regs for the
        current architecture.
        """
        return {name: self.get_reg(name) for name in self.get_all_regs()}

    def get_regs(self, regs: Iterable[str] = None) -> Dict[str, int]:
        """
        Returns a dictionary of registers and their values. Defaults
        to important regs for the current architecture
        """
        if regs is None:
            regs = self.imp_regs
        return {r: self.get_reg(r) for r in regs}

    def dumpregs(self, regs: Iterable[str] = None) -> str:
        if regs is None:
            regs = self.imp_regs

        def get_reg_string(reg):
            val = self.get_reg(reg)
            fmt = "{0}: 0x{1:0" + str(self.state.bytes * 2) + "x}"
            return (fmt).format(reg, val)

        reg_strings = [get_reg_string(r) for r in regs]

        return columnate(reg_strings, 4)

    def context_restore(self, context):
        return self._uc.context_restore(context)

    def context_save(self):
        return self._uc.context_save()

    def emu_start(self, begin, until, timeout=0, count=0):
        self._is_running = True
        try:
            return self._uc.emu_start(begin, until, timeout, count)
        finally:
            self._is_running = False

    def emu_stop(self):
        return self._uc.emu_stop()

    def hook_add(
        self, htype, callback, user_data=None, begin=1, end=0, arg1=0
    ):
        assert not self.is_running
        return self._uc.hook_add(htype, callback, user_data, begin, end, arg1)

    def hook_del(self, h):
        assert not self.is_running
        return self._uc.hook_del(h)

    def mem_map(
        self,
        address: int,
        size: int,
        name: str = "",
        kind: str = "",
        module_name: str = "",
        prot: int = ProtType.RWX,
        shared: bool = False,
        reserve: bool = False,
    ):
        if address % 0x1000 != 0:
            raise ValueError("invalid argument: address not aligned")
        if size % 0x1000 != 0:
            raise ValueError("invalid argument: size not aligned")
        if self._mem_area_overlaps(address, size):
            raise ValueError("invalid argument: {address, size} overlaps")
        mr = MemoryRegion(
            self,
            address,
            size,
            prot,
            name,
            kind,
            module_name,
            shared=shared,
            reserve=reserve,
        )
        self._mem_map_region(mr)

    def mem_map_file(
        self,
        address: int,
        filename: str,
        offset: int = 0,
        size: int = 0,
        prot: int = ProtType.RW,
        shared: bool = False,
    ):
        if address % 0x1000 != 0:
            raise ValueError("invalid argument: address not aligned")
        if offset % 0x1000 != 0:
            raise ValueError("invalid argument: offset not aligned")
        with open(filename, "rb") as f:
            basename = os.path.basename(filename)
            file_map = mmap.mmap(
                f.fileno(), length=0, offset=offset, access=mmap.ACCESS_COPY
            )
            ptr = ctypes.POINTER(ctypes.c_void_p)(
                ctypes.c_void_p.from_buffer(file_map)
            )
            if size == 0:
                size = os.fstat(f.fileno()).st_size
            size = align(size)
            if self._mem_area_overlaps(address, size):
                raise ValueError("invalid argument: {address, size} overlaps")
            mr = MemoryRegion(
                self,
                address,
                size,
                prot,
                basename,
                "mapped",
                basename,
                shared=shared,
                host_address=ctypes.addressof(ptr.contents),
                managed_object=file_map,
            )
            self._mem_map_region(mr)
            return
        raise ValueError("invalid argument: filename")

    def map_shared(self, mr: MemoryRegion):
        self._mem_map_region(mr)

    # unmap a range of memory
    def mem_unmap(self, address: int, size: int):
        if size <= 0:
            return
        if address % 0x1000 != 0:
            raise ValueError("invalid argument: address not aligned")
        if size % 0x1000 != 0:
            raise ValueError("invalid argument: size not aligned")
        if not self._mem_area_mapped(address, size):
            raise ValueError("invalid argument: {address, size} not mapped")
        addr = address
        count = 0
        while count < size:
            mr = self.mem_region(addr)
            length = min(size - count, mr.end + 1 - addr)
            self._split_region(mr, addr, length, do_delete=True)
            mr = self.mem_region(addr)
            if mr is not None:
                self._mem_unmap_region(mr)
            count += length
            addr += length

    # protect a range of memory
    def mem_protect(self, address: int, size: int, prot: int = ProtType.RWX):
        if size <= 0:
            return
        if address % 0x1000 != 0:
            raise ValueError("invalid argument: address not aligned")
        if size % 0x1000 != 0:
            raise ValueError("invalid argument: size not aligned")
        if not self._mem_area_mapped(address, size):
            raise ValueError("invalid argument: {address, size} not mapped")
        addr = address
        count = 0
        while count < size:
            mr = self.mem_region(addr)
            length = min(size - count, mr.size)
            self._split_region(mr, addr, length)
            mr = self.mem_region(addr)
            mr.prot = prot
            self._uc.mem_protect(mr.address, mr.size, prot)
            count += length
            addr += length

    def mem_region(self, address: int):
        for region in self.mem_regions():
            if address >= region.address and address <= region.end:
                return region
        return None

    # Returns MemoryRegions sorted by start address
    def mem_regions(self):
        return list(self._regions.values())

    # read data from memory
    def mem_read(self, address: int, size: int):
        return self._page_table.read(address, size)

    # write to memory
    def mem_write(self, address: int, data):
        self._page_table.write(address, data)

    def bb_count(self):
        return self._uc.bb_count()

    def inst_count(self):
        return self._uc.inst_count()

    def to_signed(self, x, bytes=None):
        return self.unpack(self.pack(x, bytes=bytes), bytes=bytes, signed=True)

    def pack(
        self,
        x: int,
        bytes: int = None,
        little_endian: bool = None,
        signed: bool = False,
    ) -> bytes:
        """
        Packs an integer into bytes. Defaults to the
        current architecture bytes and endianness.
        """
        if bytes is None:
            bytes = self.bytes
        if little_endian is None:
            little_endian = self.state.endianness[0] == "l"
        fmt = None
        if little_endian:
            if signed:
                fmt = self._pack_fmt_signed_little[bytes]
            else:
                fmt = self._pack_fmt_little[bytes]
        else:
            if signed:
                fmt = self._pack_fmt_signed_big[bytes]
            else:
                fmt = self._pack_fmt_big[bytes]
        return pack(fmt, x & self._pack_bitmask[bytes])

    def unpack(
        self,
        x: bytes,
        bytes: int = None,
        little_endian: bool = None,
        signed: bool = False,
    ) -> int:
        """
        Unpacks an integer from a byte format. Defaults to the
        current architecture bytes and endianness.
        """
        if bytes is None:
            bytes = self.bytes
        if little_endian is None:
            little_endian = self.state.endianness[0] == "l"
        fmt = None
        if little_endian:
            if signed:
                fmt = self._pack_fmt_signed_little[bytes]
            else:
                fmt = self._pack_fmt_little[bytes]
        else:
            if signed:
                fmt = self._pack_fmt_signed_big[bytes]
            else:
                fmt = self._pack_fmt_big[bytes]
        return unpack(fmt, x)[0]

    def _mem_map_region(self, mr: MemoryRegion):
        self._uc.mem_map_ptr(mr.address, mr.size, mr.prot, mr.host_address)
        self._page_table.add(mr)
        self._regions[mr.address] = mr

    def _mem_unmap_region(self, mr: MemoryRegion):
        self._uc.mem_unmap(mr.address, mr.size)
        self._page_table.remove(mr)
        del self._regions[mr.address]

    def _mem_area_overlaps(self, address: int, size: int) -> bool:
        end = address + size - 1
        for mr in self.mem_regions():
            if address >= mr.address and address <= mr.end:
                return True
            if end >= mr.address and end <= mr.end:
                return True
            if address < mr.address and end > mr.end:
                return True

    def _mem_area_mapped(self, address: int, size: int) -> bool:
        count = 0
        while count < size:
            mr = self.mem_region(address)
            if mr is None:
                break
            length = min(size - count, mr.end + 1 - address)
            count += length
            address += length
        return count == size

    def _split_region(
        self,
        mr: MemoryRegion,
        address: int,
        size: int,
        do_delete: bool = False,
    ):
        chunk_end = address + size
        if (address <= mr.address and chunk_end > mr.end) or size == 0:
            return
        if address > mr.end or chunk_end <= mr.address:
            raise OutOfMemoryException()
        self._mem_unmap_region(mr)
        if address < mr.address:
            address = mr.address
        if chunk_end > mr.end + 1:
            chunk_end = mr.end + 1
        l_size = address - mr.address
        m_size = chunk_end - address
        r_size = mr.end + 1 - chunk_end
        if l_size > 0:
            l_mr = copy.copy(mr)
            l_mr.shrink(mr.address, l_size)
            self._mem_map_region(l_mr)
        if m_size > 0 and not do_delete:
            m_mr = copy.copy(mr)
            m_mr.shrink(address, m_size)
            self._mem_map_region(m_mr)
        if r_size > 0:
            r_mr = copy.copy(mr)
            r_mr.shrink(chunk_end, r_size)
            self._mem_map_region(r_mr)


def create_emulator(arch, mode, state) -> IEmuHelper:
    """
    Factory method for constructing the appropriate IEmuHelper
    """
    from zebracorn import Uc, UC_ARCH_ARM, UC_ARCH_MIPS, UC_ARCH_X86
    from zebracorn import UcError

    try:
        uc = Uc(arch, mode)
        arch = uc._arch
        if arch == UC_ARCH_X86 and state.bits == 32:
            from .x86 import x86EmuHelper

            return x86EmuHelper(uc, state)
        if arch == UC_ARCH_X86 and state.bits == 64:
            from .x86 import x86_64EmuHelper

            return x86_64EmuHelper(uc, state)
        elif arch == UC_ARCH_ARM:
            from .arm import ArmEmuHelper

            return ArmEmuHelper(uc, state)
        elif arch == UC_ARCH_MIPS:
            from .mips import MipsEmuHelper

            return MipsEmuHelper(uc, state)
        else:
            raise ZelosLoadException(
                f"Unsupported architecture {arch} {state.bits}"
            )
    except UcError:
        raise ZelosLoadException(
            f"Custom zebracorn does not support the arch/mode/bits"
            + f" {arch}/{mode}/{state.bits}"
        )
