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
from __future__ import absolute_import, print_function

import ctypes
import logging
import os
import re

from collections import defaultdict
from typing import List, Optional

from sortedcontainers import SortedListWithKey

import zelos.util as util

from zelos.emulator.base import MemoryRegion
from zelos.enums import ProtType
from zelos.exceptions import MemoryReadUnmapped, OutOfMemoryException
from zelos.hooks import HookType


class Memory:
    """
    Responsbile for interactions with emulated memory.
    """

    HEAP_BASE = 0x90000000
    HEAP_MAX_SIZE = 100 * 1024 * 1024
    # A separate heap base for virtual allocations
    VALLOC_BASE = 0x00C50000
    MAX_UINT64 = 0xFFFFFFFFFFFFFFFF
    MAX_UINT32 = 0xFFFFFFFF

    def __init__(
        self, emu, hook_manager, state, disableNX: bool = False
    ) -> None:
        self.emu = emu
        self._hook_manager = hook_manager
        self.state = state
        self.logger = logging.getLogger(__name__)
        self.disableNX = disableNX
        self.MEM_LIMIT = 3 * 1024 * 1024 * 1024
        self.heap = None
        self.clear()
        self.heap = Heap(self, self.HEAP_BASE, self.HEAP_MAX_SIZE)

        from zebracorn import UC_HOOK_MEM_READ_PROT

        self.emu.hook_add(UC_HOOK_MEM_READ_PROT, self._hook_read_prot)
        self.mem_hooks = dict()

    def __str__(self):
        s = "Memory Manager:\n"
        for info in self.get_regions():
            s += "  {0}\n".format(info)
        return s

    def copy(self, other_memory: "Memory") -> None:
        """
        Duplicates memory regions from `other_memory` into this memory.

        Args:
            other_memory: Memory to duplicate.
        """
        self.clear()
        self.disableNX = other_memory.disableNX
        self.heap = other_memory.heap
        for mr in other_memory.get_regions():
            if mr.shared:
                self.emu.map_shared(mr)
            else:
                self.map(
                    mr.address,
                    mr.size,
                    name=mr.name,
                    kind=mr.kind,
                    module_name=mr.module_name,
                )
                data = other_memory.read(mr.address, mr.size)
                self.write(mr.address, bytes(data))

    def clear(self) -> None:
        """
        Clears all of memory
        """
        self.logger.debug(f"Clearing Memory...")
        for region in self.get_regions():
            self.logger.debug(f"  Clearing {region.start:x}-{region.end:x}")
            self.unmap(region.start, region.size)
        if self.heap:
            self.heap._clear()
        self.num_bytes_mapped = 0
        self.VALLOC_CUR = self.VALLOC_BASE

    # Helper functions for reading and writing memory. All generic
    # helpers for memory should go here moving forward
    def read(self, addr: int, size: int) -> bytearray:
        """
        Copies specified region of memory. Requires that the specified
        address is mapped.

        Args:
            addr: Address to start reading from.
            size: Number of bytes to read.

        Returns:
            Bytes corresponding to data held in memory.
        """
        val = self.emu.mem_read(addr, size)
        hooks = self._hook_manager._get_hooks(HookType.MEMORY.INTERNAL_READ)
        for hook in hooks:
            hook(0, addr, size, val)
        return val

    def write(self, addr: int, data: bytes) -> int:
        """
        Writes specified bytes to memory. Requires that the specified
        address is mapped.

        Args:
            addr: Address to start writing data to.
            data: Bytes to write in memory.
        Returns:
            Number of bytes written.
        """
        self.emu.mem_write(addr, data)
        hooks = self._hook_manager._get_hooks(HookType.MEMORY.INTERNAL_WRITE)
        for hook in hooks:
            hook(0, addr, len(data), data)
        return len(data)

    def read_int(self, addr: int, sz: int = None, signed: bool = False) -> int:
        """
        Reads an integer value from the specified address. Can handle
        multiple sizes and representations of integers.

        Args:
            addr: Address to begin reading int from.
            sz: Size (# of bytes) of integer representation.
            signed: If true, interpret bytes as signed integer. Default
                false.

        Returns:
            Integer represntation of bytes read.
        """
        sz = self.state.bytes if sz is None else sz
        value = self.read(addr, sz)
        return self.emu.unpack(value, bytes=sz, signed=signed)

    def write_int(
        self, addr: int, value: int, sz: int = None, signed: bool = False
    ) -> int:
        """
        Writes an integer value to the specified address. Can handle
        multiple sizes and representations of integers.

        Args:
            addr: Address in memory to write integer to.
            value: Integer to write into memory.
            sz: Size (# of bytes) to write into memory.
            signed: If true, write number as signed integer. Default
                false.

        Returns:
            Number of bytes written to memory.
        """
        packed = self.emu.pack(value, bytes=sz, signed=signed)
        self.write(addr, packed)
        return len(packed)

    def read_string(self, addr: int, size: int = 1024) -> str:
        """
        Reads a utf-8 string from memory. Stops at null terminator.
        Fails if a byte is uninterpretable.

        Args:
            addr: Address in memory to start reading from.
            size: Maximum size of string to read from memory.

        Returns:
            String read from memory.
        """
        try:
            return self._read_string(addr, size)
        except Exception as e:
            self.logger.debug(f"Couldn't read str at 0x{addr:x}: {e}")
            return ""

    def try_read_string(self, addr: int, size: int = 1024) -> Optional[str]:
        """
        Similar to read_string, however doesn't log on failure. Use for
        when you are checking if a valid string exists.
        """
        try:
            return self._read_string(addr, size)
        except (MemoryReadUnmapped, UnicodeDecodeError):
            pass
        return None

    def _read_string(self, addr: int, size: int = 1024) -> Optional[str]:
        if addr == 0:
            return ""
        data = b""
        for i in range(size):
            byte = bytes(self.read(addr + i, 1))
            if byte == b"\x00":
                break
            data += byte
        # TODO: Allow for different decodings.
        return data.decode()

    def read_wstring(self, addr: int, size: int = 1024) -> str:
        """
        Reads a utf-16 string from memory. Stops at null terminator.
        Fails if a byte is uninterpretable.

        Args:
            addr: Address in memory to start reading from.
            size: Maximum size of string to read from memory.

        Returns:
            String read from memory.
        """
        if addr == 0:
            return ""
        data = b""
        try:
            for i in range(0, size, 2):
                chars = self.read(addr + i, 2)
                if chars == b"\x00\x00":
                    break
                data += chars
            return data.decode("utf-16")
        except Exception:
            print("Couldn't read wstr at 0x{0:x}".format(addr + i))
            return ""

    def write_string(
        self, addr: int, value: str, terminal_null_byte: bool = True
    ) -> int:
        """
        Writes a string to a specified address as utf-8. By default,
        adds a terminal null byte.

        Args:
            addr: Address in memory to begin writing string to.
            value: String to write to memory.
            terminal_null_byte: If True, adds terminal null byte.
                Default True.

        Returns:
            Number of bytes written.
        """
        byte_value = value.encode()
        if terminal_null_byte:
            byte_value += b"\x00"
        if addr != 0:
            self.write(addr, byte_value)
        return len(byte_value)

    def write_wstring(
        self, addr: int, value: int, terminal_null_byte: bool = True
    ) -> int:
        """
        Writes a string to a specified address as utf-16-le. By default,
        adds a terminal null byte.

        Args:
            addr: Address in memory to begin writing string to.
            value: String to write to memory.
            terminal_null_byte: If True, adds terminal null byte.
                Default True.

        Returns:
            Number of bytes written.
        """
        byte_value = value.encode("utf-16-le")
        if terminal_null_byte:
            byte_value += b"\x00\x00"
        self.write(addr, byte_value)
        return len(byte_value)

    # @@TODO handle MBCS / WCHAR nonsense
    # for more information this is a good read:
    #   https://utf8everywhere.org/

    def readstruct(self, addr: int, obj: ctypes.Structure) -> ctypes.Structure:
        """
        Reads a ctypes structure from memory.

        Args:
            addr: Address in memory to begin reading structure from.
            obj: An instance of the structure to create from memory.

        Returns:
            Instance of structure read from memory.
        """
        data = self.read(addr, ctypes.sizeof(obj))
        util.str2struct(obj, data)
        return obj

    def readstructarray(
        self, addr: int, count: int, obj: ctypes.Structure
    ) -> List[ctypes.Structure]:
        """
        Read an array of ctypes structure from memory.

        Args:
            addr: Address in memory to begin reading structure from.
            count: number of instances of the object to read.
            obj: An instance of the structure to create from memory.

        Returns:
            List of structures read from memory.
        """
        results = []
        for i in range(count):
            struct = self.readstruct(addr, obj)
            results.append(struct)
            addr += ctypes.sizeof(struct)
        return results

    def writestruct(self, address: int, structure: ctypes.Structure) -> int:
        """
        Write a ctypes Structure to memory.

        Args:
            addr: Address in memory to begin writing to.
            structure: An instance of the structure to write to memory.

        Returns:
            Number of bytes written to memory.
        """
        data = util.struct2str(structure)
        self.write(address, data)
        return len(data)

    def dumpstruct(
        self, structure: ctypes.Structure, indent_level: int = 0
    ) -> None:
        """
        Prints a string representing the data held in a struct.

        Args:
            structure: The structure to print out.
            indent_level: Number of indents when printing output. Makes
                for easier reading. Defaults to no indentation.
        """
        util.dumpstruct(structure, indent_level=indent_level)

    def map_anywhere(
        self,
        size: int,
        preferred_address: int = None,
        name: str = "",
        kind: str = "",
        module_name: str = "",
        min_addr: int = 0x1000,
        max_addr: int = 0xFFFFFFFFFFFFFFFF,
        alignment: int = 0x1000,
        top_down: bool = False,
        prot: int = ProtType.RWX,
        shared: bool = False,
    ) -> int:
        """
        Maps a region of memory with requested size, within the
        addresses specified. The size and start address will respect the
        alignment.

        Args:
            size: # of bytes to map. This will be rounded up to match
                the alignment.
            preferred_address: If the specified address is available,
                it will be used for the mapping.
            name: String used to identify mapped region. Used for
                debugging.
            kind: String used to identify the purpose of the mapped
                region. Used for debugging.
            module_name: String used to identify the module that mapped
                this region.
            min_addr: The lowest address that could be mapped.
            max_addr: The highest address that could be mapped.
            alignment: Ensures the size and start address are multiples
                of this. Must be a multiple of 0x1000. Default 0x1000.
            top_down: If True, the region will be mapped to the
                highest available address instead of the lowest.
            prot: RWX permissions of the mapped region. Defaults to
                granting all permissions.
            shared: if True, region is shared with subprocesses.
        Returns:
            Start address of mapped region.
        """
        address = self.find_free_space(
            size,
            preferred_address=preferred_address,
            min_addr=min_addr,
            max_addr=max_addr,
            alignment=alignment,
            top_down=top_down,
        )
        if address is None:
            raise OutOfMemoryException()
        self.map(
            address,
            util.align(size),
            name=name,
            kind=kind,
            module_name=module_name,
            prot=prot,
            shared=shared,
        )
        return address

    def map_file_anywhere(
        self,
        filename: str,
        offset: int = 0,
        size: int = 0,
        preferred_address: int = None,
        min_addr: int = 0x1000,
        max_addr: int = 0xFFFFFFFFFFFFFFFF,
        alignment: int = 0x1000,
        top_down: bool = False,
        prot: int = ProtType.RWX,
        shared: bool = False,
    ) -> int:
        """
        Maps a region of memory with requested size, within the
        addresses specified. The size and start address will respect the
        alignment.

        Args:
            filename: Name of the file to memory map
            offset: Page-aligned offset of file to start mapping
            size: # of bytes to map. This will be rounded up to the
                nearest page.
            preferred_address: If the specified address is available,
                it will be used for the mapping.
            min_addr: The lowest address that could be mapped.
            max_addr: The highest address that could be mapped.
            alignment: Ensures the size and start address are multiples
                of this. Must be a multiple of 0x1000. Default 0x1000.
            top_down: If True, the region will be mapped to the
                highest available address instead of the lowest.
            prot: RWX permissions of the mapped region. Defaults to
                granting all permissions.
            shared: if True, region is shared with subprocesses.
        Returns:
            Start address of mapped region.
        """
        if size == 0:
            with open(filename, "rb") as f:
                size = os.fstat(f.fileno()).st_size
        size = util.align(size)
        address = self.find_free_space(
            size,
            preferred_address=preferred_address,
            min_addr=min_addr,
            max_addr=max_addr,
            alignment=alignment,
            top_down=top_down,
        )
        if address is None:
            raise OutOfMemoryException()
        self.map_file(
            address,
            filename,
            offset=offset,
            size=size,
            prot=prot,
            shared=shared,
        )
        return address

    def map(
        self,
        address: int,
        size: int,
        name: str = "",
        kind: str = "",
        module_name: str = "",
        prot: int = ProtType.RWX,
        shared: bool = False,
        reserve: bool = False,
    ) -> None:
        """
        Maps a region of memory at the specified address.

        Args:
            address: Address to map.
            size: # of bytes to map. This will be rounded up to the
                nearest 0x1000.
            name: String used to identify mapped region. Used for
                debugging.
            kind: String used to identify the purpose of the mapped
                region. Used for debugging.
            module_name: String used to identify the module that mapped
                this region.
            prot: An integer representing the RWX protection to be set
                on the mapped region.
            ptr: If specified, creates a memory map from the pointer.
            shared: if True, region is shared with subprocesses.
            reserve: Reserves memory to prepare for mapping. An option
                used in Windows.

        """
        if self.disableNX:
            prot = prot | ProtType.EXEC
        self.logger.debug(
            f"Mapping region "
            f"0x{address:x} of size 0x{size:x} ({name}, {kind})"
        )
        self.num_bytes_mapped += size
        if self.num_bytes_mapped > self.MEM_LIMIT:
            self.logger.critical("OUT OF MEMORY")
            raise OutOfMemoryException
        self.emu.mem_map(
            address,
            size,
            name=name,
            kind=kind,
            module_name=module_name,
            prot=prot,
            shared=shared,
            reserve=reserve,
        )
        hooks = self._hook_manager._get_hooks(HookType.MEMORY.INTERNAL_MAP)

        # We chose not to pass the data for the map in the hook because
        # it drastically reduces performances.
        # (some ltp tests went from 2.6 -> 3.6 seconds)
        for hook in hooks:
            hook(0, address, size, None)

    def map_file(
        self,
        address: int,
        filename: str,
        offset: int = 0,
        size: int = 0,
        prot: int = ProtType.RWX,
        shared: bool = False,
    ) -> int:
        """
        Maps a region of memory at the specified address.

        Args:
            address: Address to map.
            filename: Name of the file to memory map
            offset: page-aligned offset of file to start mapping
            size: # of bytes to map. This will be rounded up to the
                nearest page.
            prot: An integer representing the RWX protection to be set
                on the mapped region.
            shared: if True, region is shared with subprocesses.

        """
        self.emu.mem_map_file(
            address,
            filename,
            offset=offset,
            size=size,
            prot=prot,
            shared=shared,
        )
        mr = self.get_region(address)
        hooks = self._hook_manager._get_hooks(HookType.MEMORY.INTERNAL_MAP)

        # We chose not to pass the data for the map in the hook because
        # it drastically reduces performances.
        # (some ltp tests went from 2.6 -> 3.6 seconds)
        for hook in hooks:
            hook(0, address, mr.size, None)

    def protect(self, address: int, size: int, prot: int) -> None:
        """
        Sets memory permissions on the specified memory region. Respects
        alignment of 0x1000.

        Args:
            address: Address of memory region to modify permissions.
                Rounds down to nearest 0x1000.
            size: Size of region to protect. Rounds up to nearest
                0x1000.
            prot: Desired RWX permissions.

        TODO:
            This does not correspond to Sections at the moment.

        """
        # return
        if self.disableNX:
            prot = prot | ProtType.EXEC
        aligned_address = address & 0xFFFFF000  # Address needs to align with
        aligned_size = util.align((address & 0xFFF) + size)
        try:
            self.emu.mem_protect(aligned_address, aligned_size, prot)
            self.logger.debug(
                "Protected region 0x%x + 0x%x, Prot: %x",
                aligned_address,
                aligned_size,
                prot,
            )
        except Exception as e:
            self.logger.error(
                f"Error trying to protect region "
                f"0x{aligned_address:x} + 0x{aligned_size:x}, "
                f"Prot: {prot:x}: {e}"
            )

    def unmap(self, address, size) -> None:
        """
        Unmaps a memory region, allowing it to be mapped again.

        Args:
            address: Address of section to be unmapped.
            size: Number of bytes to unmap.

        TODO:
            This currently only unmaps the section at the specified
            address. If size encompasses multiple sections, only the
            first will be unmapped.
            Also, unmaps that split up sections need work to maintain
            a correct representation in the Sections.

        """
        self.logger.debug(
            f"Unmapping region " f"0x{address:x} of size 0x{size:x}"
        )
        self.emu.mem_unmap(address, size)

    def get_base(self, address: int) -> Optional[int]:
        """
        Returns the base address of the memory region that contains this
        address.

        Returns:
            The base address of the containing region, or None if
            address is not contained within any region.

        TODO:
            This function should operate on the Section object.
            Also, clarity regions split by unmap is needed.
        """
        region = self.get_region(address)
        if region is None:
            return None
        return region.address

    def get_module_base(self, name: str) -> Optional[int]:
        regions = [
            mr
            for mr in self.get_regions()
            if os.path.basename(mr.module_name) == os.path.basename(name)
        ]
        if len(regions) == 0:
            return None
        return min([mr.address for mr in regions])

    def get_perms(self, address: int) -> int:
        """
        Returns the permissions of the section containg the given
        address.

        Args:
            address: Used to pick the containing section.

        Returns:
            Permissions of the containing section.
        """
        region = self.get_region(address)
        if region is None:
            return None
        return region.prot

    def get_size(self, address: int) -> int:
        """
        Returns the size of the section containg the given address.

        Args:
            address: Used to pick the containing section.

        Returns:
            Size of the containing section.
        """
        region = self.get_region(address)
        if region is None:
            return None
        return region.size

    # TODO: move to memory hook API
    def hook_first_read(self, region_addr, hook):
        region = self.get_region(region_addr)
        size = self.get_size(region_addr)
        perms = self.get_perms(region_addr)
        if region is None or size is None or perms is None:
            return False
        addr = region.address

        try:
            self.protect(addr, util.align(size), ProtType.NONE)
        except Exception:
            self.logger.exception(
                "Error trying to protect portion 0x%x + 0x%x, Prot: %x",
                addr,
                util.align(size),
                ProtType.NONE,
            )
        self.mem_hooks[addr] = _MemHook(addr, size, perms, hook)
        return True

    def _hook_read_prot(self, uc, access, address, size, value, user_data):
        region = self.get_region(address)
        addr = region.address if region is not None else None
        if addr not in self.mem_hooks:
            return False
        mem_hook = self.mem_hooks[addr]
        self.protect(
            mem_hook.addr, util.align(mem_hook.size), mem_hook.orig_perms
        )
        del self.mem_hooks[addr]
        return mem_hook.hook(uc, access, address, size, value, user_data)

    def is_writable(self, address: int) -> bool:
        """
        Returns True if writing memory is allowed at the specified
        address.
        """
        mr = self.get_region(address)
        if mr is None:
            return False
        return mr.prot & ProtType.WRITE != 0

    def get_region(self, address: int) -> Optional[MemoryRegion]:
        """ Gets the region that this address belongs to."""
        return self.emu.mem_region(address)

    def get_regions(self):
        """ Returns a list of all mapped memory regions."""
        return self.emu.mem_regions()

    def read_ptr(self, addr: int) -> int:
        return self.read_int(addr)

    def read_size_t(self, addr: int) -> int:
        return self.read_int(addr)

    def read_int64(self, addr: int) -> int:
        return self.read_int(addr, sz=8, signed=True)

    def read_uint64(self, addr: int) -> int:
        return self.read_int(addr, sz=8, signed=False)

    def read_int32(self, addr: int) -> int:
        return self.read_int(addr, sz=4, signed=True)

    def read_uint32(self, addr: int) -> int:
        return self.read_int(addr, sz=4, signed=False)

    def read_int16(self, addr: int) -> int:
        return self.read_int(addr, sz=2, signed=True)

    def read_uint16(self, addr: int) -> int:
        return self.read_int(addr, sz=2, signed=False)

    def read_int8(self, addr: int) -> int:
        return self.read_int(addr, sz=1, signed=True)

    def read_uint8(self, addr: int) -> int:
        return self.read_int(addr, sz=1, signed=False)

    def write_ptr(self, addr: int, value: int) -> int:
        return self.write_int(addr, value)

    def write_size_t(self, addr: int, value: int) -> int:
        return self.write_int(addr, value)

    def write_int64(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=8, signed=True)

    def write_uint64(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=8, signed=False)

    def write_int32(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=4, signed=True)

    def write_uint32(self, addr, value):
        return self.write_int(addr, value, sz=4, signed=False)

    def write_int16(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=2, signed=True)

    def write_uint16(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=2, signed=False)

    def write_int8(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=1, signed=True)

    def write_uint8(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=1, signed=False)

    def _has_overlap(self, requested_addr, size):
        """
        Checks to see whether a region at the requested address of the
        given size would overlap with an existing mapped region.
        """
        requested_end = requested_addr + size
        for region in self.get_regions():
            if requested_addr <= region.end and requested_end >= region.start:
                return True
        return False

    def find_free_space(
        self,
        size,
        preferred_address=None,
        min_addr=0x1000,
        max_addr=MAX_UINT32,
        alignment=0x10000,
        top_down=False,
    ):
        """
        Returns the start address of the next region between start and
        end that allows for memory of the given size to be mapped.
        """
        if preferred_address is not None and not self._has_overlap(
            preferred_address, size
        ):
            return preferred_address
        regions = self.get_regions()
        # Check if space before first region is free
        min_addr = util.align(min_addr, alignment=alignment)
        if len(regions) == 0 or min_addr + size <= regions[0].address:
            return min_addr
        # Check if space between regions is free
        for i in range(len(regions) - 1):
            gap_begin = util.align(
                max(regions[i].end, min_addr), alignment=alignment
            )
            gap_end = min(
                min(max_addr, gap_begin + size), regions[i + 1].start
            )
            gap_size = gap_end - gap_begin
            if gap_size >= size:
                return gap_begin
        # Check if space after last region is free
        gap_begin = util.align(
            max(regions[-1].end, min_addr), alignment=alignment
        )
        gap_end = max_addr
        gap_size = gap_end - gap_begin
        if gap_size >= size:
            return gap_begin
        return None

    def search(self, needle: bytes) -> List[int]:
        """
        Search for a sequence of bytes in memory. Returns all sequences
        that match
        """
        addrs = []
        for region in self.get_regions():
            haystack = self.read(region.start, region.size)
            addrs += [
                x.start(0) + region.start
                for x in re.finditer(needle, haystack)
            ]
        return addrs

    def _save_state(self):
        data = []
        for region in self.get_regions():
            if region.kind not in ["main", "mmap", "stack", "section"]:
                continue
            mem = self.read(region.address, region.size)
            data.append((region, mem))
        return data

    def _load_state(self, data):
        for meminfo, mem in data:
            self.logger.debug(
                "Loading: ", hex(meminfo.address), hex(meminfo.size), meminfo
            )
            mem = bytes(mem)
            try:
                self.write(meminfo.address, mem)
            except Exception:
                self.map(
                    meminfo.address,
                    util.align(meminfo.size),
                    meminfo.name,
                    meminfo.kind,
                )
                self.write(meminfo.address, mem)


class _HeapObjInfo:
    """ Information on a heap object. """

    def __init__(
        self,
        address,
        size,
        current_thread_name="",
        call_stack=None,
        name="unnamed",
    ):
        self.address = address
        self.size = size
        self.name = name
        # TODO(kvalakuzhy): More work needs to be done if we want to
        # have a robust call_stack implementation.
        self.call_stack = [] if call_stack is None else list(call_stack)
        self.accesses = defaultdict(dict)
        self.parent_thread = current_thread_name

    def call_stack_string(self):
        s = ""
        if len(self.call_stack) == 0:
            return s

        def func_name(call):
            max_name_size = 25
            if len(call.name) <= max_name_size:
                return "(" + call.name + ")"
            return "(" + call.name[:max_name_size] + "...)"

        s += " <- ".join(
            [func_name(call) for call in reversed(self.call_stack[-5:])]
        )
        if len(self.call_stack) > 5:
            s += " <- ..."
        return s

    def created_in_func(self):
        if len(self.call_stack) == 0:
            return None
        return self.call_stack[-1]

    def add_access(self, eip, access, address, size):
        self.accesses[address - self.address][eip] = (access, size)

    def is_accessed_at(self, eip):
        for accesses in self.accesses.values():
            if eip in accesses:
                return True
        return False

    def has_overflow(self):
        for offset, accesses in self.accesses.items():
            for access, size in accesses.values():
                if offset + size > self.size:
                    return True
        return False


class Heap:
    """ Helper class to manage heap allocation."""

    def __init__(self, memory, heap_start, heap_max_size):
        self.memory = memory
        self.logger = logging.getLogger(__name__)

        self.heap_start = heap_start
        self.current_offset = heap_start
        self.heap_max_size = heap_max_size
        self.heap_objects = SortedListWithKey(key=lambda x: x.address)

        # Initialize default process heap
        self.memory.map(
            self.heap_start,
            self.heap_max_size,
            name="main_heap",
            kind="heap",
            prot=ProtType.READ | ProtType.WRITE,
        )

    def _clear(self):
        # This function does not need to clear its memory, since memory
        # is in charge of that. It does need to clear it's tracking
        # though.
        self.current_offset = self.heap_start
        self.heap_objects.clear()

    def dealloc(self, size: int) -> int:
        """
        Returns memory from the heap.

        Args:
            size: # of bytes to return from the heap.

        Returns:
            Address of the new heap boundary.

        TODO:
            Deallocs should be aligned as well.
        """
        # TODO: Notify objects if they have been deallocated.
        if self.current_offset - size < self.heap_start:
            self.logger.notice(
                (
                    f"Failed to dealloc {size:x} from heap, "
                    "which would go beyond the heap start"
                )
            )
            return self.current_offset

        self.logger.debug(f"Deallocating {size:x} from heap")
        self.current_offset -= size
        return self.current_offset

    def alloc(self, size: int, name: str = None, align: int = 0x10) -> int:
        """
        Allocates memory to the heap. These are rounded up to the size
        of the alignment.

        Args:
            size: Number of bytes to allocate.
            name: Used to keep track of what information was allocated.
                Used for debugging
            align: Ensures that the memory allocated is a multiple of
                this value. Defaults to 4.

        Returns:
            Address of the new heap boundary
        """
        self.logger.debug(f"Allocating {size:x} bytes named {name}")
        ret = self.current_offset
        requested_size = util.align(size, alignment=align)
        if (
            self.current_offset + requested_size
            >= self.heap_start + self.heap_max_size
        ):
            self.logger.error(
                "Ran out of heap memory . Try increasing max heap size."
            )
            return ret
        self.current_offset += requested_size
        # TODO(kvalakuzhy): It would be nice if this could be moved into
        # a heap tracking class.
        self.heap_objects.add(_HeapObjInfo(ret, size, name=name))
        return ret

    def allocstr(
        self, s, terminal_null_byte=True, is_wide=False, alloc_name="allocstr"
    ):
        """
        Allocates a string to the heap. These are rounded up to the size
        of the alignment.

        Args:
            size: Number of bytes to allocate.
            name: Used to keep track of what information was allocated.
                Used for debugging
            align: Ensures that the memory allocated is a multiple of
                this value. Defaults to 4.

        Returns:
            Address of the new heap boundary
        """
        out_string = ""
        if is_wide:
            for c in s:
                out_string += c + "\x00"
            if terminal_null_byte:
                out_string += "\x00\x00"
        else:
            out_string = s
            if terminal_null_byte:
                out_string += "\x00"

        p_str = self.alloc(len(out_string), name=alloc_name)
        self.memory.write(p_str, out_string.encode())
        return p_str, len(out_string)


class _MemHook(object):
    def __init__(self, addr, size, perms, hook):
        self.addr = addr
        self.size = size
        self.orig_perms = perms
        self.hook = hook
