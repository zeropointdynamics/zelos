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

from collections import defaultdict
from string import printable
from typing import List, Optional

from sortedcontainers import SortedDict, SortedListWithKey

import zelos.util as util

from zelos.enums import ProtType
from zelos.exceptions import OutOfMemoryException


class Section:
    """
    Represents a region of memory that has been mapped.
    """

    def __init__(
        self,
        emu,
        address,
        size,
        name,
        kind,
        module_name,
        reserve=False,
        ptr=None,
    ):
        self.emu = emu
        self.address = address
        self.size = size
        self.name = name
        self.kind = kind
        self.module_name = module_name
        self.reserved = reserve

        # If the ptr is set, this means the section is ptr mapped.
        # These sections should be shared across processes
        self.ptr = ptr

    def __str__(self):
        s = f"0x{self.address:08x}-0x{self.address+self.size:08x}: "
        s += f"{self.module_name} {self.name}, {self.kind}"
        if self.ptr is not None:
            s += " (p)"
        return s

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def get_data(self) -> bytearray:
        """
        Returns all data in the region.

        Returns:
            Data from the region.
        """
        return self.emu.mem_read(self.address, self.size)

    def entropy(self) -> float:
        """
        Calculates the entropy of data contained within the section.

        Returns:
            Entropy of this section.
        """
        data = self.get_data()
        import numpy as np
        from scipy.stats import entropy

        value, counts = np.unique(data, return_counts=True)
        return entropy(counts)

    def get_strings(self, min_len: int = 5) -> List[str]:
        """
        Returns all strings found in the region's memory.

        Args:
            min_len: The minimum length a string must be to be included
                in the output.

        Returns:
            List of strings found within this section's data.

        """
        strings = []
        string_so_far = ""
        data = self.get_data()
        for c in data:
            if chr(c) in printable:
                string_so_far += chr(c)
            else:
                if len(string_so_far) >= min_len:
                    strings.append(string_so_far)
                string_so_far = ""

        # Also look for wide strings
        string_so_far = ""
        i = 0
        while i + 1 < len(data):
            c = chr(data[i])
            if c in printable and data[i + 1] == 0:
                string_so_far += c
                i += 2
            else:
                if len(string_so_far) >= min_len:
                    strings.append(string_so_far)
                string_so_far = ""
                i += 1

        return strings


class Memory:
    """
    Responsbile for interactions with emulated memory.
    """

    # Users of memory class should use memory's protection definitions
    # defined here instead of unicorn constants directly.

    HEAP_BASE = 0x90000000
    HEAP_MAX_SIZE = 100 * 1024 * 1024

    # A separate heap base for virtual allocations
    VALLOC_BASE = 0x00C50000

    MAX_UINT64 = 0xFFFFFFFFFFFFFFFF

    def __init__(
        self,
        emu,
        state,
        lowest_addr: int = 0,
        max_addr: int = MAX_UINT64,
        disableNX: bool = False,
    ) -> None:
        self.emu = emu
        self.state = state
        self.logger = logging.getLogger(__name__)

        self.max_addr = max_addr
        self.disableNX = disableNX

        from unicorn import UC_HOOK_MEM_READ_PROT

        self.emu.hook_add(UC_HOOK_MEM_READ_PROT, self._hook_read_prot)
        self.mem_hooks = dict()

        # Prevent runaway allocation
        self.MEM_LIMIT = 3 * 1024 * 1024 * 1024

        self._setup()

        self.heap = Heap(self, self.emu, self.HEAP_BASE, self.HEAP_MAX_SIZE)

    def _setup(self):
        """Sets up variables after init or after memory is cleared."""
        self.memory_info = SortedDict()
        self.memory_info[0] = Section(
            self.emu, 0x0, 0x1000, "reserved", "zelos", "", False
        )

        self.num_bytes_mapped = 0

        # Keep track of memory changes that have been made.
        self.initial_memory_state = {}

        # Current virual allocation location
        self.VALLOC_CUR = self.VALLOC_BASE

    def __str__(self):
        s = "Memory Manager:\n"
        for info in self.memory_info.values():
            s += "  {0}\n".format(info)
        return s

    def copy(self, other_memory: "Memory") -> None:
        """
        Creates the same state in other_memory.

        Args:
            other_memory: Memory that will contain a copy of self.
        """
        for (start, end, prot) in self.emu.mem_regions():
            self.logger.spam(f"Clearing {start:x}-{end:x}")
            size = end + 1 - start
            self.emu.mem_unmap(start, size)

        self.heap._clear()

        self._setup()

        # Copy the Memory metadata
        for section in other_memory.memory_info.values():
            self.copy_section(section, other_memory)

        # other tidbits
        self.max_addr = other_memory.max_addr
        self.disableNX = other_memory.disableNX
        self.num_bytes_mapped = other_memory.num_bytes_mapped
        self.heap = other_memory.heap

    def clear(self) -> None:
        """
        Clears all of memory
        """
        for (start, end, prot) in self.emu.mem_regions():
            self.logger.spam(f"Clearing {start:x}-{end:x}")
            size = end + 1 - start
            self.emu.mem_unmap(start, size)

        self.heap._clear()

        self._setup()

        self.heap = Heap(self, self.emu, self.HEAP_BASE, self.HEAP_MAX_SIZE)

    def get_sections(self) -> List[Section]:
        """
        Gets meaningful sections from Zelos in memory. Reserved sections
        are not guaranteed to be written into Zelos, so memory
        operations on these addresses may not be meaningful.

        Returns:
            Sections present in memory.
        """
        return [
            meminfo
            for meminfo in self.memory_info.values()
            if meminfo.name not in ["reserved"]
        ]

    def record_initial_memory_state(self) -> None:
        """
        We record the initial memory state in order to use it to tell
        what memory has changed.
        """
        if len(self.initial_memory_state) > 0:
            return
        for section in self.get_sections():
            self.initial_memory_state[section.address] = (
                section,
                section.get_data(),
            )

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
        return self.emu.mem_read(addr, size)

    def write(self, addr: int, data: bytes) -> None:
        """
        Writes specified bytes to memory. Requires that the specified
        address is mapped.

        Args:
            addr: Address to start writing data to.
            data: Bytes to write in memory.
        """
        self.emu.mem_write(addr, data)

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
        value = self.emu.mem_read(addr, sz)
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
        self.emu.mem_write(addr, packed)
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
        if addr == 0:
            return ""
        data = b""
        try:
            for i in range(size):
                byte = bytes(self.emu.mem_read(addr + i, 1))
                if byte == b"\x00":
                    break
                data += byte
            # TODO: Allow for different decodings.
            return data.decode()
        except Exception as e:
            # TODO: We need to differentiate between attempts to check
            # if a string exists or if expecting a string to exist. We
            # shouldn't log an error if we aren't expecting the string
            # to exist.
            self.logger.debug(
                "Couldn't read str at 0x{0:x}: {1}".format(addr + i, e)
            )
            return ""

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
                chars = self.emu.mem_read(addr + i, 2)
                if chars == b"\x00\x00":
                    break
                data += chars
            return data.decode("utf-16")
        except Exception:
            print("Couldn't read wstr at 0x{0:x}".format(addr + i))
            return ""

    def get_punicode_string(self, addr: int) -> str:
        # punicode
        # length        ushort
        # maxlength     ushort
        # wstring        pvoid
        try:
            length = self.read_uint16(addr)
            string_pointer = self.read_ptr(addr + 4)
            if length == 0:
                value = self.read_wstring(string_pointer)
            else:
                value = self.read_wstring(string_pointer, length)
            return value
        except Exception as e:
            print("Could not read string @", hex(addr), ":", e)
            return ""

    def get_pansi_string(self, addr: int) -> int:
        # punicode
        # length        ushort
        # maxlength     ushort
        # string        pvoid
        try:
            length = self.read_uint16(addr)
            string_pointer = self.read_ptr(addr + 4)
            if length == 0:
                value = self.read_string(string_pointer)
            else:
                value = self.read_string(string_pointer, length)
            return value
        except Exception as e:
            print("Could not read string @", hex(addr), ":", e)
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
            self.emu.mem_write(addr, byte_value)
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
        self.emu.mem_write(addr, byte_value)
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
        data = self.emu.mem_read(addr, ctypes.sizeof(obj))
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
        self.emu.mem_write(address, data)
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
        name: str = "",
        kind: str = "",
        min_addr: int = 0,
        max_addr: int = 0xFFFFFFFFFFFFFFFF,
        alignment: int = 0x1000,
        prot: int = ProtType.RWX,
    ) -> int:
        """
        Maps a region of memory with requested size, within the
        addresses specified. The size and start address will respect the
        alignment.

        Args:
            size: # of bytes to map. This will be rounded up to match
                the alignment.
            name: String used to identify mapped region. Used for
                debugging.
            kind: String used to identify the purpose of the mapped
                region. Used for debugging.
            min_addr: The lowest address that could be mapped.
            max_addr: The highest address that could be mapped.
            alignment: Ensures the size and start address are multiples
                of this. Must be a multiple of 0x1000. Default 0x1000.
            prot: RWX permissions of the mapped region. Defaults to
                granting all permissions.
        Returns:
            Start address of mapped region.
        """
        address = self._find_free_space(
            size, min_addr=min_addr, max_addr=max_addr, alignment=alignment
        )
        self.map(address, util.align(size), name, kind)
        return address

    def map(
        self,
        address: int,
        size: int,
        name: str = "",
        kind: str = "",
        module_name: str = "",
        prot: int = ProtType.RWX,
        ptr: Optional[ctypes.POINTER] = None,
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

        if ptr is None:
            self.emu.mem_map(address, size)
            if prot != ProtType.RWX:
                self.protect(address, size, prot)
        else:
            self.logger.debug(
                f"mapping "
                f"{address:x}, size: {size:x}, prot {prot:x}, ptr: {ptr}"
            )
            self.emu.mem_map_ptr(address, size, prot, ptr)
        self._new_section(
            address, size, name, kind, module_name, reserve=reserve, ptr=ptr
        )

    def copy_section(self, section: Section, other_memory: "Memory") -> None:
        """
        Copies a section from this instance of memory into another
        instance of memory.

        Args:
            section: The section to copy. Must correspond to a section
                within this memory object.
            other_memory: An instance of memory to copy the specified
                section to.
        """
        start = section.address
        size = section.size
        end = start + size

        # We have the beginning mapped for special addresses
        if start == 0:
            return

        # Some sections are added to differentiate different sections in
        # the binary. These are typically not aligned. If they are,
        # should only be an extra copy.
        if start != util.align(start) or end != util.align(end):
            return

        self.logger.spam(f"Copying {start:x}-{end:x}")

        if section.ptr is None:
            data = other_memory.read(start, size)
            self.map(start, size)
            self.write(start, bytes(data))
        else:
            self.map(start, size, ptr=section.ptr)
        self._new_section(
            section.address,
            section.size,
            name=section.name,
            kind=section.kind,
            module_name=section.module_name,
            ptr=section.ptr,
        )

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
        if address in self.memory_info.keys():
            section_size = self.memory_info[address].size
            if size != section_size:
                self.logger.info(
                    "Deleting section, though size is not the same "
                    "(was %x, requested %x)",
                    section_size,
                    size,
                )
            del self.memory_info[address]

            self.emu.mem_unmap(address, size)
        else:
            self.logger.info("Attempting to unmap part of alloc section")
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
        regions = self.emu.mem_regions()
        for region in regions:
            addr = region[0]
            size = region[1] - addr + 1
            if address >= addr and address < addr + size:
                return addr
        return None

    def get_perms(self, address: int) -> int:
        """
        Returns the permissions of the section containg the given
        address.

        Args:
            address: Used to pick the containing section.

        Returns:
            Permissions of the containing section.
        """
        regions = self.emu.mem_regions()
        for region in regions:
            addr = region[0]
            size = region[1] - addr + 1
            perm = region[2]
            if address >= addr and address < addr + size:
                return perm
        return None

    def get_size(self, address: int) -> int:
        """
        Returns the size of the section containg the given address.

        Args:
            address: Used to pick the containing section.

        Returns:
            Size of the containing section.
        """
        regions = self.emu.mem_regions()
        for region in regions:
            addr = region[0]
            size = region[1] - addr + 1
            if address >= addr and address < addr + size:
                return size
        return None

    def hook_first_read(self, region_addr, hook):
        region = self.get_region(region_addr)
        size = self.get_size(region_addr)
        perms = self.get_perms(region_addr)
        if region is None or size is None or perms is None:
            return False
        addr = region.address

        try:
            self.emu.mem_protect(addr, util.align(size), ProtType.NONE)
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
        self.emu.mem_protect(
            mem_hook.addr, util.align(mem_hook.size), mem_hook.orig_perms
        )
        del self.mem_hooks[addr]
        return mem_hook.hook(uc, access, address, size, value, user_data)

    def get_region(self, address):
        """ Gets the region that this address belongs to."""
        for section in self.memory_info.values():
            if section.address <= address < section.address + section.size:
                return section
        return None

    def get_initial_region(self, address):
        """
        Returns the initial region that contained this address, along
        with the memory at that time.
        """
        for (section, mem) in self.initial_memory_state.values():
            if section.address <= address < section.address + section.size:
                return (section, mem)
        return (None, None)

    def get_region_hash(self):
        """ Used for determining whether a memory region has changed"""
        hashes = {}
        for region in self.memory_info.values():
            try:
                hashes[region.address] = region.get_data()
            except Exception:
                pass
        return hashes

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

    def write_uint32(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=4, signed=False)

    def write_int16(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=2, signed=True)

    def write_uint16(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=2, signed=False)

    def write_int8(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=1, signed=True)

    def write_uint8(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, sz=1, signed=False)

    def pack(
        self,
        x: int,
        bytes: int = None,
        little_endian: bool = None,
        signed: bool = False,
    ) -> bytes:
        """
        Unpacks an integer from a byte format. Defaults to the
        current architecture bytes and endianness.
        """
        return self.emu.pack(
            x, bytes=bytes, little_endian=little_endian, signed=signed
        )

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
        return self.emu.unpack(
            x, bytes=bytes, little_endian=little_endian, signed=signed
        )

    def _new_section(
        self,
        address: int,
        size: int,
        name: str = "",
        kind: str = "",
        module_name: str = "",
        ptr: Optional[ctypes.POINTER] = None,
        reserve: bool = False,
    ):
        if size == 0:
            self.logger.notice("Will not insert region of size 0")
            return
        self.memory_info[address] = Section(
            self.emu,
            address,
            size,
            name,
            kind,
            module_name,
            ptr=ptr,
            reserve=reserve,
        )

    def _has_overlap(self, requested_addr, size):
        """
        Checks to see whether a region at the requested address of the
        given size would overlap with an existing mapped region.
        """
        requested_end = requested_addr + size
        for region in self.emu.mem_regions():
            region_begin = region[0]
            region_end = region[1]
            if requested_addr <= region_end and requested_end >= region_begin:
                return True
        return False

    def _get_next_gap(self, size, start, end):
        """
        Returns the start address of the next region between start and
        end that allows for memory of the given size to be mapped.
        """
        min_addr_so_far = start
        for region in sorted(list(self.emu.mem_regions()), key=lambda x: x[0]):
            region_begin = region[0]
            region_end = region[1]
            if region_begin >= end or region_end < start:
                continue

            gap = region_begin - min_addr_so_far
            if gap < size:
                min_addr_so_far = util.align(region_end)
                continue
            return min_addr_so_far
        # Check to see there is a gap after the last region
        gap = end - min_addr_so_far
        if gap < size:
            self.logger.error(
                "No gap of size %x between %x and %x" % (size, start, end)
            )
        return min_addr_so_far

    # Allocate a chunk of memory at the requested address. If the
    # requested address is not available, find the first available chunk
    # of memory greater or equal to min_base. Returns the address of the
    # allocated chunk, or zero on failure.
    # This method was added after map_anywhere, due to legacy reasons.
    # Look into combining the two functionalities

    def _alloc_at(
        self,
        name,
        kind,
        module_name,
        requested_addr,
        size,
        min_addr=0x60000000,
        max_addr=0x90000000,
        prot=ProtType.RWX,
        ptr=None,
    ):
        # if requested_addr < min_addr:
        #     requested_addr = min_addr
        if requested_addr > max_addr:
            requested_addr = min_addr
        size = util.align(size)
        relocated_addr = 0
        if self._has_overlap(requested_addr, size):
            relocated_addr = self._get_next_gap(size, min_addr, max_addr)

            self.logger.debug(
                "[Loader] Relocating Overlapping Region from "
                "0x{0:08x} to 0x{1:08x}".format(requested_addr, relocated_addr)
            )
            try:
                self.map(
                    relocated_addr,
                    size,
                    name,
                    kind,
                    module_name=module_name,
                    prot=prot,
                    ptr=ptr,
                )
                return relocated_addr
            except Exception:
                self.logger.exception("Couldn't relocate properly")
                exit()
        else:
            self.map(
                requested_addr,
                size,
                name,
                kind,
                module_name=module_name,
                prot=prot,
                ptr=ptr,
            )
        return requested_addr

    def _is_free(self, address):
        """
        Returns whether a specified addrss is free or already part of an
        allocated region.
        """
        for section in self.memory_info.values():
            if (
                address >= section.address
                and address < section.address + section.size
            ):
                return False
        for region in list(self.emu.mem_regions()):
            if address >= region[0] and address < region[1]:
                return False
        return True

    def _find_free_space(
        self, size, min_addr=0, max_addr=MAX_UINT64, alignment=0x10000
    ):
        """
        Finds a region of memory that is free, larger than 'size' arg,
        and aligned.
        """
        sections = list(self.memory_info.values())
        for i in range(0, len(sections)):
            addr = util.align(
                sections[i].address + sections[i].size, alignment=alignment
            )
            # Enable allocating memory in the middle of a gap when the
            # min requested address falls in the middle of a gap
            if addr < min_addr:
                addr = min_addr
            # Cap the gap's max address by accounting for the next
            # section's start address, requested max address, and the
            # max possible address
            max_gap_addr = (
                self.max_addr
                if i == len(sections) - 1
                else sections[i + 1].address
            )
            max_gap_addr = min(max_gap_addr, max_addr)
            # Ensure the end address is less than the max and the start
            # address is free
            if addr + size < max_gap_addr and self._is_free(addr):
                return addr
        raise OutOfMemoryException()

    def _save_state(self):
        data = []
        for address, meminfo in self.memory_info.items():
            if meminfo.kind not in ["main", "mmap", "stack", "section"]:
                continue
            mem = self.emu.mem_read(address, meminfo.size)
            data.append((meminfo, mem))
        return data

    def _load_state(self, data):
        for meminfo, mem in data:
            self.logger.debug(
                "Loading: ", hex(meminfo.address), hex(meminfo.size), meminfo
            )
            mem = bytes(mem)
            try:
                self.emu.mem_write(meminfo.address, mem)
            except Exception:
                self.map(
                    meminfo.address,
                    util.align(meminfo.size),
                    meminfo.name,
                    meminfo.kind,
                )
                self.emu.mem_write(meminfo.address, mem)


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

    def __init__(self, memory, emu, heap_start, heap_max_size):
        self.memory = memory
        self.emu = emu
        self.logger = logging.getLogger(__name__)

        self.heap_start = heap_start
        self.current_offset = heap_start
        self.heap_max_size = heap_max_size
        self.heap_objects = SortedListWithKey(key=lambda x: x.address)

        self._setup()

    def _setup(self):
        # Initialize default process heap
        self.memory.map(
            self.heap_start,
            self.heap_max_size,
            "main_heap",
            "heap",
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

    def alloc(self, size: int, name: str = None, align: int = 0x4) -> int:
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
        self.emu.mem_write(p_str, out_string.encode())
        return p_str, len(out_string)


class _MemHook(object):
    def __init__(self, addr, size, perms, hook):
        self.addr = addr
        self.size = size
        self.orig_perms = perms
        self.hook = hook
