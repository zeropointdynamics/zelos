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

import ctypes

from typing import Optional

from zelos.enums import ProtType


class MemoryApi:
    def __init__(self, zelos):
        self._zelos = zelos

    @property
    def _memory(self):
        return self._zelos.internal_engine.memory

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
        return self._memory.read(addr, size)

    def write(self, addr: int, data: bytearray) -> None:
        """
        Writes specified bytes to memory. Requires that the specified
        address is mapped.

        Args:
            addr: Address to start writing data to.
            data: Bytes to write in memory.
        """
        return self._memory.write(addr, bytes(data))

    def read_int(
        self, addr: int, size: int = None, signed: bool = False
    ) -> int:
        """
        Reads an integer value from the specified address. Can handle
        multiple sizes and representations of integers.

        Args:
            addr: Address to begin reading int from.
            size: Size (# of bytes) of integer representation. If None,
                uses the architecture to determine size (32 bit -> 4,
                64bit -> 8). Default is None.
            signed: If true, interpret bytes as signed integer. Default
                false.

        Returns:
            Integer represntation of bytes read.
        """
        return self._memory.read_int(addr, size, signed)

    def write_int(
        self, addr: int, value: int, size: int = None, signed: bool = False
    ) -> int:
        """
        Writes an integer value to the specified address. Can handle
        multiple sizes and representations of integers.

        Args:
            addr: Address in memory to write integer to.
            value: Integer to write into memory.
            size: Size (# of bytes) to write into memory. If None,
                uses the architecture to determine size (32 bit -> 4,
                64bit -> 8). Default is None.
            signed: If true, write number as signed integer. Default
                false.

        Returns:
            Number of bytes written to memory.
        """
        return self._memory.write_int(addr, value, size, signed)

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
        return self._memory.read_string(addr, size)

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
        return self._memory.write_wstring(addr, size)

    def read_punicode_string(self, addr: int) -> str:
        """
        Given the address of a pointer to a unicode string, returns the
        string that was pointed to as a python string.

        Args:
            addr: Address of the unicode string pointer

        Returns:
            String read from memory
        """
        return self._memory.get_punicode_string(addr)

    def read_pansi_string(self, addr: int) -> int:
        """
        Given the address of a pointer to a ANSI string, returns the
        string that was pointed to as a python string.

        Args:
            addr: Address of the ANSI string pointer

        Returns:
            String read from memory
        """
        return self._memory.get_pansi_string(addr)

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
        return self._memory.write_string(addr, value, terminal_null_byte)

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
        return self._memory.write_wstring(addr, value, terminal_null_byte)

    def readstruct(self, addr: int, obj: ctypes.Structure) -> ctypes.Structure:
        """
        Reads a ctypes structure from memory.

        Args:
            addr: Address in memory to begin reading structure from.
            obj: An instance of the structure to create from memory.

        Returns:
            Instance of structure read from memory.

        Example:
            .. code-block:: python

                class SIGACTION(ctypes.Structure):
                    _fields_ = [
                        ("sa_handler", ctypes.c_uint64),
                        ("sa_flags", ctypes.c_uint64),
                        ("sa_restorer", ctypes.c_uint64),
                        ("sa_mask", ctypes.c_uint64),
                    ]

                # Pointer to sigaction struct
                pointer = 0xdeadbeef

                sigaction = api.memory.readstruct(pointer, SIGACTION())
                print(sigaction.sa_handler)
        """
        return self._memory.readstruct(addr, obj)

    def writestruct(self, address: int, structure: ctypes.Structure) -> int:
        """
        Write a ctypes Structure to memory.

        Args:
            addr: Address in memory to begin writing to.
            structure: An instance of the structure to write to memory.

        Returns:
            Number of bytes written to memory.

        Example:
            .. code-block:: python

                class SIGACTION(ctypes.Structure):
                    _fields_ = [
                        ("sa_handler", ctypes.c_uint64),
                        ("sa_flags", ctypes.c_uint64),
                        ("sa_restorer", ctypes.c_uint64),
                        ("sa_mask", ctypes.c_uint64),
                    ]

                sigaction = SIGACTION()
                sigaction.handler = 0xdeadbeef

                # Memory address to write struct to
                destination = 0xb0bad00d

                bytes_written = api.memory.writestruct(destination, sigaction)
        """
        return self._memory.writestruct(address, structure)

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
        return self._memory.map(
            address, size, name, kind, module_name, prot, ptr, reserve
        )

    def read_ptr(self, addr: int) -> int:
        """
        Reads a pointer at `addr`. The number of bytes read
        is dependent on the architecture of the binary.
        """
        return self._memory.read_ptr(addr)

    def read_size_t(self, addr: int) -> int:
        """
        Reads a value of type `size_t` at `addr`.
        """
        return self._memory.read_size_t(addr)

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
        return self._memory.pack(
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
        return self._memory.unpack(
            x, bytes=bytes, little_endian=little_endian, signed=signed
        )

    def read_int64(self, addr: int) -> int:
        return self._memory.read_int64(addr)

    def read_uint64(self, addr: int) -> int:
        return self._memory.read_uint64(addr)

    def read_int32(self, addr: int) -> int:
        return self._memory.read_int32(addr)

    def read_uint32(self, addr: int) -> int:
        return self._memory.read_uint32(addr)

    def read_int16(self, addr: int) -> int:
        return self._memory.read_int16(addr)

    def read_uint16(self, addr: int) -> int:
        return self._memory.read_uint16(addr)

    def read_int8(self, addr: int) -> int:
        return self._memory.read_int8(addr)

    def read_uint8(self, addr: int) -> int:
        return self._memory.read_uint8(addr)

    def write_ptr(self, addr: int, value: int) -> int:
        return self._memory.write_ptr(addr, value)

    def write_size_t(self, addr: int, value: int) -> int:
        return self._memory.write_size_t(addr, value)

    def write_int64(self, addr: int, value: int) -> int:
        return self._memory.write_int64(addr, value)

    def write_uint64(self, addr: int, value: int) -> int:
        return self._memory.write_uint64(addr, value)

    def write_int32(self, addr: int, value: int) -> int:
        return self._memory.write_int32(addr, value)

    def write_uint32(self, addr: int, value: int) -> int:
        return self._memory.write_uint32(addr, value)

    def write_int16(self, addr: int, value: int) -> int:
        return self._memory.write_int16(addr, value)

    def write_uint16(self, addr: int, value: int) -> int:
        return self._memory.write_uint16(addr, value)

    def write_int8(self, addr: int, value: int) -> int:
        return self._memory.write_int8(addr, value)

    def write_uint8(self, addr: int, value: int) -> int:
        return self._memory.write_uint8(addr, value)
