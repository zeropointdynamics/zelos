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
import logging

from typing import Dict, Iterable, List

from unicorn import UC_ARCH_ARM, UC_ARCH_MIPS, UC_ARCH_X86

from zelos.exceptions import InvalidRegException, ZelosLoadException
from zelos.util import columnate, struct


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

    def __init__(self, unicorn_engine, state):
        self.unicorn_engine = unicorn_engine
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.state = state

    # This allows the emu helper to have all of the functionality of the
    # unicorn engine

    def __getattr__(self, attr):
        return getattr(self.unicorn_engine, attr)

    @property
    def regmap(self):
        raise NotImplementedError()

    @property
    def bytes(self) -> int:
        return self.state.bytes

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
            return self.reg_read(self.regmap[reg_name])
        except KeyError:
            raise InvalidRegException(reg_name)

    def set_reg(self, reg_name: str, val: int) -> None:
        try:
            self.reg_write(self.regmap[reg_name], val)
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

    ###############
    # FOR UTILITY #
    ###############

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
        Unpacks an integer from a byte format. Defaults to the
        current architecture bytes and endianness.
        """
        endian_char, bit_char, bit_mask = self._pack_format(
            bytes, little_endian, signed
        )
        return struct.pack(endian_char + bit_char, x & bit_mask)

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
        endian_char, bit_char, bit_mask = self._pack_format(
            bytes, little_endian, signed
        )
        return struct.unpack(endian_char + bit_char, x)[0]

    def _pack_format(self, bytes: int, little_endian: bool, signed: bool):
        """
        Generates the format for the struct.pack and unpack functions.
        Defaults to the current architecture bytes and endianness
        """
        if bytes is None:
            bytes = self.bytes
        if little_endian is None:
            little_endian = self.state.endianness == "little"
        bits = bytes * 8

        bit_char = {8: "B", 16: "H", 32: "I", 64: "Q"}[bits]
        bit_mask = 2 ** bits - 1

        if signed:
            bit_char = bit_char.lower()
        endian_char = "<" if little_endian else ">"
        return endian_char, bit_char, bit_mask


def create_emulator(arch, mode, state) -> IEmuHelper:
    """
    Factory method for constructing the appropriate IEmuHelper
    """
    from unicorn.unicorn import UcError
    from unicorn import Uc

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
            f"Custom unicorn does not support the arch/mode/bits"
            + f" {arch}/{mode}/{state.bits}"
        )
