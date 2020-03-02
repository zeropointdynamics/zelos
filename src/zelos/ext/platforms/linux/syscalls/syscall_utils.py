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


def twos_comp(val, bits):
    """compute the 2's complement of int value val"""
    if (
        val & (1 << (bits - 1))
    ) != 0:  # if sign bit is set e.g., 8bit: 128-255
        val = val - (1 << bits)  # compute negative value
    return val  # return positive value as is


_FSMSR = 0xC0000100
_GSMSR = 0xC0000101


def _set_msr(p, msr, value):
    """
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given scratch address, as it
    emits some code.
    """
    emu = p.emu
    memory = p.memory
    # save clobbered registers
    orax = emu.get_reg("rax")
    ordx = emu.get_reg("rdx")
    orcx = emu.get_reg("rcx")
    orip = emu.get_reg("rip")

    # In addition, special handling needs to be done for setting and
    # getting the fs and gs registers
    # x86: wrmsr
    buf = b"\x0f\x30"
    buf_ptr = memory.map_anywhere(2, "wrmsr inst")
    memory.write(buf_ptr, buf)
    # x86: wrmsr
    emu.set_reg("rax", value & 0xFFFFFFFF)
    emu.set_reg("rdx", (value >> 32) & 0xFFFFFFFF)
    emu.set_reg("rcx", msr & 0xFFFFFFFF)
    emu.emu_start(buf_ptr, buf_ptr + len(buf), count=1)

    # stop for all syscalls

    # restore clobbered registers
    emu.set_reg("rax", orax)
    emu.set_reg("rdx", ordx)
    emu.set_reg("rcx", orcx)
    emu.set_reg("rip", orip)


def _get_msr(p, msr):
    """
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given scratch address, as it
    emits some code.
    """

    emu = p.emu
    memory = p.memory
    # save clobbered registers
    orax = emu.get_reg("rax")
    ordx = emu.get_reg("rdx")
    orcx = emu.get_reg("rcx")
    orip = emu.get_reg("rip")

    # x86: rdmsr
    buf = "\x0f\x32"
    buf_ptr = memory.heap.alloc(2, "wrmsr inst")
    memory.write(buf_ptr, buf)

    emu.set_reg("rcx", msr & 0xFFFFFFFF)
    emu.emu_start(buf_ptr, buf_ptr + len(buf), count=1)
    eax = emu.get_reg("eax")
    edx = emu.get_reg("edx")

    # restore clobbered registers
    emu.set_reg("rax", orax)
    emu.set_reg("rdx", ordx)
    emu.set_reg("rcx", orcx)
    emu.set_reg("rip", orip)

    return (edx << 32) | (eax & 0xFFFFFFFF)


def set_gs(p, addr):
    GSMSR = 0xC0000101
    return _set_msr(p, GSMSR, addr)


def get_gs(p):
    GSMSR = 0xC0000101
    return _get_msr(p, GSMSR)


def set_fs(p, addr):
    FSMSR = 0xC0000100
    return _set_msr(p, FSMSR, addr)


def get_fs(p):
    FSMSR = 0xC0000100
    return _get_msr(p, FSMSR)
