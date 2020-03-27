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


# These msr registers are x86 specific
_FSMSR = 0xC0000100
_GSMSR = 0xC0000101


def set_gs(p, addr):
    p.emu.msr_write(_GSMSR, addr)


def get_gs(p):
    return p.emu.msr_read(_GSMSR)


def set_fs(p, addr):
    p.emu.msr_write(_FSMSR, addr)


def get_fs(p):
    return p.emu.msr_read(_FSMSR)
