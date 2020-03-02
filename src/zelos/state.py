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
import datetime


class State:
    """
    This maintains all state that is useful internally to other
    Components, but does not belong in any specific one.
    """

    def __init__(self, z, binary, date):
        if binary is not None:
            self.bits = binary.Bits
            self.arch = binary.Architecture
        else:
            self.bits = 32
            self.arch = "x86"

        self.date = date
        self.datetime = datetime.datetime.now()

        # Whether or not to implement our modification to Unicorn's TCG
        # generation. Extra speed, but hooking behavior is different.
        self.patched_unicorn_enabled = False

        self.endianness = self.__get_endianness(binary)

    @property
    def is64(self):
        return self.bits == 64

    @property
    def bytes(self):
        assert self.bits % 8 == 0, "Bits is not a multiple of 8"
        return self.bits // 8

    def __get_endianness(self, binary):
        try:
            id = binary.binary.header.identity_data
            assert id != id.NONE, "currently only 32 bit is supported"
            if id == id.MSB:
                return "big"
            elif id == id.LSB:
                return "little"
            else:
                return "unknown"
        except Exception:
            return "little"
