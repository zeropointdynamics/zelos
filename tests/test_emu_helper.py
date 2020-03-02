# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.


# <http://www.gnu.org/licenses/>.
# ======================================================================
from __future__ import absolute_import

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
import unittest

from zelos import Zelos


class EmuHelperTest(unittest.TestCase):
    def test_pack(self):
        z = Zelos(None)
        emu = z.internal_engine.emu
        self.assertEqual(123, emu.unpack(emu.pack(123)))
        self.assertEqual(-1, emu.unpack(emu.pack(-1), signed=True))


def main():
    unittest.main()


if __name__ == "__main__":
    main()
