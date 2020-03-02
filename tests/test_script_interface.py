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

import unittest

from zelos import Zelos


class ZelosTest(unittest.TestCase):
    def test_invalid_args(self):
        self.assertRaises(
            SystemExit,
            Zelos,
            "tests/data/static_elf_helloworld",
            invalid_arg="testval",
        )


def main():
    unittest.main()


if __name__ == "__main__":
    main()
