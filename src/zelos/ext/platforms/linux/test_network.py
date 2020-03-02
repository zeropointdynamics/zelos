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

from zelos.ext.platforms.linux.network import _bytes_to_host
from zelos.ext.platforms.linux.syscalls.syscalls_const import SocketFamily


class NetworkTest(unittest.TestCase):
    def test_helper_funcs(self):
        self.assertEqual(
            _bytes_to_host(0x80706050, SocketFamily.AF_INET), "80.96.112.128"
        )


def main():
    unittest.main()


if __name__ == "__main__":
    main()
