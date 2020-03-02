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

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
import unittest

from zelos.plugin import ArgFactory


class ArgFactoryTest(unittest.TestCase):
    def test_create_args(self):
        arg_factory = ArgFactory(lambda arg: "")

        args = arg_factory.gen_args(
            [("int", "fd"), ("void*", "buf"), ("size_t", "count")],
            [0x4, 0xDEADBEEF, 0x10],
        )
        self.assertEqual(args.fd, 0x4)
        self.assertEqual(args.buf, 0xDEADBEEF)
        self.assertEqual(args.count, 0x10)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
