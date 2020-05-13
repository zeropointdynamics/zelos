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

from io import StringIO
from unittest.mock import patch

import zelos.util as util

from zelos.ext.platforms.linux.syscalls.syscall_structs import (
    MMSGHDR,
    SIGACTION,
)


class UtilTest(unittest.TestCase):
    def test_align(self):
        self.assertEqual(0x1000, util.align(0x1000))
        self.assertEqual(0x2000, util.align(0x1001))
        self.assertEqual(0x1000, util.align(1))
        self.assertEqual(0x12000, util.align(0x11002))

        self.assertEqual(0x14, util.align(0x11, alignment=0x4))
        self.assertEqual(0x10, util.align(0xF, alignment=0x4))

    def test_dumpstruct(self):
        mmsghdr = MMSGHDR()  # nested struct
        sigact = SIGACTION()  # flat struct
        with patch("sys.stdout", new=StringIO()) as stdout:
            util.dumpstruct(mmsghdr)
            self.assertIn("MSGHDR object at", stdout.getvalue())
            self.assertIn("msg_name: 0x0", stdout.getvalue())
            self.assertIn("msg_len: 0x0", stdout.getvalue())

            util.dumpstruct(sigact)
            self.assertIn("sa_handler: 0x0", stdout.getvalue())
            self.assertIn("sa_mask: 0x0", stdout.getvalue())
