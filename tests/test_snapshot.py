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

from __future__ import absolute_import

import json
import unittest

from io import StringIO
from os import path

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class SnapshotTest(unittest.TestCase):
    def test_simple_snapshot(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        z.start()

        output = StringIO()
        z.plugins.snapshotter.snapshot(output)
        output.seek(0)

        data = output.read()[len("DISAS\n") :]
        memdump = json.loads(data)

        self.assertEqual(len(memdump["sections"]), 18)
        self.assertEqual(len(memdump["comments"]), 0)

    def test_snapshot_comments(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"), "-vv", fasttrace=True
        )

        z.start()

        output = StringIO()
        z.plugins.snapshotter.snapshot(output)
        output.seek(0)

        data = output.read()[len("DISAS\n") :]
        memdump = json.loads(data)

        self.assertEqual(len(memdump["sections"]), 18)
        self.assertGreater(len(memdump["comments"]), 0)

        self.assertEqual(memdump["comments"][0]["address"], 134515568)
        self.assertEqual(memdump["comments"][0]["text"], "ebp = 0x0")

        self.assertEqual(memdump["comments"][1000]["address"], 135680695)
        self.assertEqual(memdump["comments"][1000]["text"], "0x12 vs 0x1")

        self.assertEqual(memdump["comments"][2000]["address"], 135673274)
        self.assertEqual(
            memdump["comments"][2000]["text"], "store(0xff08ecfc,0x4)"
        )

        self.assertEqual(memdump["comments"][4000]["address"], 134521663)
        self.assertEqual(
            memdump["comments"][4000]["text"], "push(0x81e7a54) -> 0"
        )
