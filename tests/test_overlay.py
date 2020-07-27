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
import os
import tempfile
import unittest

from io import StringIO
from os import path

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class OverlayTest(unittest.TestCase):
    def test_overlay_memory(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        z.start()

        output = StringIO()
        z.plugins.overlay.export(output, mem=True)
        output.seek(0)

        data = output.read()[len("DISAS\n") :]
        memdump = json.loads(data)

        self.assertEqual(len(memdump["sections"]), 18)
        self.assertEqual(len(memdump["comments"]), 0)

    def test_overlay_comments(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            inst=True,
            fasttrace=True,
            export_trace=True,
            trace_off=True,
        )

        directory = tempfile.TemporaryDirectory()
        # The exported file is written to the directory that zelos is
        # run in
        original_dir = os.path.abspath(os.path.curdir)
        try:
            os.chdir(directory.name)
            z.start()
            z.close()
        finally:
            os.chdir(original_dir)

        output = open(path.join(directory.name, "static_elf_helloworld.zmu"))

        data = output.read()[len("DISAS\n") :]
        memdump = json.loads(data)
        self.assertGreaterEqual(len(memdump["comments"]), 8277)

        self.assertEqual(len(memdump["functions"]), 244)

        self.assertEqual(memdump["comments"][0]["address"], 134515568)
        self.assertEqual(memdump["comments"][0]["text"], "ebp = 0x0")
        output.close()
