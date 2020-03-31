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

import unittest

from io import StringIO
from os import path
from unittest.mock import patch

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class TraceTest(unittest.TestCase):
    def test_traceon(self):

        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.plugins.trace.traceon(0x08131B16)

        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            self.assertNotIn("[080f5c00]", stdout.getvalue())
            self.assertIn("[08131b16]", stdout.getvalue())

    def test_traceoff(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), verbosity=1)
        z.plugins.trace.traceoff(0x08048B73)

        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            self.assertIn("[08048b70]", stdout.getvalue())
            self.assertNotIn("[08048b73]", stdout.getvalue())

    def test_traceon_syscall(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.plugins.trace.traceon_syscall("write")

        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            self.assertIn("[08131b16]", stdout.getvalue())

    def test_traceoff_syscall(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), verbosity=1)
        z.plugins.trace.traceoff_syscall("brk")
        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            # self.assertIn("[0815b56f]", stdout.getvalue())
            self.assertNotIn("[0815b575]", stdout.getvalue())

    def test_hook_comments(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            verbosity=1,
            fasttrace=True,
        )

        comments = []

        def comment_hook(zelos, address, thread_id, text):
            comments.append((address, thread_id, text))

        z.plugins.trace.hook_comments(comment_hook)
        z.start()

        self.assertGreater(len(comments), 0)
        self.assertIn("ebp = 0x0", comments[0][2])
        self.assertIn("ecx = 0xff08eea4 -> ff08ef41", comments[2][2])
