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

    def test_x86_comments(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), verbosity=1)
        expected_comments = [
            ("ebp = 0x0"),  # xor ebp, ebp
            ("esi = 0x1"),  # pop esi
            ("ecx = 0xff08eea4 -> ff08ef41"),  # mov ecx, esp
            ("esp = 0xff08eea0 -> 1"),  # and esp, 0xfffffff0
            ("push(0x0)"),  # push eax
            ("push(0xff08ee98) -> ff08ee9c"),  # push esp
            ("push(0x0)"),  # push edx
            ("call(0x8048ba3)"),  # call 0x8048ba3
        ]

        # Wrap the get_comment method to extract its output from a
        # real run.
        get_comment = z.plugins.trace.comment_generator.get_comment
        recieved_comments = []

        def comment_wrapper(insn):
            comment = get_comment(insn)
            recieved_comments.append(comment)
            return comment

        z.plugins.trace.comment_generator.get_comment = comment_wrapper

        z.plugins.runner.run_to_addr(0x08048BA3)
        self.assertEqual(expected_comments, recieved_comments)
