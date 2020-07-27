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

import os
import tempfile
import unittest

from io import StringIO
from os import path
from unittest.mock import patch

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class TraceTest(unittest.TestCase):
    def test_trace_inst_start_on_addr(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            inst_feed="addr=0x08131B16",
        )

        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            self.assertNotIn("[080f5c00]", stdout.getvalue())
            self.assertIn("[08131b16]", stdout.getvalue())

    def test_trace_inst_stop_on_addr(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            inst=True,
            no_feeds="addr=0x08048B73",
        )

        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            self.assertIn("[08048b70]", stdout.getvalue())
            self.assertNotIn("[08048b73]", stdout.getvalue())

    def test_trace_inst_start_on_syscall(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            inst_feed="syscall=write",
        )

        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            self.assertIn("[08131b16]", stdout.getvalue())

    def test_trace_inst_stop_on_syscall(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            inst=True,
            no_feeds="syscall=brk",
        )
        with patch("sys.stdout", new=StringIO()) as stdout:
            z.start()
            self.assertIn("[0815b56f]", stdout.getvalue())
            self.assertNotIn("[0815b575]", stdout.getvalue())

    def test_trace_file_cmdline_option(self):
        fd, temp_file = tempfile.mkstemp()

        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            trace_file=temp_file,
            inst=True,
            fasttrace=True,
        )

        z.start()

        f = open(temp_file, "r")
        lines = f.readlines()
        print(lines)
        # TODO: Figure out why runners execute a different number of
        # lines. They seem to consistently get 9579.
        # self.assertEqual(len([l for l in lines if "[INS]" in l]), 9580)
        self.assertEqual(len([l for l in lines if "[SYSCALL]" in l]), 12)
        f.close()
        z.plugins.trace.trace_file.close()
        os.close(fd)
        os.remove(temp_file)

    def test_x86_comments(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), inst=True)
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

        z.plugins.trace.trace_off()
        z.start()
        self.assertEqual(expected_comments, recieved_comments)

    def test_arm_comments(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"), inst=True)
        expected_comments = [
            "fp = 0x0",  # mov     fp, #0
            "lr = 0x0",  # mov     lr, #0
            "[ 1]",  # pop     {r1}
            "r2 = 0xff08eea4",  # mov     r2, sp
            "store(0xff08eea4, 0xff08ee9c)",  # str     r2, [sp, #-4]!
            "store(0x0, 0xff08ee98)",  # str     r0, [sp, #-4]!
            "ip = load(0x101cc) = 0x10ac4",  # ldr     ip, [pc, #0x10]
            "store(0x10ac4, 0xff08ee94)",  # str     ip, [sp, #-4]!
            "r0 = load(0x101d0) = 0x102dc",  # ldr     r0, [pc, #0xc]
            "r3 = load(0x101d4) = 0x10a24",  # ldr     r3, [pc, #0xc]
            "<__libc_start_main> (0x1030c)",  # bl      #0x1030c
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

        z.plugins.runner.run_to_addr(0x0001030C)
        self.assertEqual(expected_comments, recieved_comments)

        z.plugins.trace.trace_off()
        z.start()
        self.assertEqual(expected_comments, recieved_comments)

    def test_hook_comments(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            inst=True,
            trace_off=True,
        )

        expected_comments = [
            "ebp = 0x0",  # xor ebp, ebp
            "esi = 0x1",  # pop esi
            "ecx = 0xff08eea4 -> ff08ef41",  # mov ecx, esp
            "esp = 0xff08eea0 -> 1",  # and esp, 0xfffffff0
            "push(0x0)",  # push eax
            "push(0xff08ee98) -> ff08ee9c",  # push esp
            "push(0x0)",  # push edx
            "call(0x8048ba3)",  # call 0x8048ba3
        ]

        comments = []

        def comment_hook(zelos, addr, comment):
            comments.append(comment)

        # hook comment generation
        z.plugins.trace.hook_comments(comment_hook)

        z.start()

        self.assertEqual(expected_comments, comments[:8])
