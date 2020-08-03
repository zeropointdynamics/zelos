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

from os import path
from unittest.mock import Mock

from zelos.plugin.arg_base import Arg, Args
from zelos.zml import ZmlParser


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ZmlTest(unittest.TestCase):
    def setUp(self):
        self.zelos = None
        self.zml_parser = ZmlParser(self.zelos)

    def test_grammar(self):
        valid_rules = [
            "syscall=test",
            "n=2,func=test",
            "func=test,n=2",
            "thread=test,thread=test2",
            "n=2,thread=test",
            "thread=test,n=2",
            "addr=10,n=2",
            "addr=10,thread=test",
            "arg_test=10,addr=10",
            "addr = 10 , n = 2 ",
        ]
        for r in valid_rules:
            self.zml_parser._zml_parser.parse(r)

        invalid_rules = [
            "func=test,syscall=test2",
            "func=test,func=test2",
            "func=test,addr=2",
            "n=2",
            "n=test",
            "addr=test",
            "retval=test",
        ]
        for r in invalid_rules:
            self.assertRaises(Exception, self.zml_parser._zml_parser.parse, r)

    def test_empty_condition_list(self):
        zml_object = self.zml_parser.parse_zml_string("")

        m = Mock()
        zml_object.act_when_satisfied(self.zelos, m)
        m.assert_called_once()

    def test_syscall_basic(self):
        zml_object = self.zml_parser.parse_zml_string("syscall=brk")

        self.assertTrue(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name", 0x10, "")]), 0x20
            )
        )
        # Check that it continues to be satisfied.
        self.assertTrue(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name", 0x10, "")]), 0x20
            )
        )

        self.assertFalse(
            zml_object.is_satisfied(
                self.zelos, "open", Args([Arg("type", "name", 0x10, "")]), 0x20
            )
        )

    def test_syscall_args(self):
        zml_object = self.zml_parser.parse_zml_string(
            "syscall=brk,arg_name1=0x10"
        )

        self.assertTrue(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name1", 0x10, "")]), 0x20
            )
        )

        self.assertFalse(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name1", 0x11, "")]), 0x20
            )
        )

        self.assertFalse(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name2", 0x10, "")]), 0x20
            )
        )

    def test_syscall_retval(self):
        zml_object = self.zml_parser.parse_zml_string(
            "syscall=brk,retval=0x20"
        )

        self.assertTrue(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name1", 0x10, "")]), 0x20
            )
        )

        self.assertFalse(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name1", 0x10, "")]), 0x21
            )
        )

    def test_syscall_n(self):
        zml_object = self.zml_parser.parse_zml_string("syscall=brk,n=2")

        self.assertFalse(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name1", 0x10, "")]), 0x20
            )
        )

        self.assertTrue(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name1", 0x11, "")]), 0x21
            )
        )

        self.assertFalse(
            zml_object.is_satisfied(
                self.zelos, "brk", Args([Arg("type", "name1", 0x10, "")]), 0x20
            )
        )

    def test_address_n(self):
        zml_object = self.zml_parser.parse_zml_string("addr=0x12345,n=2")

        self.assertFalse(zml_object.is_satisfied(self.zelos))
        self.assertTrue(zml_object.is_satisfied(self.zelos))
        self.assertFalse(zml_object.is_satisfied(self.zelos))
