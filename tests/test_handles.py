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

from zelos import Zelos
from zelos.handles import FileHandle


class HandleTest(unittest.TestCase):
    def test_add_handle(self):
        z = Zelos(None)
        handles = z.internal_engine.handles
        handle_num = handles.new_file("test")

        file_handle = handles.get(handle_num)
        self.assertEqual(file_handle.category(), "file")
        self.assertEqual(file_handle.Refs, 1)
        self.assertTrue(handles.exists(handle_num))

        handles.close(handle_num)
        self.assertEqual(file_handle.Refs, 0)
        self.assertFalse(handles.exists(handle_num))

    def test_overwrite_handle(self):
        z = Zelos(None)
        handles = z.internal_engine.handles

        num1 = handles.new_file("test1")
        file_handle1 = handles.get(num1)
        self.assertEqual(file_handle1.Name, "test1")

        num2 = handles.new_file("test2")
        file_handle2 = handles.get(num2)
        self.assertEqual(file_handle2.Name, "test2")

        handles.add_handle(file_handle2, num1)
        # Now both num1 and num2 should refer to the second handle
        self.assertIs(handles.get(num1), file_handle2)
        self.assertIs(handles.get(num2), file_handle2)

        self.assertEqual(file_handle2.Refs, 2)
        self.assertEqual(file_handle1.Refs, 0)

    def test_get_by(self):
        z = Zelos(None)
        handles = z.internal_engine.handles

        handles.new_pipe("pipe1")
        file_num1 = handles.new_file("file1")
        file_num2 = handles.new_file("file2")
        file1 = handles.get(file_num1)
        file2 = handles.get(file_num2)
        self.assertIs(handles.get_by_name("file1"), file_num1)

        file_handles = handles.get_by_type(FileHandle)
        self.assertSetEqual(set(file_handles), set([file1, file2]))

        self.assertIsNone(handles.get(file_num1, pid=0x1000))

        handles.add_handle(file1, handle_num=file_num1, pid=0x1000)
        self.assertIs(handles.get(file_num1, pid=0x1000), file1)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
