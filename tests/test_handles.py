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


from __future__ import absolute_import

import io
import tempfile
import unittest

from os import path
from unittest.mock import patch

from zelos import Zelos
from zelos.handles import FileHandle


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


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

    def test_truncate(self):
        z = Zelos(None)
        handles = z.internal_engine.handles

        handle_num = handles.new_file(
            "TestFile", file=tempfile.TemporaryFile("wb")
        )
        handle = handles.get(handle_num)

        self.assertEqual(handle.size(), 0)
        handle.truncate(0x100)
        self.assertEqual(handle.size(), 0x100)

    def test_stdin_redirect(self):
        new_stdin = io.TextIOWrapper(
            io.BufferedReader(io.BytesIO(b"test data"))
        )
        with patch("sys.stdin", new=new_stdin):
            z = Zelos(path.join(DATA_DIR, "read_stdin"), trace_off=True)
            with patch("sys.stdout", new=io.StringIO()) as stdout:
                z.start()
                self.assertIn("string is: test data", stdout.getvalue())

    def test_issue_96(self):
        # Zelos shouldn't close passed through stdin when cleaning up
        # stdin handle
        # Zelos shouldn't crash if stdin is closed before zelos is
        # initialized.
        new_stdin = io.TextIOWrapper(
            io.BufferedReader(io.BytesIO(b"test data"))
        )
        with patch("sys.stdin", new=new_stdin):
            z = Zelos(None)
            stdin_handle = z.internal_engine.handles.get(0)
            stdin_handle.cleanup()
            self.assertFalse(new_stdin.closed)

            new_stdin.close()
            Zelos(None)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
