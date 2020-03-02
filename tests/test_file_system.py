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
import os
import tempfile
import unittest

from zelos import Zelos
from zelos.file_system import PathTranslator


def path_leaf(path):
    import ntpath

    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


class TestPathTranslator(unittest.TestCase):
    def test_add_file(self):
        path_translator = PathTranslator("/")

        file = tempfile.NamedTemporaryFile()
        path_translator.add_file(file.name, "/root/testfile")

        file_name = path_translator.emulated_path_to_host_path(
            "/root/testfile"
        )
        self.assertEqual(file_name, file.name)

        file_name = path_translator.emulated_path_to_host_path("/testfile")
        self.assertIsNone(file_name)

    def test_order(self):
        path_translator = PathTranslator("/")

        file = tempfile.NamedTemporaryFile()
        folder = tempfile.TemporaryDirectory()
        f1 = open(
            path_translator.emulated_join(folder.name, path_leaf(file.name)),
            "wb",
        )
        f2 = open(
            path_translator.emulated_join(folder.name, "testfile2"), "wb"
        )
        path_translator.add_file(file.name, "/testfolder/testfile2")
        path_translator.mount_folder(folder.name, "/testfolder")

        file_name = path_translator.emulated_path_to_host_path("/testfolder")
        self.assertEqual(file_name, folder.name + os.path.sep)

        file_name = path_translator.emulated_path_to_host_path(
            "/testfolder/testfile2"
        )
        self.assertEqual(file_name, file.name)

        file_name = path_translator.emulated_path_to_host_path("/testfile2")
        self.assertIsNone(file_name)

        f1.close()
        f2.close()
        folder.cleanup()

    def test_change_directory(self):
        path_translator = PathTranslator("/")

        file = tempfile.NamedTemporaryFile()
        path_translator.add_file(file.name, "/root/testfile")

        file_name = path_translator.emulated_path_to_host_path(
            "/root/testfile"
        )
        self.assertEqual(file_name, file.name)

        path_translator.change_working_directory("/")
        file_name = path_translator.emulated_path_to_host_path("root/testfile")

        file_name = path_translator.emulated_path_to_host_path("testfile")
        self.assertIsNone(file_name)

        path_translator.change_working_directory("/root")
        file_name = path_translator.emulated_path_to_host_path("testfile")
        self.assertEqual(file_name, file.name)

    # def test_convert_to_host_path(self):
    #     import platform
    #     if platform.system() == 'Linux':
    #         path_translator = PathTranslator("/")

    #         host_path = path_translator._convert_to_host_path(
    #             'this/that/whatever.txt')
    #         self.assertEqual('this/that/whatever.txt', host_path)

    #         path_translator = PathTranslator("C:\\")

    #         host_path = path_translator._convert_to_host_path(
    #             'this\\that\\whatever.txt')
    #         self.assertEqual('this/that/whatever.txt', host_path)


class FileSystemTest(unittest.TestCase):
    def test_get_file(self):
        z = Zelos(None)
        file_system = z.internal_engine.files
        handle = file_system.create_file("test_file1")
        self.assertEqual(file_system.get_filename(handle), "test_file1")

    def test_offsets(self):
        z = Zelos(None)
        file_system = z.internal_engine.files
        handle_num = file_system.create_file("test_file1")
        h = z.internal_engine.handles.get(handle_num)

        self.assertEqual(0, h.Offset)
        h.Offset = 100
        h = z.internal_engine.handles.get(handle_num)

        self.assertEqual(100, h.Offset)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
