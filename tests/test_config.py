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

import unittest

from os import path

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ConfigTest(unittest.TestCase):
    def test_mount_folder(self):
        z = Zelos(None, mount=f"x86,/home/data,{DATA_DIR}", log="debug")
        file = z.internal_engine.files.open_library(
            "/home/data/static_elf_helloworld"
        )
        self.assertIsNotNone(file)

    def test_mount_folder_end_slash(self):
        z = Zelos(None, mount=f"x86,/home/data/,{DATA_DIR}", log="debug")
        file = z.internal_engine.files.open_library(
            "/home/data/static_elf_helloworld"
        )
        self.assertIsNotNone(file)

    def test_mount_file(self):
        real_path = path.join(DATA_DIR, "static_elf_helloworld")
        z = Zelos(
            None, mount=f"x86,/home/data/sample_file,{real_path}", log="debug"
        )
        file = z.internal_engine.files.open_library("/home/data/sample_file")
        self.assertIsNotNone(file)

    def test_mount_file_end_slash(self):
        real_path = path.join(DATA_DIR, "static_elf_helloworld")

        z = Zelos(None, mount=f"x86,/home/data/,{real_path}", log="debug")
        file = z.internal_engine.files.open_library(
            "/home/data/static_elf_helloworld"
        )
        self.assertIsNotNone(file)

    def test_env_vars(self):
        # specify single env_var
        z = Zelos(None, env_vars="HELLO=world test spaces")
        self.assertDictEqual(z.config.env_vars, {"HELLO": "world test spaces"})
        # specify multiple env_vars
        z = Zelos(None, env_vars=["HELLO=world", "LOREM=ipsum"])
        self.assertDictEqual(
            z.config.env_vars, {"HELLO": "world", "LOREM": "ipsum"}
        )

    def test_args_with_starting_dash(self):
        real_path = path.join(DATA_DIR, "static_elf_helloworld")
        z = Zelos(real_path, "--first_arg", "--second_arg")

        self.assertEqual("--first_arg", z.internal_engine.cmdline_args[1])
        self.assertEqual("--second_arg", z.internal_engine.cmdline_args[2])


def main():
    unittest.main()


if __name__ == "__main__":
    main()
