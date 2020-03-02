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
import subprocess
import unittest

from os import path


# from zelos.api.zelos_api import ZelosCmdline


DATA_DIR = path.dirname(path.abspath(__file__))


class ExamplesTest(unittest.TestCase):
    # def test_inmemory_strings_script(self):
    #     stdout = subprocess.check_output(
    #         [
    #             "python",
    #             path.join(DATA_DIR, "inmemory_strings", "strings_script.py"),
    #             path.join(DATA_DIR, "inmemory_strings", "pwnablekr_flag"),
    #         ]
    #     )

    #     self.assertIn(b"UPX...? sounds like a delivery service :)", stdout)

    # def test_inmemory_strings_plugin(self):
    #     os.environ["ZELOS_PLUGIN_DIR"] = path.join(
    #         DATA_DIR, "inmemory_strings"
    #     )
    #     filepath = path.join(DATA_DIR, "inmemory_strings", "pwnablekr_flag")

    #     # sys.stdout = printed_output
    #     z = ZelosCmdline(f"--print_strings 4 {filepath}")
    #     z.start()

    #     # This test doesn't work on windows.
    #     # self.assertIn(
    #     #     "UPX...? sounds like a delivery service :)",
    #     #     printed_output.getvalue(),
    #     # )

    def test_hello(self):
        output = subprocess.check_output(
            ["python", path.join(DATA_DIR, "hello", "hello.py")]
        )
        self.assertTrue("Hello, Zelos!" in str(output))

    def test_brute(self):
        output = subprocess.check_output(
            ["python", path.join(DATA_DIR, "script_brute", "brute.py")]
        )
        self.assertTrue("Correct!" in str(output))

    def test_bypass_mem(self):
        output = subprocess.check_output(
            [
                "python",
                path.join(DATA_DIR, "script_bypass", "bypass.py"),
                "mem",
            ]
        )
        self.assertTrue("Correct!" in str(output))

    def test_bypass_reg(self):
        output = subprocess.check_output(
            [
                "python",
                path.join(DATA_DIR, "script_bypass", "bypass.py"),
                "reg",
            ]
        )
        self.assertTrue("Correct!" in str(output))

    # def test_bypass_code(self):
    #     output = subprocess.check_output(
    #         [
    #             "python",
    #             path.join(DATA_DIR, "script_bypass", "bypass.py"),
    #             "code",
    #         ]
    #     )
    #     self.assertTrue("Correct!" in str(output))


def main():
    unittest.main()


if __name__ == "__main__":
    main()
