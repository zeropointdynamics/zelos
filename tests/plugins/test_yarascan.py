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

import sys
import tempfile
import unittest

from io import StringIO
from os import path

import mock

from zelos import Zelos


DATA_DIR = path.join(
    path.dirname(path.abspath(__file__)), path.join("..", "data")
)

rule1 = """
rule testrule1
{
      meta:
        description="test rule 1"
      strings:
        $a = "Hello"
      condition:
        $a
}
"""

rule2 = """
rule testrule2
{
      meta:
        description="test rule 2"
      strings:
        $a = "World"
      condition:
        $a
}
"""

rule3 = """
rule testrule3
{
      meta:
        description="test rule 3"
      strings:
        $a = "C++"
      condition:
        $a
}
"""

expected_yaml = [
    """- cmdline_rule0:
        namespace: cmdline
        rule: rule0
        region_desc: "08176000-08177000 00001000 rwx private static_elf_helloworld, main"
        region_address: 0x8176000
        xrefs: 0
        strings:
                address: 0x8176449
                        offset: 0x449
                        value: "b'Hello World!'"
                        xrefs: 0
""",  # noqa
    """- rulefile3_testrule3:
        description: "test rule 3"
        namespace: rulefile3
        rule: testrule3
        region_desc: "08176000-08177000 00001000 rwx private static_elf_helloworld, main"
        region_address: 0x8176000
        xrefs: 0
        strings:
                address: 0x817645d
                        offset: 0x45d
                        value: "b'C++'"
                        xrefs: 0
""",  # noqa
    """- rulefile1_testrule1:
        description: "test rule 1"
        namespace: rulefile1
        rule: testrule1
        region_desc: "08176000-08177000 00001000 rwx private static_elf_helloworld, main"
        region_address: 0x8176000
        xrefs: 0
        strings:
                address: 0x8176449
                        offset: 0x449
                        value: "b'Hello'"
                        xrefs: 0
""",  # noqa
    """- rulefile2_testrule2:
        description: "test rule 2"
        namespace: rulefile2
        rule: testrule2
        region_desc: "08176000-08177000 00001000 rwx private static_elf_helloworld, main"
        region_address: 0x8176000
        xrefs: 0
        strings:
                address: 0x817644f
                        offset: 0x44f
                        value: "b'World'"
                        xrefs: 0
""",  # noqa
]


def remove_matching_lines(haystack, needles):
    result = StringIO()
    for line in haystack.split("\n"):
        if not any(needle in line for needle in needles):
            result.write(f"{line}\n")
    return result.getvalue()


class TestYaraScanPlugin(unittest.TestCase):
    def test_yarascan(self):
        # Create temp directory to store yarascan output files
        with tempfile.TemporaryDirectory() as tmpdir:
            filename1 = path.join(tmpdir, "rulefile1.yar")
            filename2 = path.join(tmpdir, "rulefile2.yar")
            filename3 = path.join(tmpdir, "rulefile3.yap")
            with open(filename1, "w") as f1, open(filename2, "w") as f2, open(
                filename3, "w"
            ) as f3:
                f1.write(rule1)
                f2.write(rule2)
                f3.write(rule3)
            testglob = path.join(tmpdir, "*.yar")
            yaml_filename = path.join(tmpdir, "yara.yaml")
            memdump_dir = path.join(tmpdir, "memdumps")

            # Init `zelos` and request yara scanning post-emulation.
            z = Zelos(
                path.join(DATA_DIR, "static_elf_helloworld"),
                trace_off=True,
                yara_file=filename3,
                yara_file_glob=testglob,
                yara_rule=r"/hello\sworld!/nocase",
                yara_memdump=memdump_dir,
                yara_outfile=yaml_filename,
                yara_xrefs=True,
                # yara_brief=True,
                # yara_pid=None,
            )
            z.start(timeout=10)

            # Invoke yarascan plugin via scripting, independent of the
            # post-emulation scanning.
            yara = z.plugins.yarascan
            yara.compile(rules=["Hello World"], files=[], glob_string=None)
            matches = list(
                yara.matches(
                    pid=z.process.pid, yamldump=yaml_filename, brief=True
                )
            )
            self.assertEqual(1, len(matches))
            self.assertEqual(
                matches[0].info(brief=True), "Matched rule: cmdline.rule0"
            )

            # Test missing `yara-python` dependency
            with mock.patch.dict(sys.modules, {"yara": None}):
                self.assertFalse(yara.import_yara())
            self.assertTrue(yara.import_yara())

            # `close` triggers the yara memory scan requested via
            # the `yara_` arguments during `zelos` initialization.
            z.close()

            # Load in the yaml file generated by yarascan for validation
            with open(yaml_filename, "r") as f:
                yaml = f.read()
            # PID may change, omit it from test
            yaml = remove_matching_lines(yaml, ["pid"])
            yaml = yaml.replace("\t", "        ")

            # Check each yaml entry individually, since `yara-python`
            # match order is not deterministic.
            for expected in expected_yaml:
                self.assertTrue(expected in yaml)

    def test_yarascan_no_xrefs_issue_129(self):
        # Create temp directory to store yarascan output files
        # Init `zelos` and request yara scanning post-emulation.
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            trace_off=True,
            yara_rule=r"/hello\sworld!/nocase",
        )
        z.start(timeout=10)

        yara = z.plugins.yarascan
        yara.compile(rules=["Hello World"], files=[], glob_string=None)
        matches = list(yara.matches(pid=z.process.pid, xrefs=False))
        # Check whether we are handling the strings method correctly,
        # specifically when xrefs is false.
        matches[0].strings


if __name__ == "__main__":
    unittest.main()
