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

import subprocess
import unittest

from os import path


DATA_DIR = path.dirname(path.abspath(__file__))


class TraceTest(unittest.TestCase):
    def test_traceon(self):
        output = subprocess.check_output(
            ["python", path.join(DATA_DIR, "run_trace.py"), "traceon"]
        )
        self.assertNotIn("[080f5c00]", str(output))
        self.assertIn("[08131b16]", str(output))

    def test_traceoff(self):
        output = subprocess.check_output(
            ["python", path.join(DATA_DIR, "run_trace.py"), "traceoff"]
        )
        self.assertIn("[08048b70]", str(output))
        self.assertNotIn("[08048b73]", str(output))

    def test_traceon_syscall(self):
        output = subprocess.check_output(
            ["python", path.join(DATA_DIR, "run_trace.py"), "sys_traceon"]
        )
        self.assertIn("[08131b16]", str(output))

    def test_traceoff_syscall(self):
        output = subprocess.check_output(
            ["python", path.join(DATA_DIR, "run_trace.py"), "sys_traceoff"]
        )
        # self.assertIn("[0815b56f]", str(output))
        self.assertNotIn("[0815b575]", str(output))
