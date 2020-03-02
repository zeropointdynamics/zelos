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

from os import path

from zelos import Zelos
from zelos.threads import ThreadState


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ZelosTest(unittest.TestCase):
    def _ltp_run(self, bin_path, timeout=3):
        z = Zelos(path.join(DATA_DIR, bin_path), log="ERROR")
        z.internal_engine.set_verbose(False)
        z.internal_engine.trace.threads_to_print.add("none")

        stdout = z.internal_engine.handles.get(1)
        buffer = bytearray()

        def write_override(data):
            buffer.extend(data)

        stdout.write = write_override

        z.internal_engine.start(timeout=timeout)

        # All threads should exit successfully
        self.assertTrue(
            all(
                [
                    t.state == ThreadState.SUCCESS
                    for t in z.internal_engine.processes.get_all_threads()
                ]
            ),
            msg=z.internal_engine.processes.__str__(),
        )

        return buffer

    def test_brk(self):
        buffer = self._ltp_run("ltp_x64/syscalls/brk01")
        self.assertIn("passed   1", str(buffer))

    def test_chdir(self):
        # self._ltp_run('ltp_x64/syscalls/chdir01')
        self._ltp_run("ltp_x64/syscalls/chdir02")
        # self._ltp_run('ltp_x64/syscalls/chdir03')
        # self._ltp_run('ltp_x64/syscalls/chdir04')

    def test_fork(self):
        # self._ltp_run('ltp_x64/syscalls/fork01')
        self._ltp_run("ltp_x64/syscalls/fork02")
        self._ltp_run("ltp_x64/syscalls/fork03")
        # self._ltp_run('ltp_x64/syscalls/fork04')
        # test fork05 only for x32
        # self._ltp_run('ltp_x64/syscalls/fork06')
        # self._ltp_run('ltp_x64/syscalls/fork07')
        # self._ltp_run('ltp_x64/syscalls/fork08')
        # self._ltp_run('ltp_x64/syscalls/fork09')

    def test_getpid(self):
        buffer = self._ltp_run("ltp_x64/syscalls/getpid01")
        self.assertEqual(1, str(buffer).count("TPASS"))
        buffer = self._ltp_run("ltp_x64/syscalls/getpid02")
        self.assertEqual(1, str(buffer).count("TPASS"))

    def test_getppid(self):
        buffer = self._ltp_run("ltp_x64/syscalls/getppid01")
        self.assertEqual(1, str(buffer).count("TPASS"))
        self._ltp_run("ltp_x64/syscalls/getppid02")

    def test_kill(self):
        pass
        # self._ltp_run('ltp_x64/syscalls/kill01')
        # self._ltp_run('ltp_x64/syscalls/kill02')
        # Needs to kill child process instead of letting it exit.
        # self._ltp_run('ltp_x64/syscalls/kill03')
        # Needs proc/sys/kernel/pid_max
        # self._ltp_run('ltp_x64/syscalls/kill04')
        # self._ltp_run('ltp_x64/syscalls/kill05')
        # self._ltp_run('ltp_x64/syscalls/kill06')
        # self._ltp_run('ltp_x64/syscalls/kill07')
        # self._ltp_run('ltp_x64/syscalls/kill08')
        # Needs to kill child process instead of letting it exit.
        # self._ltp_run('ltp_x64/syscalls/kill09')

    def test_open(self):
        # self._ltp_run('ltp_x64/syscalls/open01')
        # self._ltp_run('ltp_x64/syscalls/open02')
        self._ltp_run("ltp_x64/syscalls/open03")
        # self._ltp_run('ltp_x64/syscalls/open04')
        # self._ltp_run('ltp_x64/syscalls/open05')
        # self._ltp_run('ltp_x64/syscalls/open06')
        # self._ltp_run('ltp_x64/syscalls/open07')
        # self._ltp_run('ltp_x64/syscalls/open08')
        # self._ltp_run('ltp_x64/syscalls/open09')

    def test_pipe(self):
        self._ltp_run("ltp_x64/syscalls/pipe01")
        # self._ltp_run('ltp_x64/syscalls/pipe02')
        self._ltp_run("ltp_x64/syscalls/pipe03")
        # self._ltp_run('ltp_x64/syscalls/pipe04')
        # self._ltp_run('ltp_x64/syscalls/pipe05')
        # self._ltp_run('ltp_x64/syscalls/pipe06')
        # self._ltp_run('ltp_x64/syscalls/pipe07')
        # self._ltp_run('ltp_x64/syscalls/pipe08')
        self._ltp_run("ltp_x64/syscalls/pipe09")

    def test_read(self):
        buffer = self._ltp_run("ltp_x64/syscalls/read01")
        self.assertIn("passed   1", str(buffer))
        # buffer = self._ltp_run('ltp_x64/syscalls/read02')
        # buffer = self._ltp_run('ltp_x64/syscalls/read03')
        # buffer = self._ltp_run('ltp_x64/syscalls/read04')

    def test_rmdir(self):
        buffer = self._ltp_run("ltp_x64/syscalls/rmdir01")
        self.assertIn("passed   1", str(buffer))
        # buffer = self._ltp_run('ltp_x64/syscalls/rmdir02')
        # buffer = self._ltp_run('ltp_x64/syscalls/rmdir03')

    def test_sbrk(self):
        buffer = self._ltp_run("ltp_x64/syscalls/sbrk01")
        self.assertEqual(2, str(buffer).count("TPASS"))
        buffer = self._ltp_run("ltp_x64/syscalls/sbrk02")
        # sbrk03 only works on 32bit

    def test_vfork(self):
        self._ltp_run("ltp_x64/syscalls/vfork01")
        # self._ltp_run('ltp_x64/syscalls/vfork02')

    def test_write(self):
        # self._ltp_run('ltp_x64/syscalls/write01')
        self._ltp_run("ltp_x64/syscalls/write02")
        # self._ltp_run('ltp_x64/syscalls/write03')
        # self._ltp_run('ltp_x64/syscalls/write04')
        # self._ltp_run('ltp_x64/syscalls/write05')
