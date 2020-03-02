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

from zelos import Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ProcessesTest(unittest.TestCase):
    def test_emu_swap(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.internal_engine.current_process.threads.swap_with_next_thread()

        self.assertEqual(z.internal_engine.processes.num_active_processes(), 1)
        pid1 = z.internal_engine.current_process.pid
        self.assertEqual(
            z.internal_engine.thread_manager.num_active_threads(), 1
        )
        z.internal_engine.current_thread.setIP(0x2000)

        pid2 = z.internal_engine.processes.new_process("Process_2", pid1)
        p2 = z.internal_engine.processes.get_process(pid2)
        p2.new_thread(0x1000, "thread2")
        p2.threads.swap_with_next_thread()

        self.assertEqual(z.internal_engine.current_thread.getIP(), 0x2000)
        z.internal_engine.processes.load_process(pid2)
        self.assertEqual(z.internal_engine.current_thread.getIP(), 0x1000)

    def test_memory_swap(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        self.assertEqual(z.internal_engine.processes.num_active_processes(), 1)
        pid1 = z.internal_engine.current_process.pid
        z.internal_engine.current_process.memory.map(0xDEADB000, 0x1000)
        self.assertEqual(
            z.internal_engine.memory.read(0xDEADB000, 0x4), b"\x00" * 4
        )
        z.internal_engine.memory.write(0xDEADB000, b"\x01\x02\x03\x04")
        self.assertEqual(
            z.internal_engine.memory.read(0xDEADB000, 0x4), b"\x01\x02\x03\x04"
        )

        pid2 = z.internal_engine.processes.new_process("Process_2", pid1)
        z.internal_engine.processes.load_process(pid2)
        z.internal_engine.current_process.memory.map(0xDEADB000, 0x1000)
        self.assertEqual(
            z.internal_engine.memory.read(0xDEADB000, 0x4), b"\x00" * 4
        )
        z.internal_engine.memory.write(0xDEADB000, b"\x05\x05\x05\x05")
        self.assertEqual(
            z.internal_engine.memory.read(0xDEADB000, 0x4), b"\x05\x05\x05\x05"
        )

    def test_sys_fork(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.internal_engine.processes.swap_with_next_thread()
        self.assertEqual(z.internal_engine.processes.num_active_processes(), 1)
        p1 = z.internal_engine.current_process

        # Make handle_syscall call fork
        z.internal_engine.zos.syscall_manager.find_syscall_name_by_number = (
            lambda x: "fork"
        )
        z.internal_engine.zos.syscall_manager.handle_syscall(p1)

        new_pid = p1.emu.get_reg("eax")
        p2 = z.internal_engine.processes.get_process(new_pid)
        # We add 2 to the IP of P1 because, since Zelos is not actually
        # running, the callback of stop_and_exec that is defined inside
        # handle_syscall is never invoked and the parent process IP is
        # never incremented.
        # This is just for this test, as during normal execution this
        # would not be the case.
        self.assertEqual(p1.emu.getIP() + 2, p2.emu.getIP())
        self.assertEqual(p2.emu.get_reg("eax"), 0)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
