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

import unittest

from collections import defaultdict
from os import path
from unittest.mock import Mock

from zelos import HookType, Zelos


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ZelosTest(unittest.TestCase):
    def test_regs(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        self.assertEqual(z.regs.eip, 0x8048B70)
        z.regs.eip = 0x1  # should fail.
        z.start()
        self.assertEqual(
            1, len(z.internal_engine.thread_manager.failed_threads)
        )

    # This test failed on windows for some reason.
    # def test_start_timeout(self):
    #     z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
    #     # This should be enough such that this binary couldn't finish in
    #     # this time. If for some reason, Zelos is fast enough to run
    #     # this binary in 1 microsecond:
    #     #   1) congratulations
    #     #   2) just reduce the timeout even lower.
    #     z.start(timeout=0.000001)

    #     self.assertEqual(
    #         1, z.internal_engine.thread_manager.num_active_threads()
    #     )

    def test_memory_hook(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        read_addresses = []

        def mem_read_hook(zelos, access, address, size, value):
            read_addresses.append(address)

        write_addresses = []

        def mem_write_hook(zelos, access, address, size, value):
            write_addresses.append(address)

        z.hook_memory(HookType.MEMORY.READ, mem_read_hook)

        z.hook_memory(HookType.MEMORY.WRITE, mem_write_hook)
        z.start()

        self.assertGreater(len(read_addresses), 0)
        self.assertGreater(len(write_addresses), 0)

    def test_unmapped_memory_hook(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        z.regs.setIP(0xDEAD0000)
        z.memory.map(0xDEAD0000, 0x1000)
        z.memory.write(
            0xDEAD0000, b"\xA1\x00\x20\xad\xde"
        )  # mov eax, [0xdead2000], which is an unmapped read
        hook = Mock()
        z.hook_memory(HookType.MEMORY.UNMAPPED, hook)
        z.step()

        hook.assert_called_once()

    def test_exec_hook(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        blocks = []

        def block_hook(zelos, address, size):
            blocks.append(address)

        instr_addr = []

        def single_instr_hook(zelos, address, size):
            instr_addr.append(address)

        z.hook_execution(HookType.EXEC.BLOCK, block_hook)

        target_addr = 0x08109A7E
        z.hook_execution(
            HookType.EXEC.INST,
            single_instr_hook,
            ip_low=target_addr,
            ip_high=target_addr,
            end_condition=lambda: True,
        )

        z.start()

        self.assertGreater(len(blocks), 15000)
        self.assertEqual(target_addr, instr_addr[0])

    def test_close_hook(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        end_addr = []

        def close_hook():
            end_addr.append(
                z.internal_engine.thread_manager.completed_threads[0].getIP()
            )

        z.hook_close(close_hook)

        z.start()

        z.internal_engine.close()

        completed_addr = z.internal_engine.thread_manager.completed_threads[
            0
        ].getIP()

        self.assertEqual(end_addr[0], completed_addr)

    def test_syscall_hook(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        syscall_cnt = defaultdict(int)

        def syscall_hook(zelos, syscall_name, args, return_value):
            syscall_cnt[syscall_name] += 1

        z.hook_syscalls(HookType.SYSCALL.AFTER, syscall_hook)

        z.start()

        self.assertEqual(syscall_cnt["write"], 1)
        self.assertEqual(syscall_cnt["brk"], 4)
        self.assertEqual(syscall_cnt["set_thread_area"], 1)
        self.assertEqual(syscall_cnt["uname"], 1)
        self.assertEqual(syscall_cnt["readlink"], 1)
        self.assertEqual(syscall_cnt["access"], 1)
        self.assertEqual(syscall_cnt["fstat64"], 1)
        self.assertEqual(syscall_cnt["exit_group"], 1)

    def test_step(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        addr = 0x080EC3F0  # Call, should step into it
        z.plugins.runner.run_to_addr(addr)
        self.assertEqual(z.thread.getIP(), addr)
        z.step()
        self.assertEqual(
            z.thread.getIP(),
            0x08048DBD,
            f"{z.thread.getIP():x} vs. {0x08048DBD:x}",
        )

    def test_next(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        addr = 0x080EC3F0  # Call, should step over it.
        z.plugins.runner.run_to_addr(addr)
        self.assertEqual(z.thread.getIP(), addr)
        z.next()
        self.assertEqual(
            z.thread.getIP(),
            0x080EC3F5,
            f"{z.thread.getIP():x} vs. {0x080EC3F5:x}",
        )

    def test_stop(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        def instr_hook(zelos, address, size):
            zelos.stop()

        addr = 0x08109A7E
        z.hook_execution(
            HookType.EXEC.INST,
            instr_hook,
            ip_low=addr,
            ip_high=addr,
            end_condition=lambda: True,
        )

        z.start()

        tm = z.internal_engine.thread_manager
        self.assertEqual(tm.num_active_threads(), 1)
        self.assertEqual(z.thread.getIP(), addr)

    def test_end_thread(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        addr = 0x0816348F
        z.plugins.runner.run_to_addr(addr)
        z.end_thread()
        tm = z.internal_engine.thread_manager
        self.assertEqual(tm.num_active_threads(), 0)

    def test_breakpoint(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        addr = 0x8048B72
        z.set_breakpoint(addr)
        z.start()

        tm = z.internal_engine.thread_manager
        self.assertEqual(tm.num_active_threads(), 1)
        self.assertEqual(
            z.regs.getIP(), addr, f"{z.regs.getIP():x} vs. {addr:x}"
        )

        z.step()
        self.assertEqual(
            z.regs.getIP(), 0x8048B73, f"{z.regs.getIP():x} vs. {0x8048b73:x}"
        )

    def test_remove_breakpoint(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        addr = 0x8048B72
        z.set_breakpoint(addr)
        z.remove_breakpoint(addr)
        z.set_breakpoint(0x8048B73)
        z.start()

        self.assertEqual(
            z.regs.getIP(), 0x8048B73, f"{z.regs.getIP():x} vs. {0x8048b73:x}"
        )

    def test_syscall_breakpoint(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        z.set_syscall_breakpoint("brk")

        z.start()

        brk = 0x0815B577

        self.assertEqual(z.thread.getIP(), brk)

        z.remove_syscall_breakpoint("brk")

        z.start()

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_watchpoint(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        z.set_watchpoint(0x081E9934, True, True)

        z.start()

        self.assertEqual(z.thread.getIP(), 0x081096F3)

        z.remove_watchpoint(0x081E9934)

        z.start()

        self.assertEqual(
            1, len(z.internal_engine.thread_manager.completed_threads)
        )

    def test_date(self):
        z = Zelos(None)
        d = z.date

        self.assertEqual(d, "2019-02-02")

        z.date = "2019-03-03"
        d = z.date

        self.assertEqual(d, "2019-03-03")

    def test_memory_search(self):
        z = Zelos(None)
        z.memory.map(0x1000, 0x1000)
        z.memory.write(0x1000, b"\x00\x01\x02\x03\x00\x01\x02\x00\x01\x01\x01")
        self.assertEqual(
            [0x1000, 0x1004, 0x1007], z.memory.search(b"\x00\x01")
        )
        self.assertEqual([0x1008], z.memory.search(b"\x01\x01"))

    def test_get_region(self):
        z = Zelos(None)
        self.assertEqual(len(z.memory.get_regions()), 2)
        z.memory.map(0x1000, 0x1000)
        reg = z.memory.get_region(0x1000)
        self.assertIsNotNone(reg)
        self.assertEqual(len(z.memory.get_regions()), 3)
        z.memory.map(0x2000, 0x1000)
        reg = z.memory.get_region(0x2000)
        self.assertIsNotNone(reg)
        self.assertEqual(len(z.memory.get_regions()), 4)

    def test_binary_paths(self):
        z = Zelos(None)
        self.assertIsNone(z.main_binary)
        self.assertIsNone(z.main_binary_path)

        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        self.assertIsNotNone(z.main_binary)
        self.assertEqual(
            path.basename(z.main_binary_path), "static_elf_helloworld"
        )
        self.assertEqual(
            path.basename(z.target_binary_path), "static_elf_helloworld"
        )

        z = Zelos(path.join(DATA_DIR, "dynamic_elf_helloworld"))
        self.assertIsNotNone(z.main_binary)
        self.assertNotEqual(
            path.basename(z.main_binary_path), "dynamic_elf_helloworld"
        )
        self.assertEqual(
            path.basename(z.target_binary_path), "dynamic_elf_helloworld"
        )

    def test_memory_api_pack(self):
        z = Zelos(None)
        self.assertEqual(123, z.memory.unpack(z.memory.pack(123)))
        self.assertEqual(-1, z.memory.unpack(z.memory.pack(-1), signed=True))


def main():
    unittest.main()


if __name__ == "__main__":
    main()
