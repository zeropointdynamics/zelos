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
# <http://www.internal_engine.gnu.org/licenses/>.
# ======================================================================
import unittest

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_MODE_32,
    UC_MODE_64,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_INS_SYSCALL,
    UC_X86_REG_EAX,
    UC_X86_REG_EIP,
    UC_X86_REG_RAX,
)

from zelos import Zelos


class UnicornTest(unittest.TestCase):
    def test_fail_end_partial_addr(self):
        w = Zelos(None)
        w.internal_engine.interrupt_handler.disable()
        uc = w.internal_engine.emu
        uc.mem_map(0, 0x2000)
        self.assertRaises(
            UcError, uc.emu_start, 0x1000, 0x1007
        )  # ends inbetween instruction

    def test_hooks(self):
        record = []

        def hook(uc, address, size, userdata):
            record.append(address)

        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0, 0x2000)
        uc.hook_add(UC_HOOK_CODE, hook)
        uc.emu_start(0x1000, 0x1006)
        self.assertListEqual(record, [0x1000, 0x1002, 0x1004])

    def test_setip_before_emustop(self):
        record = []
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        def hook(uc, address, size, userdata):
            record.append(address)

        def hook_stop(uc, address, size, userdata):
            if address == 0x1002:
                uc.reg_write(UC_X86_REG_EIP, 0x1006)
                uc.emu_stop()

        uc.mem_map(0, 0x2000)
        uc.hook_add(UC_HOOK_CODE, hook)
        uc.hook_add(UC_HOOK_CODE, hook_stop)
        uc.emu_start(0x1000, 0x1008)
        self.assertListEqual(record, [0x1000, 0x1002, 0x1006])

    def test_setip_after_emustop(self):
        record = []
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        def hook(uc, address, size, userdata):
            record.append(address)

        def hook_stop(uc, address, size, userdata):
            if address == 0x1002:
                uc.emu_stop()
                uc.reg_write(UC_X86_REG_EIP, 0x1006)

        uc.mem_map(0, 0x2000)
        uc.hook_add(UC_HOOK_CODE, hook)
        uc.hook_add(UC_HOOK_CODE, hook_stop)
        uc.emu_start(0x1000, 0x1008)
        self.assertListEqual(record, [0x1000, 0x1002, 0x1006])

    def test_multiprocess(self):
        record = []

        def hook(uc, address, size, userdata):
            record.append(address)

        uc1 = Uc(UC_ARCH_X86, UC_MODE_32)
        uc1.hook_add(UC_HOOK_CODE, hook)
        uc1.mem_map(0, 0x2000)

        uc2 = Uc(UC_ARCH_X86, UC_MODE_32)
        uc2.hook_add(UC_HOOK_CODE, hook)
        uc2.mem_map(0, 0x2000)

        uc1.emu_start(0x1000, 0x1006)
        self.assertListEqual(record, [0x1000, 0x1002, 0x1004])

        uc2.emu_start(0x1000, 0x1006)
        self.assertListEqual(
            record, [0x1000, 0x1002, 0x1004, 0x1000, 0x1002, 0x1004]
        )

        uc1.reg_write(UC_X86_REG_EAX, 5)
        context1 = uc1.context_save()

        uc2.reg_write(UC_X86_REG_EAX, 6)
        context2 = uc2.context_save()

        self.assertEqual(uc1.reg_read(UC_X86_REG_EAX), 5)
        self.assertEqual(uc2.reg_read(UC_X86_REG_EAX), 6)

        uc2.context_restore(context1)
        uc1.context_restore(context2)
        self.assertEqual(uc1.reg_read(UC_X86_REG_EAX), 6)
        self.assertEqual(uc2.reg_read(UC_X86_REG_EAX), 5)

    def test_what_executes_when_switching_eip(self):
        record = []

        def hook(uc, address, size, userdata):
            record.append(address)
            if address == 0x1002:
                uc.reg_write(UC_X86_REG_EIP, 0x1006)

        w = Zelos(None)
        w.internal_engine.interrupt_handler.disable()
        uc = w.internal_engine.emu
        uc.mem_map(0, 0x2000)
        # Push 1, Push 2, push 3... that way you can tell what
        # instructions have actually executed
        # by investigating the stack
        uc.mem_write(0x1000, b"\x6A\x01\x6A\x02\x6A\x03\x6A\x04\x6A\x05")
        w.internal_engine.emu.setSP(0x100)

        uc.hook_add(UC_HOOK_CODE, hook)
        uc.emu_start(0x1000, 0x1008)
        self.assertListEqual(record, [0x1000, 0x1002, 0x1006])
        self.assertEqual(0xF8, w.internal_engine.emu.getSP())

        self.assertEqual(4, w.internal_engine.emu.getstack(0))
        self.assertEqual(1, w.internal_engine.emu.getstack(1))
        self.assertEqual(0, w.internal_engine.emu.getstack(2))

    def test_many_prefixes(self):
        # These two instructions need to fail, since they are too long.

        w = Zelos(None)
        uc = w.internal_engine.emu
        uc.mem_map(0, 0x2000)
        uc.mem_write(
            0x1000,
            b"\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\xA1\xF0\x10"
            b"\x00\x00",
        )
        try:
            uc.emu_start(0x1000, 0x1010)
            self.assertEqual(1, 0)
        except Exception:
            pass
        # self.assertEqual(uc.getIP(), 0x1010)
        uc.mem_write(
            0x1100,
            b"\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E"
            b"\x3E\x3E\xA1\xF0\x10\x00\x00",
        )
        try:
            uc.emu_start(0x1100, 0x1114)
            self.assertEqual(1, 0)
        except Exception:
            pass
        # self.assertEqual(uc.getIP(), 0x1114)

    def test_x86_64_syscall(self):
        print("Emulate x86_64 code with 'syscall' instruction")
        ADDRESS = 0x1000000
        X86_CODE64_SYSCALL = b"\x0f\x05"  # SYSCALL
        # Initialize emulator in X86-64bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64_SYSCALL)

        def hook_syscall(mu, user_data):
            rax = mu.reg_read(UC_X86_REG_RAX)
            if rax == 0x100:
                mu.reg_write(UC_X86_REG_RAX, 0x200)
            else:
                print("ERROR: was not expecting rax=%d in syscall" % rax)

        # hook interrupts for syscall
        mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

        # syscall handler is expecting rax=0x100
        mu.reg_write(UC_X86_REG_RAX, 0x100)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64_SYSCALL))
        except UcError as e:
            print("ERROR: %s" % e)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        rax = mu.reg_read(UC_X86_REG_RAX)
        print(">>> RAX = 0x%x" % rax)

    # This will cause a segfault
    # def test_run_within_hook(self):
    #     record = []

    #     def hook(uc, address, size, userdata):
    #         record.append(address)
    #         if address == 0x1002:
    #             uc.emu_stop()
    #             uc.emu_start(0x1006, 0x1008)

    #     w = Zelos(None)
    #     uc = w.internal_engine.emu
    #     uc.mem_map(0, 0x2000)
    #     # Push 1, Push 2, push 3... that way you can tell what
    #     # instructions have actually executed
    #     # by investigating the stack
    #     uc.mem_write(
    #         0x1000, b'\x6A\x01\x6A\x02\x6A\x03\x6A\x04\x6A\"
    # b"x05\x6A\x06')
    #     w.internal_engine.emu.setSP(0x100)

    #     uc.hook_add(UC_HOOK_CODE, hook)
    #     uc.emu_start(0x1000, 0x100a)
    #     self.assertListEqual(record, [0x1000, 0x1002, 0x1006])
    #     self.assertEqual(0xf8, w.internal_engine.emu.getSP())

    #     self.assertEqual(4, w.internal_engine.emu.getstack(0))
    #     self.assertEqual(1, w.internal_engine.emu.getstack(1))
    #     self.assertEqual(0, w.internal_engine.emu.getstack(2))


def main():
    unittest.main()


if __name__ == "__main__":
    main()
