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

from os import path
from unittest.mock import ANY, Mock

from zelos import Zelos
from zelos.hooks import HookType


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class HookManagerTest(unittest.TestCase):
    def test_hook_at(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"))
        hm = z.internal_engine.current_process.hooks
        action = Mock()
        handle = "handle_val"
        hm.add_hook(HookType.EXEC.INST, action, handle, name="test_hook")
        z.internal_engine.plugins.runner.stop_at(0x2B3C8)
        z.internal_engine.start()
        action.assert_called()

        action.reset_mock()
        # It is worth noting here that the hooks seem to run once for
        # the last instruction, even if this instruction is not
        # executed. In this test, we see that the mock is called
        # 2 times, even though only 1 instruction is executed.
        action.assert_not_called()
        z.step()
        action.assert_called()

        hm._delete_unicorn_hook(handle)
        action.reset_mock()
        action.assert_not_called()
        z.step()
        action.assert_not_called()

    def test_hook_syscall(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"))

        syscall_hook_data = []

        def syscall_hook(p, sys_name, args, retval):
            syscall_hook_data.append((sys_name, args, retval))

        z.internal_engine.hook_manager.register_syscall_hook(
            HookType.SYSCALL.AFTER, syscall_hook, "test_hook"
        )

        z.internal_engine.start()

        self.assertGreaterEqual(len(syscall_hook_data), 12)
        self.assertEqual(syscall_hook_data[0][0], "brk")
        self.assertEqual(syscall_hook_data[0][1].addr, 0)
        self.assertGreater(syscall_hook_data[0][2], 0)
        self.assertEqual(syscall_hook_data[-1][0], "exit_group")

    def test_temp_hook_at(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"))
        action = Mock()
        z.hook_execution(
            HookType.EXEC.INST,
            action,
            ip_low=0x2B3C4,
            ip_high=0x2B3C4,
            end_condition=lambda: True,
        )
        z.internal_engine.plugins.runner.stop_at(0x2B3C8)
        z.internal_engine.start()
        action.assert_called_once()

        action.reset_mock()
        z.internal_engine.plugins.runner.run_to_addr(0x2B3C8)
        action.assert_not_called()

    def test_temp_hook_at_with_end_condition(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_arm_helloworld"), log="debug"
        )
        action = Mock()
        end_condition = Mock(side_effect=[False, True])
        z.hook_execution(
            HookType.EXEC.INST,
            action,
            ip_low=0x2B3C4,
            ip_high=0x2B3C4,
            end_condition=end_condition,
        )
        z.internal_engine.plugins.runner.stop_at(0x2B3C8)
        z.internal_engine.start()
        action.assert_called_once()

        action.reset_mock()
        z.internal_engine.plugins.runner.run_to_addr(0x2B3C8)
        action.assert_called_once()

        action.reset_mock()
        z.internal_engine.plugins.runner.run_to_addr(0x2B3C8)
        action.assert_not_called()

    def test_add_multiple_hooks(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"))
        action1 = Mock(name="action1")
        z.hook_execution(HookType.EXEC.INST, action1, name="test_hook")
        action2 = Mock(name="action2")
        z.hook_execution(HookType.EXEC.INST, action2, name="test_hook")

        z.step()

        action1.assert_called()
        action2.assert_called()

    def test_add_multiple_temp_hooks(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_arm_helloworld"))
        action1 = Mock()
        z.hook_execution(
            HookType.EXEC.INST,
            action1,
            ip_low=0x2B3C4,
            ip_high=0x2B3C4,
            end_condition=lambda: True,
        )
        action2 = Mock()
        z.hook_execution(
            HookType.EXEC.INST,
            action2,
            ip_low=0x2B3C4,
            ip_high=0x2B3C4,
            end_condition=lambda: True,
        )
        action3 = Mock()
        z.hook_execution(
            HookType.EXEC.INST,
            action3,
            ip_low=0x2B3C8,
            ip_high=0x2B3C8,
            end_condition=lambda: True,
        )

        z.internal_engine.plugins.runner.stop_at(0x2B3CC)
        z.internal_engine.start()
        action1.assert_called()
        action2.assert_called()
        action3.assert_called()

    def test_cross_process_hooks_new_process(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        mock_hook = Mock()

        start_process_name = z.internal_engine.current_process.name
        start_addr = 0x8048B70

        hook_info = z.hook_execution(
            HookType.EXEC.INST, mock_hook, name="test_hook"
        )

        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_called_once()
        mock_hook.reset_mock()

        pid = z.internal_engine.processes.new_process("test_process")
        p = z.internal_engine.processes.get_process(pid)
        p.new_thread(start_addr)
        p.memory.copy(z.internal_engine.memory)

        z.internal_engine.processes.load_next_process()
        self.assertEqual(
            z.internal_engine.current_process.name, "test_process"
        )
        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_called_once_with(z, ANY, ANY)
        mock_hook.reset_mock()

        z.delete_hook(hook_info)
        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_not_called()

        z.internal_engine.processes.load_next_process()
        self.assertEqual(
            z.internal_engine.current_process.name, start_process_name
        )
        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_not_called()

    def test_cross_process_hooks_existing_process(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))

        mock_hook = Mock()

        start_process_name = z.internal_engine.current_process.name
        start_addr = 0x8048B70

        pid = z.internal_engine.processes.new_process("test_process")
        p = z.internal_engine.processes.get_process(pid)
        p.new_thread(start_addr)
        p.memory.copy(z.internal_engine.memory)

        hook_info = z.hook_execution(
            HookType.EXEC.INST, mock_hook, name="test_hook"
        )
        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_called_once_with(z, ANY, ANY)
        mock_hook.reset_mock()

        z.internal_engine.processes.load_next_process()
        self.assertEqual(
            z.internal_engine.current_process.name, "test_process"
        )
        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_called_once_with(z, ANY, ANY)
        mock_hook.reset_mock()

        z.delete_hook(hook_info)
        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_not_called()

        z.internal_engine.processes.load_next_process()
        self.assertEqual(
            z.internal_engine.current_process.name, start_process_name
        )
        mock_hook.assert_not_called()
        z.step()
        mock_hook.assert_not_called()


def main():
    unittest.main()


if __name__ == "__main__":
    main()
