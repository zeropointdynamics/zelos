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
import logging

from typing import Callable, Dict, List

import unicorn as uc

from zelos.emulator import create_emulator
from zelos.emulator.base import IEmuHelper
from zelos.emulator.x86_gdt import GDT_32
from zelos.exceptions import ZelosLoadException
from zelos.handles import Handles
from zelos.hooks import HookManager, Hooks, HookType, InterruptHooks
from zelos.memory import Memory
from zelos.modules import Modules
from zelos.scheduler import Scheduler
from zelos.state import State
from zelos.threads import Thread, Threads


# This has no dependencies. Purposefully not subclassing with IManager.
# If those dependencies are needed, go ahead and subclass it.
# Just kept it out for cleanliness


class Process:
    def __init__(
        self,
        processes: str,
        hook_manager: HookManager,
        pid: int,
        name: str,
        emu: IEmuHelper,
        parent_pid: int,
        main_module: str = None,
        orig_file_name: str = "",
        cmdline_args: List = None,
        environment_variables: List = None,
        virtual_filename: str = None,
        virtual_path: str = None,
        last_instruction: str = None,
        last_instruction_size: int = 0,
        disableNX: bool = False,
    ):
        # OS plugins place OS-specific, process-level, functionality
        class ZOS(object):
            def __init__(self):
                pass

        self.zos = ZOS()

        self.processes = processes
        self._hook_manager = hook_manager
        self.emu = emu
        self.name = name
        self.pid = pid
        self.parent_pid = parent_pid
        self.main_module = main_module
        self.main_module_name = (
            "" if main_module is None else main_module.Filepath
        )
        self.cmdline_args = [] if cmdline_args is None else cmdline_args
        self.environment_variables = (
            [] if environment_variables is None else environment_variables
        )
        self.virtual_filename = virtual_filename
        self.virtual_path = virtual_path
        self.original_file_name = orig_file_name
        self.last_instruction = last_instruction
        self.last_instruction_size = last_instruction_size

        self.modules = Modules()

        self.memory = Memory(self.emu, processes.state, disableNX=disableNX)

        self.threads = Threads(
            self.emu, self.memory, self.processes.stack_size
        )
        self.hooks = Hooks(self.emu, self.threads)

    def __str__(self) -> str:
        return f"Name: '{self.name}', pid: {self.pid:x}, "
        f"Active threads: {self.threads.num_active_threads()}"

    @property
    def is_active(self) -> bool:
        """
        Returns true if this process can be scheduled.
        """
        return self.threads.num_active_threads() > 0

    @property
    def scheduler(self) -> Scheduler:
        return self.threads.scheduler

    @property
    def current_thread(self) -> Thread:
        return self.threads.current_thread

    def new_thread(
        self,
        start_addr: int,
        name: str = None,
        priority: int = 0,
        stack_setup: Callable = None,
        module_path: str = "????",
        benign_code: bool = False,
    ) -> Thread:
        """
        Creates a new thread for the current process.

        Args:
            start_addr: The starting address of the new thread
            name: Name of the new thread
            priority: Scheduling priority of the new thread
            stack_setup: Callback that populates stack of the new thread
            module_path: Name of module of new thread
            benign_code: Logging parameter

        Returns:
            Thread object
        """
        if len(self.threads.get_all_threads()) == 0:
            tid = self.pid
        else:
            tid = self.processes.gen_tid()
        if name is None:
            name = f"{self.pid:x}_thread_{len(self.threads.get_all_threads())}"
        t = self.threads.new_thread(
            start_addr,
            tid,
            name=name,
            priority=priority,
            stack_setup=stack_setup,
            module_path=module_path,
            benign_code=benign_code,
        )

        current_thread = self.current_thread
        self.threads.swap_with_thread(tid=t.id)
        for hook in self._hook_manager._get_hooks(HookType.THREAD.CREATE):
            hook(t, stack_setup)
        if current_thread is not None:
            self.threads.swap_with_thread(tid=current_thread.id)
        return t

    def get_thread(self, tid: int) -> Thread:
        """
        Gets the thread in this process with the specified tid.

        Args:
            tid: Thread id

        Returns:
            Thread object
        """
        return self.threads.get_thread(tid)

    def get_child_processes(self) -> List:
        """
        Get a list of all child processes created by this process.

        Returns:
            List of Process Objects
        """
        return [
            p for p in self.processes.process_list if p.parent_pid == self.pid
        ]

    def priority(self) -> int:
        """
        Returns the scheduling priority of this process. The scheduling
        priority of a Process is that of its highest priority Thread.

        Returns:
            Number denoting priority
        """
        thread_priority_list = [
            t.priority for t in self.threads.get_active_threads()
        ]
        if len(thread_priority_list) == 0:
            return -100
        return max(thread_priority_list)

    def blocks_executed(self) -> int:
        """
        Calculates # of unique blocks executed across all threads
        of this process.

        Returns:
            Number of blocks executed
        """
        unique_blocks = set()
        for t in self.threads.get_all_threads():
            unique_blocks.update(t.blocks_executed)
        return len(unique_blocks)

    def __lt__(self, other) -> bool:  # Python 3
        return other.priority() < self.priority()  # Sorts high to low


class Processes:
    """ Exposes the processes that are on the virtual machine."""

    def __init__(
        self,
        hook_manager: HookManager,
        interrupt_handler: InterruptHooks,
        main_module_name: str,
        thread_stack_size: int,
        disableNX: bool = False,
    ):
        self._hook_manager = hook_manager
        self._interrupt_handler = interrupt_handler
        self.process_list = []
        self.state = None
        self.stack_size = thread_stack_size
        self.next_tid = 0x7400
        self.logger = logging.getLogger(__name__)
        self.disableNX = disableNX
        self.main_module_name = main_module_name

        self.current_process = None

        # Counter to keep track of which process we are at.
        self.process_counter = 0

        self.handles = Handles(self, hook_manager)

        def apply_cross_process_hooks(p):
            for hook in self._hook_manager._cross_process_hooks.values():
                p.hooks.add_hook(
                    hook.type,
                    hook.callback,
                    hook.handle,
                    name=hook.name,
                    start_addr=hook.start,
                    end_addr=hook.end,
                )

        self._hook_manager.register_process_hook(
            HookType.PROCESS.CREATE, apply_cross_process_hooks
        )

    def set_architecture(self, state: State) -> None:
        self.state = state

    def _create_first_process(self, main_module_name: str) -> None:
        self.new_process(main_module_name + "_main", None)
        self.current_process = self.process_list[0]

    def __str__(self) -> str:
        s = "Process Manager's Processes:\n"
        for p in self.process_list:
            s += p.__str__() + "\n"
            s += p.threads.__str__() + "\n"
        return s

    @property
    def current_thread(self) -> Thread:
        return self.current_process.current_thread

    @property
    def thread_manager(self) -> Threads:
        return self.current_process.threads

    def gen_tid(self) -> int:
        """
        Generates a tid that is guaranteed not to have been used before.
        """
        tid = self.next_tid
        self.next_tid += 1
        return tid

    def new_process(
        self,
        name: str = None,
        parent_pid: int = None,
        main_module=None,
        cmdline_args: List = [],
    ) -> int:
        """
        Creates a new process.

        Args:
            name: Name of the new thread.
            parent_pid: ID of the parent process.
            main_module: Module that is used to start the new process.
            cmdline_args: Arguments to pass to the new process.

        Returns:
            ID of the newly created process.
        """
        pid = self.gen_tid()

        if name is None:
            name = f"proc_{self.process_counter}"
        if self.current_process is not None:
            if parent_pid is None:
                parent_pid = self.current_process.pid
            if main_module is None:
                main_module = self.current_process.main_module

        process = Process(
            self,
            self._hook_manager,
            pid,
            name,
            self._create_emulator(),
            parent_pid,
            main_module=main_module,
            cmdline_args=cmdline_args,
            disableNX=self.disableNX,
        )

        for hook in self._hook_manager._get_hooks(HookType.PROCESS.CREATE):
            hook(process)

        self.process_list.insert(0, process)
        self.process_counter += 1

        if self.state.arch in ["x86", "x86_64"]:
            process.gdt = GDT_32(process.memory)

        return pid

    def _create_emulator(self) -> IEmuHelper:
        arch = self.state.arch

        uc_arch_mode_dict = {
            "x86": (uc.UC_ARCH_X86, uc.UC_MODE_32),
            "x86_64": (uc.UC_ARCH_X86, uc.UC_MODE_64),
            "arm": (uc.UC_ARCH_ARM, uc.UC_MODE_ARM),
            "mips": (uc.UC_ARCH_MIPS, uc.UC_MODE_MIPS32),
        }

        (uc_arch, uc_mode) = uc_arch_mode_dict[arch]

        endianness = self.state.endianness
        if endianness == "little":
            uc_mode |= uc.UC_MODE_LITTLE_ENDIAN
        elif endianness == "big":
            uc_mode |= uc.UC_MODE_BIG_ENDIAN
        else:
            raise ZelosLoadException(f"Unsupported endianness {endianness}")

        return create_emulator(uc_arch, uc_mode, self.state)

    def _as_current_process(self, p: Process, closure: Callable) -> None:
        temp = self.current_process
        self.current_process = p
        closure()
        self.current_process = temp

    def kill_process(self, pid: int) -> None:
        """
        Stops a running process and all its threads.

        Args:
            pid: ID of process to kill
        """
        p = self.get_process(pid)
        if p is not None:
            for t in p.threads.get_active_threads():
                p.threads.kill_thread(t.id)

    def new_thread_for_current_process(
        self,
        start_addr: int,
        name: str = None,
        priority: int = 0,
        stack_setup: Callable = None,
        module_path: str = "????",
        benign_code: bool = False,
    ) -> Thread:
        """
        Creates a new thread for the currently running process.

        Args:
            start_addr: The starting address of the new thread
            name: Name of the new thread
            priority: Scheduling priority of the new thread
            stack_setup: Callback that populates stack of the new thread
            module_path: Name of module of new thread
            benign_code: Logging parameter

        Returns:
            Thread object
        """
        return self.current_process.new_thread(
            start_addr,
            name,
            priority=priority,
            stack_setup=stack_setup,
            module_path=module_path,
            benign_code=benign_code,
        )

    def num_active_processes(self) -> int:
        return len([1 for p in self.process_list if p.is_active])

    def get_process(self, pid: int) -> Process:
        for p in self.process_list:
            if p.pid == pid:
                return p
        self.logger.notice(f"No process for pid {pid:x}")
        return None

    def get_thread(self, tid: int) -> Thread:
        """
        Gets the thread for the given tid.

        Args:
            tid: ID of thread.
        """
        for p in self.process_list:
            t = p.get_thread(tid)
            if t is not None:
                return t
        return None

    def get_all_threads(self) -> List[Thread]:
        """Returns a list of threads across all processes"""
        return [
            t for p in self.process_list for t in p.threads.get_all_threads()
        ]

    def load_next_process(self) -> None:
        """
        Loads the next process. Will skip processes that are not active.
        """
        self.process_list.sort()
        p = self.process_list.pop(0)
        self.process_list.append(p)
        self._load(p)

    def schedule_next(self) -> None:
        """
        Swaps processes and threads in order to ensure that all
        eventually get executed.
        """
        # TODO: consider process following a process priority based on
        # thread priority?
        self.load_next_process()
        self.swap_with_next_thread()

    def swap_with_next_thread(self) -> None:
        """
        Tries to swap with the next thread in the current process.
        If that is not possible, attempts to swap processes.
        """
        if self.current_process.is_active:
            self.current_process.threads.swap_with_next_thread()
            for hook in self._hook_manager._get_hooks(HookType.THREAD.SWAP):
                hook(self.current_thread)
        else:
            self.load_next_process()

    def load_process(self, pid) -> None:
        """
        This attempts to load the designated process. This is a no-op
        if the process to be loaded is the same as the current process.

        Args:
            pid: ID of Process to load.
        """
        p = self.get_process(pid)
        self._load(p)

    def _load(self, p) -> None:
        if self.current_process is not None:
            if self.current_process.pid == p.pid:
                return
            assert not self.current_process.emu.is_running
        self.logger.verbose(f"Loading process 0x{p.pid:x}")
        self.current_process = p
        if self.current_process.current_thread is None:
            p.threads.swap_with_next_thread()

    def serialize_process(self, p):
        raise NotImplementedError()

    def deserialize_process(self, data):
        raise NotImplementedError()

    def _save_state(self) -> Dict:
        def serialize_process(self, p):
            return {}

        context = {
            "deprecated_next_pid": self.deprecated_next_pid,
            "process_list": [
                self.serialize_process(p) for p in self.process_list
            ],
        }
        return context

    def _load_state(self, data) -> None:
        def deserialize_process(self, process_data):
            pass

        self.deprecated_next_pid = data["deprecated_next_pid"]
        self.process_list = [
            self.deserialize_process(pdata) for pdata in data["process_list"]
        ]
