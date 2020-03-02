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

from collections import defaultdict
from enum import Enum
from typing import Any, Callable, List, Optional

from unicorn import UC_PROT_READ, UC_PROT_WRITE

import zelos.util as util

from zelos.exceptions import ZelosException
from zelos.scheduler import Scheduler
from zelos.util import struct


class ThreadState(Enum):
    UNKNOWN = 0
    RUNNING = 1
    SUCCESS = 2
    FAILURE = 3
    PAUSED = 4
    KILLED = 5


class ThreadException(ZelosException):
    pass


class InvalidTidException(ZelosException):
    def __init__(self, tid):
        if tid is not None:
            super().__init__(f"{tid:x} is not a valid tid")
        else:
            super().__init__(f"'None' is not a valid tid")


class Thread(object):
    """
    Represents information regarding a thread of execution.

    Remember, a thread is mostly its register state. This is contained
    in the Emu class, and as such, if you are interacting with a thread
    that is not "the current thread" you may not be changing the correct
    state. Remember to save_context and load_context where appropriate
    to ensure that your changes only effect the thread that you care
    about.
    """

    def __init__(
        self,
        thread_manager,
        context,
        stack_base,
        stack_size,
        id,
        name=None,
        priority=0,
        parent=None,
        module_path=None,
        benign_code=False,
    ):
        # OS plugins place OS-specific, thread-level, functionality
        class ZOS(object):
            def __init__(self):
                pass

        self.zos = ZOS()

        self.threads = thread_manager
        self.total_blocks_executed = 0
        self.blocks_executed = defaultdict(int)

        self.id = id
        self.name = "unnamed_thread" if name is None else name
        self.priority = priority
        self.parent = "None" if parent is None else parent.name
        self.parent_id = 0 if parent is None else parent.id
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.context = context
        self.module_path = module_path
        self.state = ThreadState.RUNNING

        self._callstack_indent_count = -1
        self.api_count = 0

        # If the thread fails, keeps track of why.
        self.fail_reason = None

        # If the thread is paused, this condition must evaluate to true
        # to unpause
        self.pause_condition = None

        # We know threads created from DLLs in our windows set are
        # benign, we shouldn't ignore these threads.
        self.benign_code = benign_code

        # TODO:
        # This can point to address of thread local storage
        self.local_data_address = None

        # Address expected to be reached if the thread ends successfully
        self.end_address = 0xDEADBEEF

    @property
    def memory(self):
        return self.threads.memory

    @property
    def emu(self):
        return self.threads.emu

    @property
    def is_active(self):
        return self.state == ThreadState.RUNNING

    def get_reg(self, reg_name: str) -> int:
        """
        Gets the value of the specified register for this thread.

        Args:
            reg_name: The name of the register to get the value of.

        Returns:
            An unsigned integer containing the value of the register.
        """
        return self.threads.as_current_thread(
            self, lambda: self.emu.get_reg(reg_name)
        )

    def set_reg(self, reg_name: str, val: int) -> None:
        """
        Gets the value of the specified register for this thread.

        Args:
            reg_name: The name of the register to set.
            val: The value to set the register to.

        Returns:
            An unsigned integer containing the value of the register.
        """
        self.threads.as_current_thread(
            self, lambda: self.emu.set_reg(reg_name, val)
        )

    def getIP(self) -> int:
        return self.threads.as_current_thread(self, lambda: self.emu.getIP())

    def setIP(self, new_ip: int) -> None:
        self.threads.as_current_thread(self, lambda: self.emu.setIP(new_ip))

    def getSP(self) -> int:
        return self.threads.as_current_thread(self, lambda: self.emu.getSP())

    def setSP(self, new_sp: int) -> None:
        self.threads.as_current_thread(self, lambda: self.emu.setSP(new_sp))

    def getFP(self) -> int:
        return self.threads.as_current_thread(self, lambda: self.emu.getFP())

    def setFP(self, new_fp: int) -> None:
        return self.threads.as_current_thread(
            self, lambda: self.emu.setFP(new_fp)
        )

    def getstack(self, idx: int) -> int:
        return self.threads.as_current_thread(
            self, lambda: self.emu.getstack(idx)
        )

    def setstack(self, idx: int, val: int) -> None:
        self.threads.as_current_thread(
            self, lambda: self.emu.setstack(idx, val)
        )

    def popstack(self) -> int:
        return self.threads.as_current_thread(
            self, lambda: self.emu.popstack()
        )

    def pushstack(self, data: int) -> int:
        return self.threads.as_current_thread(
            self, lambda: self.emu.pushstack(data)
        )

    def get_all_regs(self):
        return self.threads.as_current_thread(
            self, lambda: self.emu.get_all_regs()
        )

    def get_all_reg_vals(self):
        return self.threads.as_current_thread(
            self, lambda: self.emu.get_all_reg_vals()
        )

    def get_regs(self, regs=None):
        return self.threads.as_current_thread(
            self, lambda: self.emu.get_regs(regs)
        )

    def dumpregs(self, regs=None):
        return self.threads.as_current_thread(
            self, lambda: self.emu.dumpregs(regs)
        )

    def pack(self, x, bytes=None, little_endian=None, signed=False):
        return self.threads.emu.pack(x, bytes, little_endian, signed)

    def unpack(self, x, bytes=None, little_endian=None, signed=False):
        return self.threads.emu.unpack(x, bytes, little_endian, signed)

    def __str__(self):
        return f"{self.name} (0x{self.id:x}), PRI: {self.priority}, "
        f"parent: {self.parent}, IP: 0x{self.getIP():x}, "
        f"blocks_exec'd: 0x{self.total_blocks_executed:x}, {self.state}"

    def __lt__(self, other):  # Python 3
        return other.priority < self.priority  # Sorts high to low

    def cleanup(self, z):
        z.emu.mem_unmap(self.stack_base, self.stack_size)

    def save_context(self):
        self.context = self.threads.emu.context_save()

    def load_context(self):
        self.threads.emu.context_restore(self.context)

    def print_stack(self, sp=0, fp=0, top_count=5, bottom_count=10):
        self.threads.current_thread.save_context()
        self.load_context()
        max_lines = 100
        # Start at stack top (sp) and print every 32-bit value between
        # sp and fp, incrementing 4 bytes at a time. Print
        # top{bottom}_count additional stack values from the top and
        # bottom addresses surrounding sp and bp
        result = ""
        if sp == 0:
            sp = self.emu.getSP()
        if fp == 0:
            fp = self.emu.getFP()
        if fp == 0:
            fp = sp
        ptr_size = 4
        address = sp - top_count * ptr_size
        end = fp + bottom_count * ptr_size
        if end < address:
            end = address + 0x4 * 15
        line_count = 0
        while address <= end:
            line_count += 1
            if line_count >= max_lines:
                break
            prefix = "        "
            if address == fp:
                prefix = " fp --> "
            elif address == sp:
                prefix = " sp --> "
            try:
                val = self.emu.mem_read(address, ptr_size)
                val = struct.unpack("<L", val)[0]
                stack_str = prefix + "0x{0:08x}: {1:08x}".format(address, val)
            except Exception:
                break

            # Annotate each line with which function wrote that address.
            owner = self.call_stack.get_stack_addr_owner(address)
            if owner:
                stack_str += "  (" + owner + ")"

            result += stack_str + "\n"
            address += ptr_size
        print(result)
        self.save_context()
        self.threads.current_thread.load_context()


class Threads:
    """
    Handles the execution of multiple threads on the same memory.

    This class should be manipulated through the process layer.
    """

    def __init__(self, emu, memory, stack_size):
        self.stack_min = 0x00000000
        self.stack_max = 0xC0000000  # MAX MIPS 32-bit handles w/ qemu

        self.emu = emu
        self.scheduler = Scheduler(self, emu)
        self.memory = memory
        self.stack_size = stack_size
        self.logger = logging.getLogger(__name__)
        self._reset()

    def _reset(self):
        self.verbose = False
        self.thread_list = []
        self.current_thread = None
        self.dll_funcs = defaultdict(int)

        # A count of threads that are created, so we can create unique
        # names for threads
        self.thread_count = 0

    def __str__(self):
        s = "Thread Manager's Threads:\n"
        threads = self.get_all_threads()
        if len(threads) == 0:
            s += "  No threads present :(\n"
            return s

        for t in sorted(threads, key=lambda x: x.name):
            if self.is_current_thread(t):
                s += f"  *{t}\n"
            else:
                s += f"   {t}\n"

        return s

    @property
    def completed_threads(self):
        return [
            t for t in self.get_all_threads() if t.state == ThreadState.SUCCESS
        ]

    @property
    def failed_threads(self):
        return [
            t for t in self.get_all_threads() if t.state == ThreadState.FAILURE
        ]

    def get_active_threads(self) -> List[Thread]:
        """Returns all active threads"""
        self._check_paused_threads()
        return [t for t in self.get_all_threads() if t.is_active]

    def is_current_thread(self, t: Thread) -> bool:
        """
        Returns True if "t" is the currently running thread.

        Args:
            t: The thread to check.

        Returns:
            True if "t" is currently running.
        """
        return (
            self.current_thread is not None and self.current_thread.id == t.id
        )

    def kill_thread(self, tid: int) -> None:
        """
        Changes the state of the specified thread to KILLED

        Args:
            tid: The thread id of desired thread to kill
        """
        t = self.get_thread(tid)
        if t is None:
            self.logger.notice(f"No thread {tid:x} to kill")
            return
        if t.state != ThreadState.RUNNING:
            self.logger.info(
                f"Thread {tid:x}, is already in state {t.state}. "
                f"Refusing to kill"
            )
            return
        self.logger.info(f"Killing {tid:x}")
        if self.is_current_thread(t):
            self._inactivate_with_state(ThreadState.FAILURE)
        else:
            t.state = ThreadState.KILLED

    def as_current_thread(self, t: Thread, closure: Callable[[], Any]) -> Any:
        """
        Executes the closure as if "t" was the current thread.

        Args:
            t: The thread to set active while executing the closure
            closure: The function to execute

        Returns:
            The result of the closure.
        """
        if self.is_current_thread(t):
            return closure()

        current_thread_tid = None
        if self.current_thread is not None:
            current_thread_tid = self.current_thread.id
            self.swap_with_thread(tid=t.id)

        ret_val = closure()

        if current_thread_tid is not None:
            self.swap_with_thread(tid=current_thread_tid)
        return ret_val

    # TODO(V): Remove this function, put in timeleap
    def record_block(self, block_address):
        if self.current_thread is not None:
            self.current_thread.blocks_executed[block_address] += 1

    def block_seen_before(self, block_address):
        """
        Returns true if the block address has been seen in the current
        thread before
        """
        if self.current_thread is None:
            return None
        return block_address in self.current_thread.blocks_executed

    def num_unique_blocks(self, thread_name=None):
        """
        Returns the number of unique blocks for the given thread.
        Returns unique blocks across threads if no thread name is given
        """
        if thread_name is not None:
            t = self.get_thread_by_name(thread_name)
            return len(t.blocks_executed) if t is not None else 0

        threads = self.get_active_threads()
        return sum(len(t.blocks_executed) for t in threads)

    def executed_within_region(self, begin_addr, end_addr, thread_names=None):
        """
        Returns all block starts within the specified region, executed
        by the specified threads. If no thread_names are specified,
        checks all threads
        """
        threads = self.get_threads(thread_names)
        all_block_starts = []
        for t in threads:
            block_starts = [
                addr
                for addr in t.blocks_executed.keys()
                if begin_addr <= addr < end_addr
            ]
            all_block_starts.extend(block_starts)
        return all_block_starts

    def num_active_threads(self) -> int:
        """
        Returns the number of threads that are still executing.

        Returns:
            Number of threads that are still executing
        """
        return len(self.get_active_threads())

    # Ways a thread can fail
    #   * Inside an API, we can just say what the api is
    #   *   If it was a sys call, it may be useful to indicate this
    #   * Outside an api, this has to be an exception

    def fail_current_thread(self, fail_reason: Optional[str] = None) -> None:
        """
        Records the current thread as a failure and removes it from
        execution

        Args:
            fail_reason: Keeps track of why the thread failed. Used in
                debugging
        """
        self.current_thread.fail_reason = (
            "Unknown" if fail_reason is None else fail_reason
        )
        self.logger.error(
            "Thread %s failed: %s",
            self.current_thread.name,
            self.current_thread.fail_reason,
        )
        self._inactivate_with_state(ThreadState.FAILURE)

    def complete_current_thread(self) -> None:
        """
        Records the current thread as having completed successfully and
        removes it from execution
        """
        self.logger.success(
            f"Done executing thread {self.current_thread.name}"
        )
        self._inactivate_with_state(ThreadState.SUCCESS)

    def pause_current_thread(
        self, condition: Optional[Callable[[], bool]] = None
    ) -> None:
        """
        Pauses the thread until the condition closure is checked and it
        evaluates to true. If no condition is supplied, the thread is
        paused indefinitely.

        Args:
            condition: Evaluated periodically, if it ever returns True,
                unpauses the thread

        """
        if condition is None:

            def condition():
                return False

        if condition():
            self.logger.notice(
                "Pause condition is already true. "
                "This is probably unintended."
            )
            return

        self.current_thread.pause_condition = condition

        self.logger.info(f"Pausing thread {self.current_thread.name}")
        self._inactivate_with_state(ThreadState.PAUSED)

    def _inactivate_with_state(self, thread_state):
        self.current_thread.state = thread_state
        self._swap(None)
        self.emu.setIP(0x30)
        self.scheduler.stop_and_exec("inactivate thread", lambda: True)

    def _check_paused_threads(self):
        """Checks whether any paused threads are ready to run"""
        for t in self.get_all_threads():
            if t.state != ThreadState.PAUSED:
                continue
            if t.pause_condition():
                self.logger.info(f"Thread {t.name} has been unpaused!")
                t.pause_condition = None
                t.state = ThreadState.RUNNING

    def new_thread(
        self,
        start_addr: int,
        tid: int,
        name: Optional[str] = None,
        priority: int = 0,
        stack_setup=None,
        module_path: str = "????",
        benign_code: bool = False,
    ) -> Thread:
        """
        Adds a thread which will run the thread_setup before starting.
        """
        # We want to ensure that we initialize the stack for this thread
        if name is None:
            name = f"child_thread_{self.thread_count}"
            self.thread_count += 1

        stack_bottom = self.memory.map_anywhere(
            self.stack_size,
            min_addr=self.stack_min,
            max_addr=self.stack_max,
            name=name,
            kind="stack",
            prot=UC_PROT_READ | UC_PROT_WRITE,
        )

        stack_base = util.align_down(
            stack_bottom + self.stack_size - 1, alignment=0x1000
        )

        new_thread = self.create_thread(
            start_addr,
            tid,
            stack_base,
            name,
            priority,
            stack_setup,
            module_path,
            benign_code,
        )

        self.thread_list.append(new_thread)

        return new_thread

    def create_thread(
        self,
        start_addr,
        tid,
        stack_base,
        name=None,
        priority=0,
        stack_setup=None,
        module_path="????",
        benign_code=False,
    ) -> Thread:
        temp_context = self.emu.context_save()
        self.emu.setIP(start_addr)
        new_thread_context = self.emu.context_save()

        self.logger.debug(
            f"  Adding thread {name} (priority {priority}) "
            f"stack base at {stack_base:x}"
        )
        new_thread = Thread(
            self,
            new_thread_context,
            stack_base,
            self.stack_size,
            tid,
            name,
            priority,
            parent=self.current_thread,
            module_path=module_path,
            benign_code=benign_code,
        )

        # TODO: Not a fan of the fact that we set the current thread to
        # be the new thread for the hooks. Need to find a way to allow
        # for the thread_create hooks to run, without having to
        # continually switch between the active thread and this one.

        self.emu.context_restore(temp_context)
        return new_thread

    def change_thread_priority(self, thread_name, new_priority):
        """ Change the priority of a thread"""
        t = self.get_thread_by_name(thread_name)
        if t is None:
            print("Unable to find thread %s" % thread_name)
            return
        t.priority = new_priority

    def get_all_threads(self) -> List[Thread]:
        """ Returns all threads, whether active or stopped"""
        return self.thread_list[:]

    def get_thread_by_name(self, name: str) -> Optional[Thread]:
        """ Returns the first thread with the given name """
        threads = self.get_threads([name])
        return threads[0] if len(threads) > 0 else None

    def get_thread(self, tid):
        for t in self.get_all_threads():
            if t.id == tid:
                return t
        return None

    def get_threads(self, names):
        """
        Returns threads that have a name within the given list. If names
        is None, returns all threads
        """
        if names is None:
            return self.get_all_threads()
        threads = []
        for t in self.get_all_threads():
            if t.name in names:
                threads.append(t)
        return threads

    def get_child_threads(self, tid: int) -> List[Thread]:
        """Returns all threads with the given parent name"""
        return [t for t in self.get_all_threads() if t.parent_id == tid]

    def swap_with_thread(
        self, name: Optional[str] = None, tid: Optional[int] = None
    ) -> None:
        """
        Swaps the current thread with the first thread with the given
        name or thread id. Keep in mind, this will override the priority
        given to threads.
        You can only specify one of name or tid.

        Args:
            name: If specified, finds a thread by the name
            tid: If specified, finds a thread with that thread id
        """
        if name is None and tid is None:
            raise ThreadException("Must specify at least one of name/tid")
        if name is not None and tid is not None:
            raise ThreadException("May only specify one of name/tid")
        if name is not None:
            t = self.get_thread_by_name(name)
            if t is None:
                raise ThreadException(f"No thread named {name} exists.")
        if tid is not None:
            t = self.get_thread(tid)
            if t is None:
                raise InvalidTidException(tid)

        self._swap(t)

    def swap_with_next_thread(self) -> None:
        """
        Swaps the current thread with the next thread to execute. This
        respects priority, and will not swap if there is no thread of
        equal or greater priority
        """
        self._check_paused_threads()
        t = self._next()
        if t is None:
            self.logger.spam("Can't swap with thread, no other threads")

        self._swap(t)

    def _swap(self, thread):
        """
        Swaps the currently executing thread with the specified thread
        in the emulator
        """
        if self.current_thread is not None:
            self.current_thread.save_context()
        self._load(thread)

    def _load(self, thread):
        """ Loads the specified thread into the emulator """
        if thread is None:
            self.current_thread = None
            return
        if not thread.is_active:
            self.logger.error(
                f"Loading a thread with inactive state {thread.state}"
            )
        self.emu.context_restore(thread.context)
        self.current_thread = thread
        self.logger.verbose(
            "Loaded thread {0}, starting at {1:x}, stack at {2:x}".format(
                thread.name, self.emu.getIP(), self.emu.getSP()
            )
        )
        self.emu.setIP(self.emu.getIP())

    def _next(self, tid=None):
        """Returns the next thread to be scheduled."""
        active_threads = sorted(self.get_active_threads())
        if len(active_threads) == 0:
            return None
        next_thread = active_threads[0]
        self._send_to_back(next_thread.id)
        return next_thread

    def _send_to_back(self, tid):
        """
        Sends this tid back to the end of the list. Used for scheduling.
        """
        for i, t in enumerate(self.thread_list):
            if t.id == tid:
                self.thread_list.append(self.thread_list.pop(i))
                return
        raise InvalidTidException(tid)

    regs_to_save = (
        "eax",
        "ebp",
        "ebx",
        "ecx",
        "edi",
        "edx",
        "flags",
        "eip",
        "esi",
        "esp",
    )

    def _save_state(self):
        def _serialize_thread(thread):
            if thread is None:
                return None
            d = thread.__dict__.copy()
            del d["context"]  # Can't pickle, must be removed from dict
            self.emu.context_restore(thread.context)
            return (d, [self.emu.get_reg(reg) for reg in self.regs_to_save])

        if self.current_thread is not None:
            self.current_thread.save_context()

        context = {
            # Must be done first, since it is current loaded
            "current_thread_tid": self.current_thread.id
            if self.current_thread is not None
            else None,
            "thread_list": [_serialize_thread(t) for t in self.thread_list],
            "thread_count": self.thread_count,
        }

        # Restore the current thread's context
        if self.current_thread is not None:
            self.emu.context_restore(self.current_thread.context)
        return context

    def _load_state(self, data):
        self._reset()

        def _deserialize_thread(data):
            if data is None:
                return None
            (thread_dict, reg_vals) = data
            # Unsure if you need deepcopy, but you definitely need to
            # make sure that you are not linking the state data and the
            # thread_manager.
            thread_dict = thread_dict.copy()
            for val, reg in zip(reg_vals, self.regs_to_save):
                self.emu.set_reg(reg, val)
            thread_dict["context"] = self.emu.context_save()
            # Get a thread, we will set attributes manually.
            t = Thread(None, None, None, None, None)
            t.__dict__ = thread_dict
            return t

        self.thread_list = [
            _deserialize_thread(d) for d in data["thread_list"]
        ]
        # End with loading the current_thread, so that execution state
        # is ready to go.
        current_thread = self.get_thread(data["current_thread_tid"])
        self._load(current_thread)
        self.thread_count = data["thread_count"]
