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

from collections import defaultdict
from typing import Any, Callable, Optional

from zelos.api.memory_api import MemoryApi
from zelos.api.regs_api import RegsApi
from zelos.config_gen import generate_config, generate_config_from_cmdline
from zelos.engine import Engine
from zelos.hooks import HookInfo, HookType
from zelos.plugin import Plugins
from zelos.processes import Process
from zelos.threads import Thread


class Zelos:
    """
    Class that provides access to the core APIs. These core APIs
    are event hooking, debugging, memory access, register access, and
    emulation context.

    Args:
        filename: Specifies the name of the file to emulate.
        cmdline_args: Arguments that are passed to the emulated binary.
        flags: Parameters for zelos. To see the list of all flags, refer
            to :ref:`flag-label`

    Example:
        .. code-block:: python

            from zelos import Zelos

            # initialize zelos with binary name, 2 cmdline args, and
            # verbosity flag set to 1
            z = Zelos(
                "binary_to_emulate"
                "ARG1",
                "ARG2",
                verbosity=1,
            )
    """

    def __init__(self, filename, *cmdline_args, **flags):
        config = generate_config(filename, *cmdline_args, **flags)
        self._setup(config)

    def _setup(self, config):
        self.config = config
        self._regs = RegsApi(self)
        self._memory = MemoryApi(self)

        self._breakpoints = {}
        self._watchpoints = defaultdict(dict)

        # If you need to access data that is not exposed through the api
        # yet, access the internal_engine representation at your own
        # risk.
        Engine(config=config, api=self)
        self.plugins = Plugins(self, ["plugins"])
        self.internal_engine.plugins = self.plugins

    # **** Memory API ****
    @property
    def memory(self):
        """
        Returns the :py:class:`~zelos.api.memory_api.MemoryApi` object.
        """
        return self._memory

    # **** Registers API ****
    @property
    def regs(self):
        """
        Returns the :py:class:`~zelos.api.regs_api.RegsApi` object.
        """
        return self._regs

    # **** Begin Hook API ****
    def hook_memory(
        self,
        hook_type: HookType.MEMORY,
        callback: Callable[["Zelos", int, int, int, int], Any],
        mem_low: Optional[int] = None,
        mem_high: Optional[int] = None,
        name: Optional[str] = None,
        end_condition: Optional[Callable[[], bool]] = None,
    ) -> HookInfo:
        """
        Registers a hook on memory. Executes callback every time the
        specified event happens in memory.

        The hook will only trigger when the event occurs at an address
        between mem_low and mem_high, if either of them are specified.

        The hook will continue to trigger until the end_condition
        specified evaluates to True.

        Args:
            hook_type: Specifies the event in memory that should trigger
                the callback to be executed. Options can be found in
                :py:class:`zelos.HookType.MEMORY`
            callback: The code that should be executed when the
                specified event occurs. The function should accept the
                following inputs: (zelos, access, address, size, value).
                The return value of "callback" is ignored.
            mem_low: If specified, only executes callback if the
                event occurs at an address greater than or equal to
                this.
            mem_high: If specified, only executes callback if the
                event occurs at an address less than or equal to this.
            name: An identifier for this hook. Used for debugging.
            end_condition: If specified, executes after the callback. If
                the function returns True, this hook is deleted.

        Returns:
            Information regarding the hook.

        Example:
            .. code-block:: python

                from zelos import Zelos, HookType

                # Print every write to memory
                def memory_hook(zelos, access, address, size, value):
                    print(value)

                z = Zelos("binary_to_emulate")
                z.hook_memory(
                    HookType.MEMORY.WRITE,
                    memory_hook
                )
                z.start()
        """

        return self.internal_engine.hook_manager.register_mem_hook(
            hook_type,
            callback,
            mem_low=mem_low,
            mem_high=mem_high,
            name=name,
            end_condition=end_condition,
        )

    def hook_execution(
        self,
        hook_type: HookType.EXEC,
        callback: Callable[["Zelos", int, int], Any],
        ip_low: Optional[int] = None,
        ip_high: Optional[int] = None,
        name: Optional[str] = None,
        end_condition: Optional[Callable[[], bool]] = None,
    ) -> HookInfo:
        """
        Registers a hook that executes when code is executed. This is
        either for every instruction that is executed, or every block.

        The hook will only trigger when the event occurs at an address
        between ip_low and ip_high, if either of them are specified.

        The hook will continue to trigger until the end_condition
        specified evaluates to True.

        Args:
            hook_type: Specifies whether the callback should be
                triggered every instruction, or every block. Options can
                be found in :py:class:`zelos.HookType.EXEC`
            callback: The code that should be executed when the
                specified event occurs. The function should accept the
                following inputs: (zelos, address, size).
                The return value of "callback" is ignored.
            mem_low: If specified, only executes callback if the
                event occurs at an address greater than or equal to
                this.
            mem_high: If specified, only executes callback if the
                event occurs at an address less than or equal to this.
            name: An identifier for this hook. Used for debugging.
            end_condition: If specified, executes after the callback. If
                the function returns True, this hook is deleted.

        Returns:
            Information regarding the hook.

        Example:
            .. code-block:: python

                from zelos import Zelos, HookType

                # Print the first address of every block
                def exec_hook(zelos, address, size):
                    print(address)

                z = Zelos("binary_to_emulate")
                z.hook_execution(
                    HookType.EXEC.BLOCK, exec_hook
                )
                z.start()
        """
        return self.internal_engine.hook_manager.register_exec_hook(
            hook_type,
            callback,
            ip_low=ip_low,
            ip_high=ip_high,
            name=name,
            end_condition=end_condition,
        )

    def hook_close(self, closure: Callable[[], Any]) -> HookInfo:
        """
        Registers a closure that is called when
        :py:meth:`zelos.Engine.close()` is called.

        Args:
            closure: Called when zelos is closed. Does not take any
                arguments. The return value of `closure` is ignored

        Example:
            .. code-block:: python

                from zelos import Zelos

                # Close a file you are using with zelos
                file = open("testfile", "r")
                def close_cleanup():
                    file.close()

                z = Zelos("binary_to_emulate")
                z.hook_close(close_cleanup)
                z.start()

                # Hooks are run at this point
                z.close()
        """
        return self.internal_engine.hook_manager.register_close_hook(closure)

    def hook_syscalls(
        self,
        syscall_hook_type: HookType.SYSCALL,
        callback: Callable[["Zelos", str, "Args", int], Any],
        name: str = None,
    ) -> HookInfo:
        """
        Registers a closure that is called when a syscall is invoked.

        Args:
            syscall_hook_type: Decides when the hook should be triggered
                in relation to the execution of the syscall. Options can
                be found in :py:class:`zelos.HookType.SYSCALL`
            callback: The code that should be executed when the
                specified event occurs. The function should accept the
                following inputs:
                (zelos, syscall_name, args, return_value)
                The return value of "callback" is ignored.
            name: An identifier for this hook. Used for debugging.

        Example:
            .. code-block:: python

                from zelos import Zelos, HookType

                # Keep track of the syscall return values
                syscall_return_values = []
                def syscall_hook(zelos, sys_name, args, ret_val):
                    syscall_return_values.append((sys_name, ret_val))

                z = Zelos("binary_to_emulate")
                z.hook_syscalls(
                    HookType.SYSCALL.AFTER, syscall_hook
                )
                z.start()

        """
        return self.internal_engine.hook_manager.register_syscall_hook(
            syscall_hook_type, callback, name
        )

    def delete_hook(self, hook_info: HookInfo) -> None:
        self.internal_engine.hook_manager.delete_hook(hook_info)

    # **** Begin Debugging API ****

    def start(self, timeout: float = 0) -> None:
        """
        Begin emulation. When called for the first time, begins
        execution at the binary entry point. If the emulation is
        stopped (for example, after calling :py:meth:`stop()`) this
        will resume execution from the current IP.

        Args:
            timeout: Stops execution after `timeout` seconds.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                # Start execution from the entry point
                z.start()

        """
        self.internal_engine.start(timeout=timeout)

    def step(self, count=1) -> None:
        """
        Begin emulation, stopping after executing `count` instructions.

        Args:
            count: Maximum number of instructions to execute before
                stopping
        """
        self.internal_engine.step(count=count)

    def stop(self, reason: str = "plugin"):
        """
        Stop the Zelos run loop. After a call to
        :py:meth:`stop()`, execution can be resumed from the
        current IP with a call to :py:meth:`start()`.

        Args:
            reason: An optional identifier that specifies a reason for
                stopping execution. Upon calling stop, the reason will
                be printed to stdout after Zelos exits the run loop.
                This is useful for debugging when log level is set to
                'debug' or 'spam'.
        """
        self.internal_engine.scheduler.stop(reason)

    def close(self):
        """
        Closes Zelos and runs cleanup functions.
        """
        self.internal_engine.close()

    def end_thread(self):
        """
        End the current thread. Marks current thread as successfully
        completed and swaps to the next available thread, if one exists.
        """
        self.internal_engine.thread_manager.complete_current_thread()

    def swap_thread(self, reason: str = "thread swap"):
        """
        Swap the running thread with the next scheduled thread.

        Args:
            reason: An optional identifier that specifies a reason for
                swapping threads. Upon calling swap_thread, the reason
                will be printed to stdout after Zelos has successfully
                swapped to the next scheduled thread. This is useful
                for debugging when log level is set to 'spam'.
        """
        self.internal_engine.scheduler.stop_and_exec(
            reason, self.internal_engine.processes.schedule_next
        )

    def set_breakpoint(self, address: int, temporary: bool = False):
        """
        Set a breakpoint at a particular address.

        Args:
            address: Target address of breakpoint.
            temporary: Determines whether or not the breakpoint is
                temporary. A temporary breakpoint will be automatically
                removed after use.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                z.set_breakpoint(0xdeadbeef)

                z.start()

        """

        def hook(zelos, access, size):
            zelos.stop("breakpoint")

        hook_info = self.internal_engine.hook_manager.register_exec_hook(
            HookType.EXEC.INST,
            hook,
            ip_low=address,
            ip_high=address,
            name=f"breakpoint_{address:x}",
            end_condition=lambda: temporary,
        )

        self._breakpoints[address] = hook_info

        return True

    def remove_breakpoint(self, address: int):
        """
        Remove a previously set breakpoint.

        Args:
            address: Target address of breakpoint to remove.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                z.set_breakpoint(0xdeadbeef)

                z.remove_breakpoint(0xdeadbeef)

                z.start()

        """
        hook_info = self._breakpoints[address]
        self.internal_engine.hook_manager.delete_hook(hook_info)

    def set_syscall_breakpoint(self, syscall_name: str):
        """
        Set a breakpoint at all syscalls of a specified name.

        Args:
            syscall_name: Target syscall set breakpoint at.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                z.set_syscall_breakpoint("write")

                z.start()

        """
        self.internal_engine.zos.syscall_manager.set_breakpoint(syscall_name)

    def remove_syscall_breakpoint(self, syscall_name: str):
        """
        Remove a previously set syscall breakpoint specified by name.

        Args:
            syscall_name: Target syscall to remove breakpoints from.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                z.set_syscall_breakpoint("write")

                z.remove_syscall_breakpoint("write")

                z.start()

        """
        self.internal_engine.zos.syscall_manager.remove_breakpoint(
            syscall_name
        )

    def set_watchpoint(
        self, address: int, read: bool, write: bool, temporary: bool = False
    ):
        """
        Set a watchpoint on a particular memory address.

        Args:
            address: Target address of watchpoint.
            read: Determines whether to watch for reads to the target
                memory address.
            write: Determines whether to watch for writes to the target
                memory address.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                # Break at any read or write to memory address 0xdeadbeef
                z.set_watchpoint(0xdeadbeef, True, True)

                # Break only at writes to memory address 0xfeedf00d
                z.set_watchpoint(0xfeedf00d, False, True)

                # Break only at reads to memory address 0xb0bad00d
                z.set_watchpoint(0xb0bad00d, True, False)

                z.start()

        """

        def hook(zelos, access, address, size, value):
            zelos.stop("watchpoint")

        if read:
            read_hook_info = self.hook_memory(
                HookType.MEMORY.READ,
                hook,
                name=f"read_watchpoint_{address:x}",
                mem_low=address,
                mem_high=address,
                end_condition=lambda: temporary,
            )
            self._watchpoints[address]["read"] = read_hook_info
        if write:
            write_hook_info = self.hook_memory(
                HookType.MEMORY.WRITE,
                hook,
                name=f"write_watchpoint_{address:x}",
                mem_low=address,
                mem_high=address,
                end_condition=lambda: temporary,
            )
            self._watchpoints[address]["write"] = write_hook_info

        return True

    def remove_watchpoint(self, address: int):
        """
        Remove a previously set watchpoint.

        Args:
            address: Target address of watchpoint to remove.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                z.set_watchpoint(0xdeadbeef, True, True)

                z.remove_watchpoint(0xdeadbeef)

                z.start()

        """
        for hook_info in self._watchpoints[address].values():
            self.internal_engine.hook_manager.delete_hook(hook_info)
        del self._watchpoints[address]

        return True

    # **** Begin Context API ****

    @property
    def date(self):
        """
        Returns the date string used internally during emulation. The
        date string format is `YYYY-MM-DD`.

        :getter: Returns the date string in YYYY-MM-DD format.
        :setter: Sets the date string. Input must be YYYY-MM-DD format.
        :type: str
        """
        return self.internal_engine.date

    @date.setter
    def date(self, date_str: str):
        """
        Set the date to be used for emulation. This affects the linux
        system calls sys_time, sys_gettimeofday, and sys_clock_gettime.

        Args:
            date_str: A string of the form `YYYY-MM-DD` specifying the
                target date.

        Example:
            .. code-block:: python

                from zelos import Zelos

                z = Zelos("binary_to_emulate")

                z.date = "2020-03-04"

                z.start()

        """
        self.internal_engine.date = date_str

    @property
    def process(self) -> Process:
        """
        Returns the currently active process.

        :type: Process

        """
        return self.internal_engine.current_process

    @property
    def thread(self) -> Thread:
        """
        Returns the currently active thread.

        :type: Thread

        """
        return self.internal_engine.current_process.current_thread


class ZelosCmdline(Zelos):
    """
    A workaround for allowing `Zelos` to be initialized with a
    commandline string while also allowing the main `Zelos` to maintain
    its simple/intuitive constructor based on commandline arguments and
    flags.
    """

    def __init__(self, cmdline_args):
        config = generate_config_from_cmdline(cmdline_args)
        self._setup(config)
