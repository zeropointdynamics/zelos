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

import functools
import logging

from collections import defaultdict
from typing import Any, Callable, Optional

import zebracorn as uc

from zelos.enums import HookType
from zelos.exceptions import InvalidHookTypeException, ZelosRuntimeException


class HookInfo:
    def __init__(
        self,
        hook_type,
        callback,
        handle,
        name: str = "",
        start=None,
        end=None,
        end_condition=None,
    ):
        self.type = hook_type
        self.callback = callback
        self.handle = handle
        self.name = name
        self.start = start
        self.end = end
        self.end_condition = end_condition

    def __str__(self):
        hook_string = f"{self.name}, Type {self.type}"
        if self.start is not None or self.end is not None:
            start = "None" if self.start is None else hex(self.start)
            end = "None" if self.end is None else hex(self.end)

            hook_string += f", Effective from {start} - {end}"
        return hook_string


def _zelos_hook_to_zebracorn(hook_type):
    return {
        HookType.MEMORY.READ: uc.UC_HOOK_MEM_READ,
        HookType.MEMORY.WRITE: uc.UC_HOOK_MEM_WRITE,
        HookType.MEMORY.READ_UNMAPPED: uc.UC_HOOK_MEM_READ_UNMAPPED,
        HookType.MEMORY.WRITE_UNMAPPED: uc.UC_HOOK_MEM_WRITE_UNMAPPED,
        HookType.MEMORY.READ_PROT: uc.UC_HOOK_MEM_READ_PROT,
        HookType.MEMORY.WRITE_PROT: uc.UC_HOOK_MEM_WRITE_PROT,
        HookType.MEMORY.READ_AFTER: uc.UC_HOOK_MEM_READ_AFTER,
        HookType.MEMORY.UNMAPPED: uc.UC_HOOK_MEM_UNMAPPED,
        HookType.MEMORY.PROT: uc.UC_HOOK_MEM_PROT,
        HookType.MEMORY.READ_INVALID: uc.UC_HOOK_MEM_READ_INVALID,
        HookType.MEMORY.WRITE_INVALID: uc.UC_HOOK_MEM_WRITE_INVALID,
        HookType.MEMORY.INVALID: uc.UC_HOOK_MEM_INVALID,
        HookType.MEMORY.VALID: uc.UC_HOOK_MEM_VALID,
        HookType.EXEC.INST: uc.UC_HOOK_CODE,
        HookType.EXEC.BLOCK: uc.UC_HOOK_BLOCK,
        HookType._OTHER.INTERRUPT: uc.UC_HOOK_INTR,
        HookType._INST.X86_SYSCALL: uc.x86_const.UC_X86_INS_SYSCALL,
    }[hook_type]


class HookManager:
    """
    Manages hooks that allow user code to execute at certain predefined
    events, such as the creation of threads/process, or the execution of
    a block of instructions.
    """

    def __init__(self, z, api) -> None:
        self.logger = logging.getLogger(__name__)
        self.z = z
        self.api = api
        self.exception_handle_hook = None

        self._hook_index = 0
        self._hooks = defaultdict(dict)

        self._cross_process_hooks = {}

        # Used to keep track of hook deletions that need to occur once
        # zebracorn is done running (since they can't safely occur while
        # zebracorn is running).
        self._to_delete_closures = []

        # Kernel hooks are used to track memory reads and writes that
        # are done by Zelos. However, memory initialization is not
        # interesting in that sense. We only turn on kernel_hooks after
        # initialization has been completed.
        self._internal_mem_hooks_enabled = False

        # In order to use function hooks, we need to know the base
        # address of the target module. This is not immediately
        # available for dynamic binaries. We will wait for the first
        # time the target binary is mapped into memory.
        self._func_hooks_enabled = False
        self._func_hooks_to_register = []

    def register_mem_hook(
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
                the callback to be executed.
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

        Returns
            Information regarding the hook. Can be used for deletion.

        """

        if self.is_internal_mem_hook(hook_type):
            return self._register_zelos_mem_hook(
                hook_type, callback, mem_low, mem_high, name, end_condition
            )

        def memhook_wrapper(uc, access, address, size, value, user_data):
            return callback(self.api, access, address, size, value)

        return self._add_zebracorn_hook(
            hook_type,
            memhook_wrapper,
            name,
            mem_low,
            mem_high,
            end_condition=end_condition,
        )

    def _register_zelos_mem_hook(
        self, hook_type, callback, mem_low, mem_high, name, end_condition
    ) -> HookInfo:
        """
        Used to hook memory reads and writes that are done by Zelos.
        """

        def zelos_memhook_wrapper(access, address, size, value):
            nonlocal hook_info
            try:
                if mem_low is not None and address + size <= mem_low:
                    return
                if mem_high is not None and address > mem_high:
                    return
                callback(self.api, access, address, size, value)
                if end_condition is not None and end_condition():
                    self.delete_hook(hook_info)
            except Exception as e:
                self.logger.exception(f"Error running mem hook: {e}")

        hook_info = self._add_zelos_hook(
            hook_type, zelos_memhook_wrapper, name
        )
        return hook_info

    def register_exec_hook(
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
                triggered every instruction, or every block.
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

        Returns
            Information regarding the hook. Can be used for deletion.
        """

        def exechook_wrapper(uc, address, size, user_data):
            return callback(self.api, address, size)

        return self._add_zebracorn_hook(
            hook_type,
            exechook_wrapper,
            name,
            ip_low,
            ip_high,
            end_condition=end_condition,
        )

    def register_interrupt_hook(
        self, callback, intno=None, name=None, end_condition=None
    ):
        if intno is None:
            return self.z.interrupt_handler.register_generic_interrupt_handler(
                callback
            )
        else:
            return self.z.interrupt_handler.register_interrupt_handler(
                intno, callback
            )

    def register_thread_hook(self, hook_type, callback, name=None):
        if not isinstance(hook_type, HookType.THREAD):
            raise InvalidHookTypeException()
        return self._add_zelos_hook(hook_type, callback, name)

    def register_process_hook(self, hook_type, callback, name=None):
        if not isinstance(hook_type, HookType.PROCESS):
            raise InvalidHookTypeException()
        return self._add_zelos_hook(hook_type, callback, name)

    def register_inst_type_hook(
        self, inst_type, callback, name="", start_addr=None, end_addr=None
    ) -> HookInfo:
        def insttype_hook_wrapper(uc, user_data):
            return callback(self.api)

        return self._add_zebracorn_hook(
            inst_type,
            insttype_hook_wrapper,
            name=name,
            start_addr=start_addr,
            end_addr=end_addr,
        )

    def register_syscall_hook(
        self, syscall_hook_type, callback, name=None, syscall_name=None
    ) -> HookInfo:
        if syscall_name is not None:

            def syscall_callback_wrapper(zelos, sysname, args, retval):
                if sysname == syscall_name:
                    return callback(zelos, sysname, args, retval)

            return self._add_zelos_hook(
                syscall_hook_type, syscall_callback_wrapper, name
            )
        return self._add_zelos_hook(syscall_hook_type, callback, name)

    def setup_func_hooks(self):
        """
        This function must be called before function hooks are enabled.
        It can only be called once the addresses of the imported
        functions are known.
        """
        self._func_hooks_enabled = True
        for registration_callback in self._func_hooks_to_register:
            registration_callback()
        self._func_hooks_to_register = None

    def on_entrypoint(self, callback):
        """
        Run callback when the binary has reached it's entrypoint for
        the first time.
        """

        def register_on_entrypoint_hook():
            entrypoint = self._rebase_target_module_addr(
                self.z.main_module._target_entrypoint
            )

            def exec_callback_wrapper(*args):
                self.logger.info(f"Reached entrypoint 0x{entrypoint:x}")
                callback()

            self.register_exec_hook(
                HookType.EXEC.BLOCK,
                exec_callback_wrapper,
                ip_low=entrypoint,
                ip_high=entrypoint,
                name="on_entrypoint",
                end_condition=lambda: True,
            )

        self.on_main_module_load(register_on_entrypoint_hook)

    def on_main_module_load(self, callback):
        """
        Run callback when the first part of the target module has been
        loaded into memory.
        """
        base_address = self.z.memory.get_module_base(self.z.target_binary_path)
        if base_address is not None:
            callback()
            return

        # Wait for the main module to be loaded before setting up the
        # function hooks
        def main_module_is_loaded():
            base_address = self.z.memory.get_module_base(
                self.z.target_binary_path
            )
            return base_address is not None

        def delayed_func_hook_setup(zelos, access, address, size, data):
            if main_module_is_loaded():
                callback()

        self.register_mem_hook(
            HookType.MEMORY.INTERNAL_MAP,
            delayed_func_hook_setup,
            name="on_main_module_load",
            end_condition=main_module_is_loaded,
        )

    def _rebase_target_module_addr(self, addr: int):
        """
        Takes an address with the target binary's image base and
        rebases it to the address that it was actually loaded at.
        """
        return (
            addr
            - self.z.main_module._target_imagebase
            + self.z.memory.get_module_base(self.z.target_binary_path)
        )

    def register_func_hook(
        self,
        func_name: str,
        callback: Callable[["Zelos"], Any],
        end_condition=None,
    ) -> HookInfo:
        """
        Registers a hook that should execute when an imported function
        is called.

        There are multiple assumptions embedded in this hook.
        We assume that the pointers to the imported functions will be
        set at the time the entrypoint is reached. There are certain
        protections that can be put in place that will get around this,
        and we may have to update how function hooks are registered for
        those binaries.
        """
        address_ptr = self.z.main_module._elf_dynamic_import_addrs.get(
            func_name, None
        )
        if address_ptr is None:
            return None

        if not self._func_hooks_enabled:
            registration_callback = functools.partial(
                self.register_func_hook,
                func_name,
                callback,
                end_condition=end_condition,
            )
            self._func_hooks_to_register.append(registration_callback)
            return

        address_ptr = self._rebase_target_module_addr(address_ptr)

        func_addr = self.z.memory.read_int(address_ptr)

        def read_wrapper(z, address, size):
            callback(z)

        return self.register_exec_hook(
            HookType.EXEC.BLOCK,
            read_wrapper,
            ip_low=func_addr,
            ip_high=func_addr,
            name=f"func_{func_name}",
            end_condition=end_condition,
        )

    def register_exception_hook(self, callback, name=None) -> HookInfo:
        self.z.exception_handler.register_exception_handler(callback)
        return HookInfo(HookType._OTHER.EXCEPTION, callback, None, name)

    def register_zml_hook(
        self, zml_string: str, closure: Callable[[], Any], name=None
    ) -> HookInfo:
        """
        Registers a hook that is triggered when a zml string is
        satisfied.
        """
        return self.z.zml_parser.trigger_on_zml(closure, zml_string)

    def register_close_hook(
        self, closure: Callable[[], Any], name=None
    ) -> HookInfo:
        """
        Registers a closure that is called before Zelos benignly exits.
        If Zelos does not exist cleanly, there is no guarantee that
        hooks registered here will be called.

        Args:
            closure: Called before Zelos exits.
        """
        return self._add_zelos_hook(HookType._OTHER.CLOSE, closure, name)

    def delete_hook(self, hook_info: HookInfo) -> None:
        """
        Deletes a hook. Keep in mind that deletion is slightly delayed.
        If you delete a hook before it has run on the current address,
        the hook will still run.

        Args:
            hook_info:
        """
        if self.z.emu.is_running:
            closure = functools.partial(self.delete_hook, hook_info)
            self._stop_to_delete_hook(closure)
            return

        if self._is_zebracorn_hook(hook_info.type):
            self._delete_zebracorn_hook(hook_info.handle)
        else:
            try:
                del self._hooks[hook_info.type][hook_info.handle]
            except KeyError:
                self.logger.warning(
                    f"Hook handle {hook_info.handle} does not exist for"
                    f"hook type {hook_info.type}"
                )

    def _stop_to_delete_hook(self, closure):
        self._to_delete_closures.append(closure)
        self.z.scheduler.stop_and_exec("delete hook", lambda: True)

    def _clear_deleted_hooks(self):
        """
        Removes hooks that were deleted while running zelos.
        """
        if self.z.emu.is_running:
            self.logger.critical(
                "Attempting to clear hooks while zebracorn is running. "
                "You might have a bad time."
            )
        for closure in self._to_delete_closures:
            closure()
        self._to_delete_closures.clear()

    def _delete_zebracorn_hook(self, handle):
        """
        Deleting zebracorn hooks can cause issues if done while zebracorn
        is running. To get around this, we should register the deletions
        and then stop zebracorn to trigger them.
        """
        if self.z.emu.is_running:
            closure = functools.partial(self._delete_zebracorn_hook, handle)
            self._stop_to_delete_hook(closure)
            return
        del self._cross_process_hooks[handle]
        for p in self.z.processes.process_list:
            p.hooks._delete_zebracorn_hook(handle)

    def _is_zebracorn_hook(self, hook_type):
        if isinstance(hook_type, HookType.MEMORY):
            if self.is_internal_mem_hook(hook_type):
                return False
            return True

        if isinstance(hook_type, HookType.EXEC) or hook_type in [
            HookType._OTHER.INTERRUPT
        ]:
            return True

        if isinstance(
            hook_type, (HookType.PROCESS, HookType.THREAD, HookType.SYSCALL)
        ) or hook_type in [HookType._OTHER.CLOSE]:
            return False
        raise Exception(
            f"Unsure whether {hook_type} is a type of zebracorn hook."
        )
        return False

    def _add_zelos_hook(self, hook_type, callback, name=None) -> HookInfo:
        hook_info = HookInfo(hook_type, callback, self._hook_index, name=name)
        self._hooks[hook_type][self._hook_index] = callback
        self._hook_index += 1
        return hook_info

    def _wrap_callback(self, name, callback, handle, end_condition):
        """
        Incorporates the self deletion triggered by the end_condition
        into the callback.
        """
        # TODO(v): Make this function generic so non-zebracorn hooks can
        # also have an end condition argument.
        done = False

        def wrapper(*args):
            nonlocal done
            if done:
                self.logger.error(f"Attempted to run deleted hook {name}.")
                return
            try:
                callback(*args)
                if end_condition():
                    done = True
                    self._delete_zebracorn_hook(handle)
            except Exception:
                self.logger.exception(
                    f"Hook {name} failed to execute. Deleting now"
                )
                done = True
                self._delete_zebracorn_hook(handle)

        return wrapper

    def _add_zebracorn_hook(
        self,
        hook_type,
        callback,
        name=None,
        start_addr=None,
        end_addr=None,
        end_condition=None,
    ) -> HookInfo:
        """
        A cross process hook must accept a process as the first
        argument, followed by the arguments expected by a zebracorn hook
        of the given hook_type.
        """
        handle = self._hook_index
        self._hook_index += 1
        if end_condition is None:
            wrapped_callback = callback
        else:
            name = f"{name}_{start_addr}"
            wrapped_callback = self._wrap_callback(
                name, callback, handle, end_condition
            )

        if hasattr(self.z, "processes"):
            for p in self.z.processes.process_list:
                p.hooks.add_hook(
                    hook_type,
                    wrapped_callback,
                    handle,
                    name,
                    start_addr=start_addr,
                    end_addr=end_addr,
                )

        self._cross_process_hooks[handle] = HookInfo(
            hook_type,
            wrapped_callback,
            handle,
            name,
            start_addr,
            end_addr,
            end_condition,
        )

        return self._cross_process_hooks[handle]

    def is_internal_mem_hook(self, hook_type):
        return hook_type in [
            HookType.MEMORY.INTERNAL_READ,
            HookType.MEMORY.INTERNAL_WRITE,
            HookType.MEMORY.INTERNAL_MAP,
        ]

    def _get_hooks(self, hook_type):
        if (
            self.is_internal_mem_hook(hook_type)
            and not self._internal_mem_hooks_enabled
        ):
            return []
        # Hooks might delete themselves, can't iterate over the values
        # if they are editing the underlying dictionary.
        return list(self._hooks[hook_type].values())

    def _enable_internal_memory_hooks(self):
        self._internal_mem_hooks_enabled = True


class Hooks:
    """ Keeps track of the hooks that are in action."""

    def __init__(self, emu, scheduler):
        self.emu = emu
        self.scheduler = scheduler
        self.logger = logging.getLogger(__name__)

        # Used for hooks that will be active until a user deactivates.
        self._hook_dict = {}
        self.unnamed_hook_index = 1
        self.emu.hook_add(
            uc.UC_HOOK_MEM_READ_UNMAPPED | uc.UC_HOOK_MEM_WRITE_UNMAPPED,
            self.hook_mem_invalid,
        )

        # List of closures to run to delete hooks
        self._cleanup_closures = []

        # callback for tracing invalid memory access (READ or WRITE)

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        eip = self.emu.getIP()
        print(
            "Missing memory at 0x%x, IP = 0x%x data size = %u, "
            "data value = 0x%x" % (address, eip, size, value)
        )
        return False  # Returning False allows other hooks to execute.

    def add_hook(
        self,
        zelos_hook_type,
        callback,
        handle,
        name=None,
        start_addr=None,
        end_addr=None,
    ) -> None:
        """
        Adds a hook to zebracorn. Depending on the hook type, the callback
        is triggered at different moments, such as on ever instruction
        or every basic block. In addition, if you specify an address
        region, the hook will only run on those addresses. Restricting
        the addresses that a hook can trigger can result in considerable
        speedups.
        """
        if self.emu.is_running:
            add_hook_callback = functools.partial(
                self.add_hook,
                zelos_hook_type,
                callback,
                handle,
                name=name,
                start_addr=start_addr,
                end_addr=end_addr,
            )
            self.scheduler.stop_and_exec("add_hook", add_hook_callback)
            return
        if isinstance(zelos_hook_type, HookType._INST):
            zebracorn_hook_type = uc.UC_HOOK_INSN
            arg1 = _zelos_hook_to_zebracorn(zelos_hook_type)
        else:
            zebracorn_hook_type = _zelos_hook_to_zebracorn(zelos_hook_type)
            arg1 = 0

        try:
            if start_addr is not None:
                zebracorn_handle = self.emu.hook_add(
                    zebracorn_hook_type,
                    callback,
                    begin=start_addr,
                    end=end_addr,
                    arg1=arg1,
                )
            else:
                zebracorn_handle = self.emu.hook_add(
                    zebracorn_hook_type, callback, arg1=arg1
                )

        except uc.UcError:
            raise ZelosRuntimeException(
                f"Issue adding hook {name}, "
                f"type {zelos_hook_type}, arg1 {arg1}"
            )

        self._hook_dict[handle] = zebracorn_handle

    def _delete_zebracorn_hook(self, zelos_handle):
        if self.emu.is_running:
            self.logger.critical(
                "Attempting to delete hooks while zebracorn is running. "
                "You might have a bad time."
            )
        zebracorn_handle = self._hook_dict[zelos_handle]
        self.emu.hook_del(zebracorn_handle)

    def del_hook(self, name):
        if name not in self._hook_dict:
            self.logger.notice("No hook with name %s" % name)
            return
        handle = self._hook_dict.pop(name)
        self._delete_zebracorn_hook(handle)

    def print_active_hooks(self):
        print("Permanent Hooks:")
        for name, handle in self._hook_dict.items():
            print(" {0}: {1}".format(name, handle))

    def _save_state(self):
        return self._hook_dict

    def _load_state(self, data):
        self._hook_dict = data


class InterruptHooks:
    """
    Manages hooks that handle interrupts emitted by the cpu emulator
    """

    def __init__(self, hook_manager, z):
        self.logger = logging.getLogger(__name__)
        self.hook_manager = hook_manager
        self._z = z

        # CPUID interrupt is 0xf0f0f0f0 (TODO)
        self.interrupt_handlers = {}
        self.generic_interrupt_handlers = []
        self.unhandled_interrupt_handlers = []

        self._interrupt_handler_hook_info = None
        self.enable()

    def __str__(self):
        s = "Registered Interrupt Handlers:\n"
        s += "\n".join(
            [f"  0x{k:x}: {v}" for k, v in self.interrupt_handlers.items()]
        )
        return s

    def enable(self) -> None:
        """Enables hooks for cpu interrupts across all processes."""

        def interrupt_hook_wrapper(uc, intno, userdata):
            self._hook_interrupt(self._z.api, intno)

        hook_info = self.hook_manager._add_zebracorn_hook(
            HookType._OTHER.INTERRUPT,
            interrupt_hook_wrapper,
            name="interrupt_hook",
        )
        self._interrupt_handler_hook_info = hook_info

    def disable(self) -> None:
        """Disable hooks for cpu interrupts across all processes."""
        if self._interrupt_handler_hook_info is not None:
            self.hook_manager.delete_hook(self._interrupt_handler_hook_info)
        self._interrupt_handler_hook_info = None

    def register_interrupt_handler(self, interrupt_number, handler):
        self.interrupt_handlers[interrupt_number] = handler

    def register_generic_interrupt_handler(self, handler):
        self.generic_interrupt_handlers.append(handler)

    def register_unhandled_interrupt_handler(self, handler):
        self.unhandled_interrupt_handlers.append(handler)

    def _hook_interrupt(self, zelos, intno):
        if zelos.thread is None:
            zelos.internal_engine.scheduler.stop_and_exec(
                "interrupt_null_thread", lambda: True
            )
            return

        self.logger.spam(
            f"Got interrupt 0x{intno:x} on thread {zelos.thread.name}"
        )

        handler = self.interrupt_handlers.get(intno, None)

        interrupt_handled = False
        if handler is not None:
            handler(zelos.process)
            interrupt_handled = True
        for handler in self.generic_interrupt_handlers:
            if handler(intno, zelos.process):
                interrupt_handled = True
        if not interrupt_handled:
            for handler in self.unhandled_interrupt_handlers:
                handler(intno, zelos.process)


class ExceptionHooks:
    def __init__(self, z):
        self.z = z
        self.logger = logging.getLogger(__name__)
        self.handler = None

    def handle_exception(self, e):
        if self.handler is None:
            self.logger.notice("No exception handler registered")
            self.z.scheduler.stop(f"Unhandled exception")
            return
        self.logger.debug(
            f"Invoking Exception Handler: {e} "
            f"EIP = 0x{self.z.current_thread.getIP():x}"
        )
        self.handler(self.z.current_process, e)

    def register_exception_handler(self, callback):
        self.handler = callback
