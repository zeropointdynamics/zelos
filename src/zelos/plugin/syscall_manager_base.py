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
import ctypes
import logging
import sys

from typing import Dict, List

from termcolor import colored

from zelos.hooks import HookType


def ptr2struct(z, addr, struct_class):
    """
    Returns an instance of struct_class read starting from addr
    """
    data = z.memory.read(addr, ctypes.sizeof(struct_class))
    instance = struct_class()
    str2struct(instance, bytes(data))
    return instance


def get_pchar_array(z, addr, size=-1):
    """
    Reads a set of string pointers starting at addr up to the first null
    pointer (with a max of size, if specified)
    Returns a list of null-terminated strings read from those pointers.
    """
    result = []
    i = 0
    while i != size:
        pstr = z.memory.read_int(addr + i * 4)
        if pstr == 0:
            break
        result.append(z.memory.read_string(pstr))
        i += 1
    return result


def str2struct(struct_obj, data):
    fit = min(len(data), ctypes.sizeof(struct_obj))
    ctypes.memmove(ctypes.addressof(struct_obj), data, fit)


class SyscallManager(object):
    def __init__(self, engine):
        self.logger = logging.getLogger(__name__)
        self.z = engine

        self.strace_file = sys.stdout

        self.breakpoints = set()

        # Reference to the last Args() created from get_args(). Used to
        # provide argument information for syscall breakpoints.
        self.last_syscall_args = None
        self.last_retval = 0

        # If this is set, engine will set the IP value after breaking
        # execution. This is needed to avoid an issue in Unicorn wherein
        # emu_stop() fails to stop if IP is changed from within a hook.
        self.pending_ip_change = None

        self.syscall_break_name = None

    @property
    def emu(self):
        return self.z.current_process.emu

    def set_breakpoint(self, syscall_name):
        self.breakpoints.add(syscall_name)

    def remove_breakpoint(self, syscall_name):
        self.breakpoints.remove(syscall_name)

    def get_last_syscall_args(self):
        """ Gets the last set of Args() parsed by get_args """
        return self.last_syscall_args

    def get_last_retval(self):
        """ Gets the last retval return by a syscall """
        return self.last_retval

    def get_retval_register(self):
        """ Gets the register name used for syscall return values """
        return self._REG_RETURN

    def _handle_syscall_break(self, syscall_name):
        # Check if a breakpoint was requested for this syscall name. If
        # so, use the `break_exception` to exit the run-loop
        # post-syscall. Save a reference to the syscall name that caused
        # the break. Note that syscall breaks stop execution *after*
        # zemu has already run the simulated syscall, cleaned up the
        # stack (if needed), and set PC to the return address.
        self.syscall_break_name = None
        if syscall_name in self.breakpoints:
            self.logger.warning(f"BREAKPOINT ON SYSCALL '{syscall_name}'")
            self.syscall_break_name = syscall_name
            self.z.scheduler.stop("syscall breakpoint")

    def generate_break_state(self):
        if self.syscall_break_name is None:
            syscall = None
        else:
            if self.pending_ip_change is not None:
                self.z.current_thread.setIP(self.pending_ip_change)
                self.pending_ip_change = None
            syscall = {
                "name": self.syscall_break_name,
                "args": self.get_last_syscall_args().to_dict_list(),
                "retval": self.get_last_retval(),
                "retval_register": self.get_retval_register(),
            }
            self.syscall_break_name = None

        return {
            "pc": self.z.current_thread.getIP(),
            "syscall": syscall,
            "bits": self.z.state.bits,
        }

    def set_strace_file(self, filename):
        self.strace_file = self.z.files.unsafe_open(filename, "w")

    def print(self, string, max_len=1000):
        """
        Used to print additional debug information within a syscall.
        Will not appear in the strace.
        """
        if not self.z.trace.should_print_thread():
            return
        if len(string) > max_len:
            string = str(string[:max_len]) + "..."

        print(string)

    def print_info(self, string):
        """Used to print auxiliary information to the strace file"""
        if not self.z.trace.should_print_thread():
            return
        if self.strace_file is sys.stdout:
            s = (
                colored(f"[{self.z.current_thread.name}]", "magenta")
                + " "
                + colored(f"[INFO]", "white")
                + f" {string}"
            )
        else:
            s = f"[{self.z.current_thread.name}] " + f"[INFO] {string}"
        print(s, file=self.strace_file, flush=True)

    def print_syscall(self, thread, syscall_name, args, retval):
        """
        Prints information regarding a syscall for the strace.
        Note, this may not immediately print the syscall (may need to
        wait for return value
        """
        self.z.triggers.tr_syscall(thread, syscall_name, args, "Unknown")

        if not self.z.trace.should_print_thread(thread):
            return

        retstr = "void" if retval is None else f"{retval:x}"

        if args is None:
            self.z.logger.warning("Syscall did not call get_args")

        if self.strace_file is sys.stdout:
            s = (
                colored(f"[{thread.name}]", "magenta")
                + " "
                + colored(f"[SYSCALL]", "red")
                + " "
                + colored(f"{syscall_name}", "white", attrs=["bold"])
                + f" ( {args} ) -> {retstr}"
            )
        else:
            ip = thread.getIP()
            s = (
                f"[{thread.name}] "
                f"[0x{ip:x}] {syscall_name} ( {args} ) -> {retstr}"
            )

        print(s, file=self.strace_file, flush=True)

    def handle_syscall(self, process):
        """
        Calls the corresponding syscall with given name or number in the
        context of the given process
        """
        sys_num = self.get_syscall_number()
        sys_name = self.find_syscall_name_by_number(sys_num)
        self.z.triggers.tr_call_syscall(sys_name)
        self.logger.spam(f"Executing syscall {sys_name}")
        sys_fn = self.find_syscall(sys_name)
        try:
            # The current thread might get modified by the syscall.
            thread = self.z.current_thread
            self.last_syscall_args = None
            retval = sys_fn(self, process)
            if retval is not None:
                self.set_return_value(retval)
            self.print_syscall(
                thread, sys_name, self.last_syscall_args, retval
            )
        except Exception as e:
            self.logger.error(f"Error happened inside syscall {sys_name}")
            self.print_syscall(thread, sys_name, self.last_syscall_args, None)
            raise e

        hooks = self.z.hook_manager._get_hooks(HookType.SYSCALL.AFTER)
        for hook in hooks:
            hook(self.z.api, sys_name, self.last_syscall_args, retval)

        self.last_retval = retval
        self._handle_syscall_break(sys_name)
        return True

    def pause_syscall(self, process, condition=None):
        """
        Defines what happens when the pause syscall exception is
        received.
        """
        process.threads.pause_current_thread(condition=condition)
        return

    def register_overrides(self, override_dict: Dict[str, List[int]]):
        """
        Overrides return value behavior in the syscall manager.
        """
        for sys_name, overrides in override_dict.items():
            sys_func = self._name2syscall_func[sys_name]

            def sys_func_wrapper(sm, p):
                retval = sys_func(sm, p)
                if len(overrides) > 0:
                    self.logger.info("Invoking sysfunc return override")
                    return overrides.pop(0)
                return retval

            self._name2syscall_func[sys_name] = sys_func_wrapper

    def find_syscall_name_by_number(self, n):
        """
        Finds and returns syscall name by syscall number.
        """
        if n in self.rev_map:
            sys_name = self.rev_map[n]
            return sys_name
        else:
            self.logger.error(
                f"[!] [0x{self.z.current_thread.getIP():x}] "
                f"Could not find syscall name by number: [{n} 0x{n:x}]"
            )
            return "Unknown"

    def find_syscall(self, sys_name):
        """
        Finds and returns syscall implementation by syscall number.
        """
        sys_fn = self._name2syscall_func.get(sys_name, self.nullsub)

        if sys_fn == self.nullsub:
            self.logger.warning(
                "[*] Using nullsub for syscall [{0}]...".format(sys_name)
            )
        return sys_fn

    def add_custom_syscall(self, sys_num, sys_name, sys_func):
        if sys_name in self.call_map:
            self.logger.warning(
                "[!] syscall number [{0}] already exists. "
                "overwriting...".format(sys_num)
            )
        if sys_num in self.rev_map:
            self.logger.warning(
                "[!] syscall name [{0}] already exists. "
                "overwriting...".format(sys_name)
            )
        self.call_map[sys_name] = sys_num
        self.rev_map[sys_num] = sys_name
        self._name2syscall_func[sys_name] = sys_func

    def return_addr(self):
        raise NotImplementedError()

    def nullsub(self, sm, p):
        return

    def fixme(self, msg):
        self.print(f"[FIXME] {msg}")

    ##########################################
    # ARCHITECTURE SPECIFIC MEMBER VARIABLES #
    ##########################################

    # @@TODO handle cases where we use 2 return registers
    # @@TODO handle argument loading from the stack

    _REG_NUMBER = ""
    _REG_ARGS = []
    _REG_RETURN = ""
    _REG_RETURN_2 = ""  # pipe(2)
    _REG_IP = ""
    _REG_SP = ""

    def get_syscall_number(self):
        raise NotImplementedError()

    def set_return_value(self, value):
        raise NotImplementedError()
