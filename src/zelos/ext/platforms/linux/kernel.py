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
import inspect

from collections import defaultdict
from typing import Callable, Dict, Optional

from termcolor import colored

from zelos import HookType
from zelos.exceptions import ZelosException
from zelos.plugin import ArgFactory, IKernel

from .syscalls import syscall_utils as sys_utils
from .syscalls.arg_strings import get_arg_string


def construct_kernel(arch, z):
    kernel_class = {
        "x86": X86Kernel,
        "x86_64": X86_64Kernel,
        "arm": ARMKernel,
        "mips": MIPSKernel,
    }.get(arch, None)

    if kernel_class is None:
        return None
    return kernel_class(z)


class LinuxKernel(IKernel):
    def __init__(self, arch, engine):
        super(LinuxKernel, self).__init__(engine)
        self.arch = arch
        self.call_map = self.__load_linux_syscall_maps(arch)
        self._name2syscall_func = self._load_linux_syscall_funcs()
        self.rev_map = {v: k for k, v in self.call_map.items()}

        self.arg_factory = ArgFactory(
            functools.partial(get_arg_string, self.z)
        )

        self.socketcall_dict = {
            1: "socket",
            2: "bind",
            3: "connect",
            4: "listen",
            5: "accept",
            6: "getsockname",
            7: "getpeername",
            8: "socketpair",
            9: "send",
            10: "recv",
            11: "sendto",
            12: "recvfrom",
            13: "shutdown",
            14: "setsockopt",
            15: "getsockopt",
            16: "sendmsg",
            17: "recvmsg",
            18: "accept4",
            19: "recvmmsg",
            20: "sendmmsg",
        }

        # These are processes that are exited, and so a parent process
        # can wait on them.
        # parent_pid -> child_pid
        self.child_state_changes = defaultdict(list)

    def _load_linux_syscall_funcs(
        self,
    ) -> Dict[str, Callable[[any], Optional[int]]]:
        """
        Returns map of name -> syscall implementation.
        """
        from .syscalls import syscalls as linux_syscall_module

        linux_syscalls = inspect.getmembers(
            linux_syscall_module, inspect.isfunction
        )

        return {
            name.partition("sys_")[-1]: func
            for name, func in linux_syscalls
            if name.startswith("sys_")
        }

    def __load_linux_syscall_maps(self, arch):
        """
        Loads the list of supported syscalls from the syscalls table.
        """
        from .syscalls.syscalls_table import cols, table

        try:
            i = cols.index(arch)
        except ValueError:
            raise ZelosException(f"Invalid architecture '{arch}'")

        return {k: v[i] for (k, v) in table.items() if v[i] != -1}

    def handle_syscall(self, process):
        """
        Additionally translate `socketcall` syscalls to their target
        socket system call, e.g. `recv`, for the purpose of syscall
        breaks. This ensures that breakpoints for `recv` will be
        triggered both for `recv` and `socketcall` syscalls that invoke
        `recv`, etc.
        """
        sys_num = self.get_syscall_number()
        sys_name = self.find_syscall_name_by_number(sys_num)
        if sys_name == "socketcall":
            socketcall_args = self.get_last_syscall_args()
            args = self.get_args(
                [("int", "call"), ("unsigned long *", "callargs")],
                sys_num=sys_num,
            )
        status = super(LinuxKernel, self).handle_syscall(process)
        if sys_name == "socketcall":
            socketcall = self.socketcall_dict.get(args.call, None)
            if socketcall is not None:
                self.last_syscall_args = socketcall_args
                self._handle_syscall_break(socketcall)
        return status

    def set_errno(self, val):
        pass

    def _get_socketcall_args(
        self, process, func_name, args_addr, arg_list, arg_string_overrides={}
    ):
        # If calling these syscalls directly, get_args the old
        # fashioned way.
        if args_addr < 0:
            return self.get_args(arg_list, arg_string_overrides)

        arg_vals = [
            process.memory.read_int(args_addr + i * 4)
            for i in range(len(arg_list))
        ]
        args = self.arg_factory.gen_args(
            arg_list, arg_vals, arg_string_overrides=arg_string_overrides
        )
        self.last_syscall_args = args
        self._print_socket_syscall(func_name, args)
        return args

    def _print_socket_syscall(self, func_name, args):
        s = colored(f"{func_name}", "white", attrs=["bold"]) + f" ( {args} )"
        self.z.plugins.trace.print("SOCKET SYSCALL", s)

    ####################
    # HELPER FUNCTIONS #
    ####################

    def get_args(self, arg_list, arg_string_overrides={}, sys_num=None):
        """
        Gets arguments according to linux syscall calling convention
        """
        z = self.z
        if sys_num is None:
            sys_num = self.get_syscall_number()
        reg_list = self._REG_ARGS

        arg_regs = reg_list[: len(arg_list)]

        arg_vals = [z.current_thread.get_reg(arg) for arg in arg_regs]

        # Get the rest of the arguments off of the stack
        i = len(arg_vals)
        while len(arg_vals) < len(arg_list):
            arg_vals.append(self.emu.getstack(i))
            i += 1
        args = self.arg_factory.gen_args(
            arg_list, arg_vals, arg_string_overrides=arg_string_overrides
        )
        self.last_syscall_args = args
        return args


class X86Kernel(LinuxKernel):
    def __init__(self, engine):
        super(X86Kernel, self).__init__("x86", engine)

        def syscall_handler_wrapper(current_process, *args, **kwargs):
            self.handle_syscall(current_process)

        engine.interrupt_handler.register_interrupt_handler(
            0x80, syscall_handler_wrapper
        )

    _REG_NUMBER = "eax"
    _REG_ARGS = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
    _REG_RETURN = "eax"
    _REG_RETURN_2 = "edx"

    def get_syscall_number(self):
        return self.emu.get_reg("eax")

    def set_return_value(self, value):
        self.emu.set_reg("eax", value)

    def return_addr(self):
        return self.emu.getIP()


class X86_64Kernel(LinuxKernel):
    def __init__(self, engine):
        super(X86_64Kernel, self).__init__("x86_64", engine)

        def handle_syscall_callback(zelos):
            current_process = engine.current_process
            """
            We need to execute a syscall at this point, however,
            certain syscalls may not be runnable within a hook (they
            cause zebracorn to execute code which is not allowed in a
            hook)
            """
            handle_syscall_closure = functools.partial(
                self.handle_syscall, current_process
            )
            current_process.scheduler.stop_and_exec(
                "handle syscall", handle_syscall_closure
            )
            return True

        # Syscalls are made using the syscall instruction. Unicorn does
        # not catch these by default though.
        engine.hook_manager.register_inst_type_hook(
            HookType._INST.X86_SYSCALL,
            handle_syscall_callback,
            name="x64_syscall_hook",
        )

    _REG_NUMBER = "rax"
    _REG_ARGS = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
    _REG_RETURN = "rax"
    _REG_RETURN_2 = "rdx"

    def get_syscall_number(self):
        return self.emu.get_reg("rax")

    def handle_syscall(self, *args, **kwargs):
        t = self.z.current_thread
        addr = t.getIP()
        super().handle_syscall(*args, **kwargs)

        if addr == t.getIP():

            def set_ip():
                t.setIP(addr + 2)

            self.z.scheduler.stop_and_exec("handle_syscall", set_ip)

    def set_return_value(self, value):
        self.emu.set_reg("rax", value)

    def set_errno(self, val: int):
        fs_base = sys_utils.get_fs(self.z.current_process)
        errno_location = fs_base - 0x80
        self.z.memory.write_int(errno_location, val)

    def return_addr(self):
        return self.emu.getIP() + 2

    def pause_syscall(self, process, condition=None):
        """
        Defines what happens when the pause syscall exception is
        received
        """
        super().pause_syscall(process, condition=condition)
        return


class ARMKernel(LinuxKernel):
    def __init__(self, engine):
        super(ARMKernel, self).__init__("arm", engine)

        def syscall_handler_wrapper(current_process, *args, **kwargs):
            self.handle_syscall(current_process)

        engine.hook_manager.register_interrupt_hook(
            syscall_handler_wrapper, intno=0x2
        )

    _REG_NUMBER = "r7"
    _REG_ARGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6"]
    _REG_RETURN = "r0"
    _REG_RETURN_2 = "r1"

    def get_syscall_number(self):
        # Some syscalls are passed through svc, and these seem to be the
        # "old abi" (https://w3challs.com/syscalls/?arch=arm_strong)
        # Discussion on difference between oldabi and eabi:
        #   https://lists.gnu.org/archive/html/qemu-devel/2009-01/msg01512.html
        # More discussion:
        #   https://www.raspberrypi.org/forums/viewtopic.php?t=158915
        svc_inst = self.z.disas(self.z.current_thread.getIP() - 4, 4)[0]
        if svc_inst.insn_name() == "svc":
            svc_val = svc_inst.operands[0].imm
            if svc_val != 0:
                return svc_val - 0x900000
        else:
            self.logger.notice(
                f"Why was there an exception here if the last instruction "
                f"wasn't a syscall {self.z.current_thread.getIP():x}"
            )
        val = self.emu.get_reg("r7")
        return val

    def set_return_value(self, value):
        self.emu.set_reg("r0", value)

    def return_addr(self):
        # (V) we had this as ip+4 initially, but found that to be wrong.
        # Double check that this is consistently correct.
        return self.emu.getIP()

    # arch/arm/kernel/entry-armv.S:
    # __kuser_get_tls: @ 0xffff0fe0
    # #if !defined(CONFIG_HAS_TLS_REG) && !defined(CONFIG_TLS_REG_EMUL)
    #     ldr r0, [pc, #(16 - 8)] @ TLS stored at 0xffff0ff0
    # #else
    #     mrc p15, 0, r0, c13, c0, 3 @ read TLS register
    # #endif
    #     usr_ret lr

    def _kuser_get_tls(self):
        self.logger.info("Called kuser_get_tls")
        tls = self.emu.get_reg("c13_c0_3")
        self.set_return_value(tls)
        self.emu.setIP(self.emu.get_reg("lr"))

    def _kuser_cmpxchg(self):
        self.logger.info("Called kuser_cmpxchg")
        oldval = self.emu.get_reg("r0")
        newval = self.emu.get_reg("r1")
        ptr = self.emu.get_reg("r2")

        d_ptr = self.z.memory.read_int(ptr)

        if d_ptr != oldval:
            CPSR_CF_CLEAR = self.emu.get_reg("cpsr") & 0xDFFFFFFF  # CPSR[29]
            self.emu.set_reg("cpsr", CPSR_CF_CLEAR)
            self.emu.setIP(self.emu.get_reg("lr"))
            self.set_return_value(1)
        else:
            self.z.memory.write_int(ptr, newval)
            CPSR_CF_SET = self.emu.get_reg("cpsr") | 0x20000000  # CPSR[29]
            self.emu.set_reg("cpsr", CPSR_CF_SET)
            self.emu.setIP(self.emu.get_reg("lr"))
            self.set_return_value(0)

    def _kuser_memory_barrier(self):
        self.logger.info("Called kuser_memory_barrier")
        self.emu.setIP(self.emu.get_reg("lr"))

    def _kuser_cmpxchg64(self):
        self.logger.notice("Reached kuser_cmpxchg64, needs to be implemented")
        self.emu.setIP(self.emu.get_reg("lr"))


class MIPSKernel(LinuxKernel):
    def __init__(self, engine):
        super(MIPSKernel, self).__init__("mips", engine)

        def syscall_handler_wrapper(current_process, *args, **kwargs):
            self.handle_syscall(current_process)

        engine.hook_manager.register_interrupt_hook(
            syscall_handler_wrapper, intno=0x11
        )

    _REG_NUMBER = "v0"
    _REG_ARGS = ["a0", "a1", "a2", "a3"]
    _REG_RETURN = "v0"
    _REG_RETURN_2 = "v1"

    def handle_syscall(self, *args, **kwargs):
        super(MIPSKernel, self).handle_syscall(*args, **kwargs)

        # Mimicking qemu user behavior (specifically -1133)
        # github.com/qemu/qemu/blob/master/linux-user/mips/cpu_loop.c
        unsigned_neg1 = 2 ** (self.z.state.bytes * 8) - 1
        retval = self.get_return_value()
        if unsigned_neg1 >= retval >= (-1133 & unsigned_neg1):
            self.emu.set_reg("a3", 1)
            self.set_return_value(-retval)
        else:
            self.emu.set_reg("a3", 0)

        return True

    def get_syscall_number(self):
        return self.emu.get_reg("v0")

    def set_return_value(self, value):
        self.emu.set_reg("v0", value)

    def get_return_value(self):
        return self.emu.get_reg("v0")

    def return_addr(self):
        return self.emu.getIP()
