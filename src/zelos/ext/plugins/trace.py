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

import capstone.arm_const as cs_arm
import capstone.x86_const as cs_x86

from termcolor import colored
from unicorn import UC_ERR_READ_UNMAPPED, UcError

from zelos import HookType, IPlugin


class Trace(IPlugin):
    def __init__(self, z):
        self.zelos = z

        self.logger = logging.getLogger(__name__)

        self.current_return_address = 0
        self.current_function_name = "???"
        self.current_api_module = "???"

        # Comments (to be dumped)
        # We should save a lot of space by moving this to a grouping by
        # thread, rather than keeping the thread with each comment.
        # This will break compatibility with systems like Doppler.
        self.comments = []
        self.MAX_INDENTS = 40
        self.threads_to_print = set()
        if z.config.tracethread != "":
            self.threads_to_print.add(z.config.tracethread)

        self.verbosity = z.config.verbosity
        self.verbose = False
        self.set_verbose(self.verbosity > 0)
        self.fasttrace = True if z.config.fasttrace > 0 else False
        self.trace_on = ""
        self.trace_off = ""

        self.last_instruction = None
        self.last_instruction_size = None
        self.should_print_last_instruction = False

        if self.verbose:
            self.set_hook_granularity(HookType.EXEC.INST)

        if self.state.arch in ["x86", "x86_64"]:
            self.comment_generator = x86CommentGenerator(
                self.zelos, self.modules
            )
        elif self.state.arch == "arm":
            self.comment_generator = ArmCommentGenerator(
                self.zelos, self.modules
            )
        else:
            self.comment_generator = EmptyCommentGenerator()

        self.comment_hooks = []

    @property
    def cs(self):
        return self.zelos.internal_engine.cs

    @property
    def modules(self):
        return self.zelos.internal_engine.modules

    @property
    def main_module(self):
        return self.zelos.internal_engine.main_module

    @property
    def state(self):
        return self.zelos.internal_engine.state

    @property
    def functions_called(self):
        return self.comment_generator.functions_called

    def get_region(self, addr):
        return self.zelos.internal_engine.memory.get_region(addr)

    def hook_comments(self, callback):
        """
        Registers a callback that is invoked when a comment is generated.

        Args:
            callback: The code that should be executed when a comment is
                generated. The function should accept the following inputs:
                (zelos, address, thread_id, text)

        Example:
             .. code-block:: python

                from zelos import Zelos

                # Keep track of the syscall return values
                comments = []
                def comment_hook(zelos, address, thread_id, text):
                    comments.append((address, thread_id, text))

                z = Zelos("binary_to_emulate")
                z.plugins.trace.hook_comments(comment_hook)
                z.start()
        """
        self.comment_hooks.append(callback)

    def hook_functions(self, callback):
        """
        Registers a callback that is invoked when a function is called.

        Args:
            callback: The code that should be executed when a comment is
                generated. The function should accept the following inputs:
                (zelos, address, thread_id, text)

        Example:
             .. code-block:: python

                from zelos import Zelos

                # Keep track of the syscall return values
                functions = []
                def function_hook(zelos, address, thread_id, text):
                    comments.append((address, thread_id, text))

                z = Zelos("binary_to_emulate")
                z.plugins.trace.hook_comments(comment_hook)
                z.start()
        """
        # TODO: hook functions called within the comment generator
        pass

    def set_hook_granularity(self, granularity: HookType.EXEC):
        """
        Sets the code hook granularity to be either every instruction
        or every block.
        """
        try:
            self.zelos.delete_hook(self.code_hook_info)
        except AttributeError:
            pass  # first time setting code_hook_info

        self.code_hook_info = self.zelos.hook_execution(
            granularity, self.hook_code, name="code_hook"
        )

    def _check_timeout(self):
        """
        Check if specified timeout has elapsed and stop execution.
        """
        if self.zelos.internal_engine.timer.is_timed_out():
            self.zelos.stop("timeout")

    def hook_code(self, zelos, address, size):
        """
        Hook that is executed for each instruction or block.
        """
        try:
            self._hook_code_impl(zelos, address, size)
            self._check_timeout()
        except Exception:
            if self.zelos.thread is not None:
                self.zelos.process.threads.kill_thread(self.zelos.thread.id)
            self.logger.exception("Stopping execution due to exception")

    def _hook_code_impl(self, zelos, address, size):
        # TCG Dump example usage:
        # self.emu.get_tcg(0, 0)
        if self.zelos.thread is None:
            self.zelos.stop("hook_code_null_thread")
            return

        self.zelos.thread.total_blocks_executed += 1
        rev_modules = self.modules.reverse_module_functions
        if (
            self.zelos.thread.total_blocks_executed % 1000 == 0
            and address not in rev_modules
        ):
            self.zelos.swap_thread("process swap")
            return

        if self.verbose:
            if self.should_print_last_instruction:
                self.bb(
                    self.last_instruction,
                    self.last_instruction_size,
                    full_trace=False,
                )
            self.should_print_last_instruction = True
            if (
                self.fasttrace
                and self.zelos.process.threads.block_seen_before(address)
            ):
                self.should_print_last_instruction = False

        self.zelos.process.threads.record_block(address)

        self.last_instruction = address
        self.last_instruction_size = size

    def traceoff(self, addr=None):
        """
        Disable verbose tracing. Optionally specify an address at which
        verbose tracing is disabled.
        """
        if addr is None:
            self.set_verbose(False)
        else:

            def hook_traceoff(zelos, address, size):
                self.set_verbose(False)

            self.zelos.hook_execution(
                HookType.EXEC.INST,
                hook_traceoff,
                name="traceoff_hook",
                ip_low=addr,
                ip_high=addr,
                end_condition=lambda: True,
            )

    def traceoff_syscall(self, syscall_name):
        """
        Disable verbose tracing after a specific system call has executed.
        """

        def hook_traceoff(zelos, sysname, args, retval):
            if sysname == syscall_name:
                zelos.plugins.trace.traceoff()

        self.zelos.hook_syscalls(HookType.SYSCALL.AFTER, hook_traceoff)

    def traceon(self, addr=None):
        """
        Enable verbose tracing. Optionally specify an address at which
        verbose tracing is enabled.
        """
        if addr is None:
            self.set_verbose(True)
        else:

            def hook_traceon(zelos, address, size):
                self.set_verbose(True)

            self.zelos.hook_execution(
                HookType.EXEC.INST,
                hook_traceon,
                name="traceon_hook",
                ip_low=addr,
                ip_high=addr,
                end_condition=lambda: True,
            )

    def traceon_syscall(self, syscall_name):
        """
        Enable verbose tracing after a specific system call has executed.
        """

        def hook_traceon(zelos, sysname, args, retval):
            if sysname == syscall_name:
                self.traceon()

        self.zelos.hook_syscalls(HookType.SYSCALL.AFTER, hook_traceon)

    def set_verbose(self, should_set_verbose) -> None:
        """
        Used to set the verbosity level, and change the hooks.
        This prevents two types of issues:

        1) Running block hooks when printing individual instructions
               This will cause the annotations that are printed to be
               the values at the end of the block's execution
        2) Running instruction hooks when not printing instructions
               This will slow down the emulation (sometimes
               considerably)
        """
        if self.verbose == should_set_verbose:
            return
        self.verbose = should_set_verbose

        if should_set_verbose:
            self.set_hook_granularity(HookType.EXEC.INST)
        else:
            self.set_hook_granularity(HookType.EXEC.BLOCK)

    def bb(self, address=None, size=20, full_trace=False):
        if not self.should_print_thread():
            return
        """ Prints instructions starting at the given address up to
        'size' bytes away. If no address is given, prints starting at
        the current address"""
        if address is None:
            address = self.zelos.regs.getIP()
        try:
            code = self.zelos.memory.read(address, size)
            insns = [insn for insn in self.cs.disasm(code, address)]
            if len(insns) == 0:
                return
            # For full trace, we'll just print the first instruction,
            # and then all the registers
            if full_trace:
                self.ins(insns[0])
                self.regs()
            else:
                for insn in insns:
                    self.ins(insn)
        except UcError as e:
            if e.errno == UC_ERR_READ_UNMAPPED:
                print("Unable to read instruction at address %x" % address)
            else:
                raise e

    def regs(self):
        """ Prints registers at the current address"""
        s = ""
        reg_list = self.zelos.internal_engine.emu.imp_regs
        for reg in reg_list:
            s += " ".join(
                [f"{reg}={self.zelos.internal_engine.emu.get_reg(reg):x}"]
            )
            s += "\n"
        print(s)

    # There are issues when this is used with autohooks. Need to see how
    # we can include this in the future. without endless indents
    def indent(self):
        self.zelos.thread._callstack_indent_count += 1

    def unindent(self):
        self.zelos.thread._callstack_indent_count -= 1

    def set_current_return_address(self, addr):
        self.current_return_address = addr

    def set_current_function_name(self, name):
        self.current_function_name = name

    def set_current_api_module(self, name):
        self.current_api_module = name

    def print(self, category, s, thread=None, addr_str=None):
        if thread is None:
            thread = self.zelos.thread.name
        if addr_str is None:
            addr_str = f"{self.zelos.regs.getIP():08x}"
        thread_str = colored(f"[{thread}]", "magenta")
        category_str = colored(f"[{category}]", "red")
        addr_str_str = colored(f"[{addr_str}]", "white", attrs=["bold"])
        print(f"{thread_str} {category_str} {addr_str_str} {s}")

    def log_api(self, args, isNative=False):
        self.api(args, isNative)

    def log_api_dbg(self, args):
        self.api_dbg(args)

    # Prints the thread, return address and api string
    def api(self, args, isNative=False):
        """ Prints an API that was called"""
        if not self.should_print_thread():
            return
        return_address = self.current_return_address
        indent_count = self.zelos.thread._callstack_indent_count
        try:
            caller_module = (
                self.get_region(return_address).module_name.split(".")[0]
                + "_____"
            )[:8]
        except Exception:
            caller_module = "________"
        native_s = ""
        if isNative:
            native_s = "[Native] "
        if indent_count == -1:
            indent_count = 0
        args = "".join([i if ord(i) < 128 else "." for i in args])
        s = (
            "  " * min(indent_count, self.MAX_INDENTS)
            + f"{native_s}{self.current_api_module}!{args}"
        )
        self.print("API", s, addr_str=f"{caller_module}:{return_address:08x}")

    # Prints the thread, return address and api string
    def api_dbg(self, args, isNative=False):
        """ Prints an API that was called"""
        if not self.should_print_thread():
            return
        return_address = self.current_return_address
        indent_count = self.zelos.thread._callstack_indent_count
        caller_module = (
            self.get_region(return_address).module_name.split(".")[0] + "_____"
        )[:8]
        if indent_count == -1:
            indent_count = 0
        args = "".join([i if ord(i) < 128 else "." for i in args])
        s = "  " * min(indent_count, self.MAX_INDENTS) + colored(
            args, "white", attrs=["bold"]
        )
        self.print("API", s, addr_str=f"{caller_module}:{return_address:08x}")

    def ins(self, insn):
        """ Prints the thread, address and instruction string """
        if not self.should_print_thread():
            return
        sep = ""
        if insn.address == self.zelos.regs.getIP():
            sep = "*"
        address = insn.address
        ins_string = self._get_insn_string(insn)
        if address in self.main_module.exported_functions:
            function_name = self.main_module.exported_functions[address]
            s = colored(f"<{function_name}>", "white", attrs=["bold"])
            self.print("INS", s, addr_str=f"{sep}{address:08x}")
        self.print("INS", ins_string, addr_str=f"{sep}{address:08x}")

    def should_print_thread(self, t=None):
        """
        Decides whether log statements should be printed for the given
        thread
        """
        # If the thread is known to be benign, let's ignore it. We can
        # add a config to print these if we need it.
        if t is None:
            t = self.zelos.thread
            if t is None:
                return False

        if t.benign_code is True:
            return False
        # The user can choose to print threads or to focus only on
        # specific threads.
        if len(self.threads_to_print) == 0:
            return True
        return t.name in self.threads_to_print

    def _get_insn_string(self, insn):
        """ Gets the string to be printed for an instruction."""
        cmt = ""
        try:
            cmt = self.comment_generator.get_comment(insn)
        except Exception as e:
            self.logger.notice(
                f"Issue printing {insn.mnemonic} instruction comment: {e}"
            )

        result = ""
        insn_str = "{0}\t{1}".format(insn.mnemonic, insn.op_str)
        if len(cmt) > 0:
            padding = ""
            padSize = 60 - len(insn_str)
            if padSize < 0:
                padSize = 1
            for y in range(0, padSize):
                padding += " "
            result += (
                insn_str
                + " "
                + padding
                + colored(" ; " + cmt, "grey", attrs=["bold"])
            )
            for fn in self.comment_hooks:
                try:
                    # invoke comment-hook callback
                    fn(self.zelos, insn.address, self.zelos.thread.id, cmt)
                except Exception:
                    from sys import exc_info

                    einfo = exc_info()
                    print(f"Exception in comment-hook callback: {einfo}")

        else:
            result += insn_str

        return result


class Comment:
    def __init__(self, address, thread_id, text):
        self.address = address
        self.thread_id = thread_id
        self.text = text


class EmptyCommentGenerator:
    def get_comment(self, insn):
        return ""


class ArmCommentGenerator:
    def __init__(self, zelos, modules):
        self.functions_called = {}
        self.zelos = zelos
        self._modules = modules

    def get_comment(self, insn):
        if insn.mnemonic[:3] in [
            "add",
            "sub",
            "mov",
            "mvn",
            "mul",
            "and",
            "orr",
        ]:
            return self._dst_comment(insn)
        if insn.mnemonic[:3] in ["cmp", "cmn", "tst", "teq"]:
            return self._cmp_comment(insn)
        if insn.mnemonic[:3] == "ldr":
            return self._ldr_comment(insn)
        if insn.mnemonic[:3] == "str":
            return self._str_comment(insn)
        if insn.mnemonic in ["b", "bl"]:
            return self._branch_comment(insn)
        if insn.mnemonic in ["push", "pop"]:
            return self._push_pop(insn)
        if insn.mnemonic == "svc":
            return self._svc_comment(insn)

        return "."

    def _push_pop(self, insn):
        """
        Returns all instructions that are pushed or popped
        """
        reg_vals = [
            f"{self._get_reg_or_mem_val(insn, i): x}" for i in insn.operands
        ]
        return f"[{','.join(reg_vals)}]"

    def _svc_comment(self, insn):
        """
        Returns the syscall name
        """
        sm = self.zelos.internal_engine.zos.syscall_manager
        if insn.insn_name() == "svc" and insn.operands[0].imm != 0:
            syscall_num = insn.operands[0].imm - 0x900000
        else:
            syscall_num = sm.get_syscall_number()
        syscall_name = sm.find_syscall_name_by_number(syscall_num)
        return f"{syscall_name}"

    def _dst_comment(self, insn):
        """
        Returns the destination register
        """
        dst_val = self._get_reg_or_mem_val(insn, insn.operands[0])
        return f"{insn.reg_name(insn.operands[0].value.reg)} = 0x{dst_val:x}"

    def _cmp_comment(self, insn):
        dst_val = self._get_reg_or_mem_val(insn, insn.operands[0])
        src_val = self._get_reg_or_mem_val(insn, insn.operands[1])
        return f"0x{dst_val:x} vs 0x{src_val:x}"

    def _ldr_comment(self, insn):
        """
        Returns a comment on loading a register from memory.
        """
        dst_val = self._get_reg_or_mem_val(insn, insn.operands[0])
        src_val = self._get_reg_or_mem_val(insn, insn.operands[1], is_dst=True)
        return f"{insn.reg_name(insn.operands[0].value.reg)} = "
        f"load(0x{src_val:x}) = 0x{dst_val:x}"

    def _str_comment(self, insn):
        """
        Returns a comment on storing a register in memory.
        """
        src_val = self._get_reg_or_mem_val(insn, insn.operands[0])
        dst_val = self._get_reg_or_mem_val(insn, insn.operands[1], is_dst=True)
        return f"store(0x{src_val:x}, 0x{dst_val:x})"

    def _branch_comment(self, insn):
        """
        Returns a comment on branch to label.
        """
        src_val = self._get_reg_or_mem_val(insn, insn.operands[0])
        if (
            src_val
            in self.zelos.internal_engine.main_module.exported_functions
        ):
            main_module = self.zelos.internal_engine.main_module
            func_name = main_module.exported_functions[src_val]
            return f"<{func_name:s}> (0x{src_val:x})"
        return f"<0x{src_val:x}>"

    def _get_reg_or_mem_val(self, insn, x, is_dst=False):
        """
        Gets the value of the operand, for memory addresses, gets
        the memory value at the location specified
        """
        if x.type == cs_arm.ARM_OP_REG:
            return self.zelos.internal_engine.emu.get_reg(
                insn.reg_name(x.value.reg)
            )
        elif x.type == cs_arm.ARM_OP_IMM:
            return x.imm
        else:
            base_val = (
                0
                if x.mem.base == 0
                else self.zelos.internal_engine.emu.get_reg(
                    insn.reg_name(x.mem.base)
                )
            )
            shift_val = (
                0
                if x.mem.index == 0
                else self.zelos.internal_engine.emu.get_reg(
                    insn.reg_name(x.mem.index)
                )
                * x.mem.scale
            )
            if is_dst:
                return base_val + shift_val + x.value.mem.disp
            else:
                return self.zelos.memory.read_int(
                    base_val + shift_val + x.value.mem.disp
                )


class x86CommentGenerator:
    def __init__(self, zelos, modules):
        self.zelos = zelos
        self._modules = modules
        self.functions_called = {}

    def _get_ptr_val_string(self, ptr: int) -> str:
        """Returns a string representing the data pointed to by 'ptr' if 'ptr'
        is a valid pointer. Otherwise, reutrns an empty string."""
        try:
            pointer_data = self.zelos.memory.read_int(ptr)
        except UcError as e:
            if e.errno == UC_ERR_READ_UNMAPPED:
                return ""
            raise e

        s = ""
        try:
            s = self.zelos.memory.read_string(ptr, 8)
        except UcError as e:
            if e.errno != UC_ERR_READ_UNMAPPED:
                raise e

        # Require a certain amount of valid characters to reduce false
        # positives for string identification.
        if len(s) > 2:
            return f' -> "{s}"'

        return f" -> {pointer_data:x}"

    def get_comment(self, insn):
        cmt = ""
        if insn.mnemonic == "call" or insn.mnemonic == "jmp":
            cmt = self._call_string(insn)
        elif insn.mnemonic == "push":
            cmt = self._push_string(insn)
        elif len(insn.operands) == 1:
            cmt = self._single_operand(insn)
        elif insn.mnemonic == "test" or insn.mnemonic == "cmp":
            cmt = self._test_or_cmp_string(insn)
        elif len(insn.operands) == 2:
            cmt = self._double_operand(insn)
        return cmt

    def _call_string(self, insn):
        # Only used when looking at the current instruction.
        # op = operands[0]
        # target = op.value.imm
        target = self.zelos.regs.getIP()
        self.functions_called[target] = True
        cmt = insn.mnemonic + "(0x{0:x}) ".format(target)
        if target in self._modules.reverse_module_functions:
            cmt += " " + self._modules.reverse_module_functions[target]
        return cmt

    def _push_string(self, insn):
        op = insn.operands[0]
        value = self._get_reg_or_mem_val(insn, op)
        ptr_val_str = self._get_ptr_val_string(value)
        return f"push(0x{value:x}){ptr_val_str}"

    def _single_operand(self, insn):
        op = insn.operands[0]
        # Just resolve any non-immediate values
        value = self._get_reg_or_mem_val(insn, op)
        ptr_val_string = self._get_ptr_val_string(value)
        if op.type == cs_x86.X86_OP_REG:
            reg_name = insn.reg_name(op.value.reg)
            s = f"{reg_name} = 0x{value:x}{ptr_val_string}"
        elif op.type == cs_x86.X86_OP_MEM:
            s = f"mem is (0x{value:x}){ptr_val_string}"
        else:
            return ""

        return s

    def _double_operand(self, insn):
        dst = insn.operands[0]
        dst_val = self._get_reg_or_mem_val(insn, dst, is_dst=True)
        if dst.type == cs_x86.X86_OP_REG:
            dst_name = insn.reg_name(dst.value.reg)
            ptr_val_string = self._get_ptr_val_string(dst_val)
            return f"{dst_name} = 0x{dst_val:x}{ptr_val_string}"

        src = insn.operands[1]
        src_val = self._get_reg_or_mem_val(insn, src)

        if dst.type == cs_x86.X86_OP_MEM:
            dst_target = dst_val  # dst.value.mem.disp
            ptr_val_string = self._get_ptr_val_string(src_val)
            return f"store(0x{dst_target:x},0x{src_val:x}){ptr_val_string}"
        return ""

    def _test_or_cmp_string(self, insn):
        dst_val = self._get_reg_or_mem_val(insn, insn.operands[0])
        src_val = self._get_reg_or_mem_val(insn, insn.operands[1])
        return "0x{0:x} vs 0x{1:x}".format(dst_val, src_val)

    def _get_reg_or_mem_val(self, insn, x, is_dst=False):
        """
        Gets the value of the operand, for memory addresses, gets the
        memory value at the location specified
        """
        if x.type == cs_x86.X86_OP_REG:
            return self.zelos.internal_engine.emu.get_reg(
                insn.reg_name(x.value.reg)
            )
        elif x.type == cs_x86.X86_OP_IMM:
            return x.imm
        else:
            base_val = (
                0
                if x.mem.base == 0
                else self.zelos.internal_engine.emu.get_reg(
                    insn.reg_name(x.mem.base)
                )
            )
            shift_val = (
                0
                if x.mem.index == 0
                else self.zelos.internal_engine.emu.get_reg(
                    insn.reg_name(x.mem.index)
                )
                * x.mem.scale
            )
            if is_dst:
                return base_val + shift_val + x.value.mem.disp
            else:
                return self.zelos.memory.read_int(
                    base_val + shift_val + x.value.mem.disp, sz=x.size
                )
