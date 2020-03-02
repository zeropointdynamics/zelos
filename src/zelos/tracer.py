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

from .manager import IManager


class Comment:
    def __init__(self, address, thread_id, text):
        self.address = address
        self.thread_id = thread_id
        self.text = text


class Tracer(IManager):
    """
    Tracer prints information to the user to help understand the state
    of execution.
    """

    def __init__(self, helpers, z, cs, modules):
        super().__init__(helpers)
        self._z = z
        self._cs = cs
        self._modules = modules
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

        if self.state.arch in ["x86", "x86_64"]:
            self.comment_generator = x86CommentGenerator(self, modules)
        elif self.state.arch == "arm":
            self.comment_generator = ArmCommentGenerator(z, self, modules)
        else:
            self.comment_generator = EmptyCommentGenerator()

    @property
    def functions_called(self):
        return self.comment_generator.functions_called

    def bb(self, address=None, size=20, full_trace=False):
        if not self.should_print_thread():
            return
        """ Prints instructions starting at the given address up to
        'size' bytes away. If no address is given, prints starting at
        the current address"""
        if address is None:
            address = self.emu.getIP()
        try:
            code = self.emu.mem_read(address, size)
            insns = [insn for insn in self._cs.disasm(code, address)]
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
        reg_list = self.emu.imp_regs
        for reg in reg_list:
            s += " ".join([f"{reg}={self.emu.get_reg(reg):x}"])
            s += "\n"
        print(s)

    # There are issues when this is used with autohooks. Need to see how
    # we can include this in the future. without endless indents
    def indent(self):
        self.get_current_thread()._callstack_indent_count += 1

    def unindent(self):
        self.get_current_thread()._callstack_indent_count -= 1

    def set_current_return_address(self, addr):
        self.current_return_address = addr

    def set_current_function_name(self, name):
        self.current_function_name = name

    def set_current_api_module(self, name):
        self.current_api_module = name

    def print(self, category, s, thread=None, addr_str=None):
        if thread is None:
            thread = self.get_current_thread().name
        if addr_str is None:
            addr_str = f"{self.emu.getIP():08x}"
        thread_str = colored(f"[{thread}]", "magenta")
        category_str = colored(f"[{category}]", "red")
        addr_str_str = colored(f"[{addr_str}]", "white", attrs=["bold"])
        print(f"{thread_str} {category_str} {addr_str_str} {s}")

    # Prints the thread, return address and api string
    def api(self, args, isNative=False):
        """ Prints an API that was called"""
        if not self.should_print_thread():
            return
        return_address = self.current_return_address
        indent_count = self.get_current_thread()._callstack_indent_count
        try:
            caller_module = (
                self.memory.get_region(return_address).module_name.split(".")[
                    0
                ]
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
        indent_count = self.get_current_thread()._callstack_indent_count
        caller_module = (
            self.memory.get_region(return_address).module_name.split(".")[0]
            + "_____"
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
        if insn.address == self.emu.getIP():
            sep = "*"
        address = insn.address
        ins_string = self._get_insn_string(insn)
        if address in self._z.main_module.exported_functions:
            function_name = self._z.main_module.exported_functions[address]
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
            t = self.get_current_thread()
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
            # Log comment for the dump
            self.comments.append(
                Comment(insn.address, self.get_current_thread().id, cmt)
            )
        else:
            result += insn_str

        return result


class EmptyCommentGenerator:
    def get_comment(self, insn):
        return ""


class ArmCommentGenerator:
    def __init__(self, z, tracer, modules):
        self.functions_called = {}
        self._z = z
        self.tracer = tracer
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
        if insn.insn_name() == "svc" and insn.operands[0].imm != 0:
            syscall_num = insn.operands[0].imm - 0x900000
        else:
            syscall_num = self._z.zos.syscall_manager.get_syscall_number()
        syscall_name = self._z.zos.syscall_manager.find_syscall_name_by_number(
            syscall_num
        )
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
        if src_val in self._z.main_module.exported_functions:
            func_name = self._z.main_module.exported_functions[src_val]
            return f"<{func_name:s}> (0x{src_val:x})"
        return f"<0x{src_val:x}>"

    def _get_reg_or_mem_val(self, insn, x, is_dst=False):
        """
        Gets the value of the operand, for memory addresses, gets
        the memory value at the location specified
        """
        if x.type == cs_arm.ARM_OP_REG:
            return self.tracer.emu.get_reg(insn.reg_name(x.value.reg))
        elif x.type == cs_arm.ARM_OP_IMM:
            return x.imm
        else:
            base_val = (
                0
                if x.mem.base == 0
                else self.tracer.emu.get_reg(insn.reg_name(x.mem.base))
            )
            shift_val = (
                0
                if x.mem.index == 0
                else self.tracer.emu.get_reg(insn.reg_name(x.mem.index))
                * x.mem.scale
            )
            if is_dst:
                return base_val + shift_val + x.value.mem.disp
            else:
                return self.tracer.memory.read_int(
                    base_val + shift_val + x.value.mem.disp
                )


class x86CommentGenerator:
    def __init__(self, tracer, modules):
        self.tracer = tracer
        self._modules = modules
        self.functions_called = {}

    def _get_ptr_val_string(self, ptr: int) -> str:
        """Returns a string representing the data pointed to by 'ptr' if 'ptr'
        is a valid pointer. Otherwise, reutrns an empty string."""
        try:
            pointer_data = self.tracer.memory.read_int(ptr)
        except UcError as e:
            if e.errno == UC_ERR_READ_UNMAPPED:
                return ""
            raise e

        s = ""
        try:
            s = self.tracer.memory.read_string(ptr, 8)
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
        target = self.tracer.emu.getIP()
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
            return self.tracer.emu.get_reg(insn.reg_name(x.value.reg))
        elif x.type == cs_x86.X86_OP_IMM:
            return x.imm
        else:
            base_val = (
                0
                if x.mem.base == 0
                else self.tracer.emu.get_reg(insn.reg_name(x.mem.base))
            )
            shift_val = (
                0
                if x.mem.index == 0
                else self.tracer.emu.get_reg(insn.reg_name(x.mem.index))
                * x.mem.scale
            )
            if is_dst:
                return base_val + shift_val + x.value.mem.disp
            else:
                return self.tracer.memory.read_int(
                    base_val + shift_val + x.value.mem.disp, sz=x.size
                )
