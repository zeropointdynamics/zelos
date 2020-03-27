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

import capstone.arm_const as cs_arm
import capstone.x86_const as cs_x86

from unicorn import UC_ERR_READ_UNMAPPED, UcError

from zelos import HookType, IPlugin


class Trace(IPlugin):
    def __init__(self, z):
        super().__init__(z)

        self.verbosity = z.config.verbosity
        self.verbose = False
        self.set_verbose(self.verbosity > 0)
        self.fasttrace = True if z.config.fasttrace > 0 else False

        self.last_instruction = None
        self.last_instruction_size = None
        self.should_print_last_instruction = False

        if self.verbose:
            self.set_hook_granularity(HookType.EXEC.INST)

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
        rev_modules = (
            self.zelos.internal_engine.modules.reverse_module_functions
        )
        if (
            self.zelos.thread.total_blocks_executed % 1000 == 0
            and address not in rev_modules
        ):
            self.zelos.swap_thread("process swap")
            return

        if self.verbose:
            if self.should_print_last_instruction:
                self.zelos.internal_engine.trace.bb(
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
