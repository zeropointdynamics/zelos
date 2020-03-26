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
        # Instruction hook runs before the instruction, so wait for the
        # hook to run once before printing instructions.
        self.should_print_last_instruction = False

        # If you remove one of the hooks on _hook_code, be careful that
        # you don't break the ability to stop a running emulation
        if self.verbose:
            self.set_hook_granularity(HookType.EXEC.INST)

    def set_hook_granularity(self, granularity: HookType.EXEC):
        try:
            self.zelos.delete_hook(self.code_hook_info)
        except AttributeError:
            pass  # first time setting code_hook_info

        self.code_hook_info = self.zelos.hook_execution(
            granularity, self.hook_code, name="code_hook"
        )

    @property
    def verbose(self):
        return self.zelos.internal_engine.verbose

    @verbose.setter
    def verbose(self, v):
        self.zelos.internal_engine.verbose = v

    def _check_timeout(self):
        if self.zelos.internal_engine.timer.is_timed_out():
            self.zelos.stop("timeout")

    # Hook invoked for each instruction or block.
    def hook_code(self, zelos, address, size):
        try:
            self.hook_code_impl(zelos, address, size)
            self._check_timeout()
        except Exception:
            if self.zelos.thread is not None:
                self.zelos.process.threads.kill_thread(self.zelos.thread.id)
            self.logger.exception("Stopping execution due to exception")

    def hook_code_impl(self, zelos, address, size):
        # TCG Dump example usage:
        # self.emu.get_tcg(0, 0)
        if self.zelos.thread is None:
            self.zelos.stop("hook_code_null_thread")
            return

        # Log the total number of blocks executed per thread. Swap
        # threads if the specified number of blocks is exceeded and
        # other threads exist
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
            if self.should_print_last_instruction:  # Print block
                # Turn on full trace to do trace comparison
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

    def set_verbose(self, should_set_verbose: bool) -> None:
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
