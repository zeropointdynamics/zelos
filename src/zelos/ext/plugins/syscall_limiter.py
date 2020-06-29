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

from zelos import CommandLineOption, HookType, IPlugin, Zelos


CommandLineOption(
    "syscall_limit",
    type=int,
    default=0,
    help="Stop execution after SYSCALL_LIMIT syscalls are executed.",
)

CommandLineOption(
    "syscall_thread_limit",
    type=int,
    default=0,
    help="End THREAD after SYSCALL_THREAD_LIMIT syscalls are executed"
    " in that thread",
)

CommandLineOption(
    "syscall_thread_swap",
    type=int,
    default=100,
    help="Swap threads after every SYSCALL_THREAD_SWAP syscalls are executed",
)

CommandLineOption(
    "rep_syscall_print_limit",
    type=int,
    default=50,
    help=(
        "After repeating this number of times, syscall printing is "
        "temporarily disabled."
    ),
)


class SyscallLimiter(IPlugin):
    """ Limit execution by the number of syscalls overall or by thread. """

    def __init__(self, z):
        super().__init__(z)
        self.syscall_limit = z.config.syscall_limit
        self.syscall_thread_limit = z.config.syscall_thread_limit
        self.syscall_thread_swap = z.config.syscall_thread_swap
        self.rep_syscall_print_limit = z.config.rep_syscall_print_limit
        if (
            self.syscall_limit > 0
            or self.syscall_thread_limit > 0
            or self.syscall_thread_swap > 0
            or self.rep_syscall_print_limit > 0
        ):
            self.zelos.hook_syscalls(
                HookType.SYSCALL.AFTER, self._syscall_callback
            )
        self.syscall_cnt = 0
        self.syscall_thread_cnt = defaultdict(int)
        # Used for detecting repetition in syscalls.
        self._last_syscall = None
        self._last_syscall_count = 0

    def _syscall_callback(self, zelos: Zelos, sysname: str, args, retval: int):
        self.syscall_cnt += 1

        # End execution if syscall limit reached
        if self.syscall_limit > 0 and self.syscall_cnt >= self.syscall_limit:
            zelos.stop("syscall limit")
            return

        # End thread if syscall thread limit reached
        if self.syscall_thread_limit != 0 and zelos.thread is not None:
            thread_name = zelos.thread.name
            self.syscall_thread_cnt[thread_name] += 1
            if (
                self.syscall_thread_cnt[thread_name]
                % self.syscall_thread_limit
                == 0
            ):
                zelos.end_thread()
                return

        # Swap threads if syscall thread swap limit reached
        if (
            self.syscall_thread_swap > 0
            and self.syscall_cnt % self.syscall_thread_swap == 0
        ):
            zelos.swap_thread("syscall limit thread swap")

        # Disable syscall printing if lots of repetitions occur
        if self.rep_syscall_print_limit > 0:
            rep_print_limit = self.rep_syscall_print_limit
            kernel = zelos.internal_engine.kernel
            if sysname == self._last_syscall:
                self._last_syscall_count += 1
            else:
                self._last_syscall = sysname
                if not kernel.should_print_syscalls:
                    self.logger.info(f"Syscall printing reenabled")
                    kernel.should_print_syscalls = True
                self._last_syscall_count = 1

            if self._last_syscall_count == rep_print_limit:
                self.logger.info(
                    f"Syscall {self._last_syscall} called "
                    f"{rep_print_limit} times. No longer printing syscalls"
                )
                kernel.should_print_syscalls = False
