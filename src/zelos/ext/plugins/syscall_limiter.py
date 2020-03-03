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

from zelos import CommandLineOption, HookType, IPlugin


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


class SyscallLimiter(IPlugin):
    """ Limit execution by the number of syscalls overall or by thread. """

    def __init__(self, z):
        super().__init__(z)
        if (
            z.config.syscall_limit > 0
            or z.config.syscall_thread_limit > 0
            or z.config.syscall_thread_swap > 0
        ):
            self.zelos.hook_syscalls(
                HookType.SYSCALL.AFTER, self._syscall_callback
            )
        self.syscall_cnt = 0
        self.syscall_thread_cnt = defaultdict(int)

    def _syscall_callback(self, zelos, sysname, args, retval):
        if zelos.thread is None:
            return

        thread_name = zelos.thread.name

        self.syscall_cnt += 1
        self.syscall_thread_cnt[thread_name] += 1

        # End execution if syscall limit reached
        if (
            zelos.config.syscall_limit > 0
            and self.syscall_cnt >= zelos.config.syscall_limit
        ):
            zelos.stop("syscall limit")
            return

        # End thread if syscall thread limit reached
        if (
            zelos.config.syscall_thread_limit != 0
            and self.syscall_thread_cnt[thread_name]
            % zelos.config.syscall_thread_limit
            == 0
        ):
            zelos.end_thread()
            return

        # Swap threads if syscall thread swap limit reached
        if (
            zelos.config.syscall_thread_swap > 0
            and self.syscall_cnt % zelos.config.syscall_thread_swap == 0
        ):
            zelos.swap_thread("syscall limit thread swap")
        return
