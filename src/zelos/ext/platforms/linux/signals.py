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

import enum
import logging

from zelos.util import columnate


def is_signal_blocked(signum: int, sigmask: int) -> bool:
    return 0 != (2 ** (signum - 1) & sigmask)


def sigmask_string(sigmask: int) -> str:
    s = "|".join(
        [sig.name for sig in Signal if is_signal_blocked(sig, sigmask)]
    )
    return f"[{s}]"


class Signals:
    """
    Signals register an action that should be taken for a certain
    process. They are another form of coordination across processes.
    """

    def __init__(self, arch, p):
        self.arch = arch
        self.logger = logging.getLogger(__name__)
        self.p = p
        # 32 linux signals
        self.signal_actions = {i: 0 for i in range(32)}
        self.signal_mask = 0
        self.signal_queue = []

    def __str__(self):
        signal_strings = [
            f"{i:<2}: 0x{addr:10<x}" for i, addr in self.signal_actions.items()
        ]
        s = columnate(signal_strings, 4)
        return s + "\n"

    def set_signal_mask(self, signal_mask):
        self.signal_mask = signal_mask

    def get_signal_mask(self):
        return self.signal_mask

    def set_signal_action(self, signal, address):
        self.signal_actions[signal] = address
        if address != 0:
            self.logger.info(
                f"Handler 0x{address:x} set for {Signal(signal).name}"
            )

    def get_signal_action(self, signal):
        return self.signal_actions.get(signal, 0)

    def send_signal(self, signum, pid):
        # TODO
        # p = self.p.processes.get_process(pid)
        pass

    def handle_signal_queue(self):
        if len(self.signal_queue) == 0:
            return
        sig = self.next_unblocked_signal()
        if sig is not None:
            self.handle_signal(sig)

    def next_unblocked_signal(self):
        for i, sig in enumerate(self.signal_queue):
            if not is_signal_blocked(sig, self.signal_mask):
                return self.signal_queue.pop(i)
        return None

    def handle_signal(self, signum):

        sig = Signal(signum)
        # Save and setup so that signal handler is handled appropriately
        if is_signal_blocked(sig, self.signal_mask):
            self.logger.info(
                f"{sig.name} blocked by mask. Queued on pid 0x{self.p.pid:x}"
            )
            self.signal_queue.append(sig)
            return

        action = self.signal_actions[sig]
        if action in [0, 1, 8]:
            self.logger.info(
                f"Signal {sig.name} ignored on pid 0x{self.p.pid:x}"
            )
            return
        # Get the current thread
        thread = self.p.current_thread
        if thread is None:
            all_threads = self.p.threads.get_active_threads()
            if len(all_threads) == 0:
                self.logger.warning(
                    f"Pid 0x{self.p.pid:x} has no active threads"
                )
                return
            thread = all_threads[0]

        # Ensure we have an up-to-date saved version of active thread
        thread.save_context()
        self.save_state = thread.context

        # Ensure next time this thread runs, so is the signal handler
        thread.setIP(action)
        self._setup_signal_handler(sig, thread)
        thread.save_context()

        self.logger.info(
            f"Signal {sig.name} handled on pid 0x{self.p.pid:x}"
            f" with action 0x{action:x}"
        )

    def return_from_signal(self):
        self.p.current_thread.load_context(self.save_state)
        self.save_state = None
        self.handle_signal_queue()

    # TODO: Consolidate with first arg in syscall manager
    def _setup_signal_handler(self, sig, thread):
        if self.arch == "x86":
            thread.set_reg("eax", sig)
        elif self.arch == "x86_64":
            thread.set_reg("rax", sig)
        elif self.arch == "mips":
            thread.set_reg("a0", sig)
        elif self.arch == "arm":
            thread.set_reg("r0", sig)


# x86/ARM + most others
# If we find there needs to be another type of signal, we can subclass
# the signal handling code.
class Signal(enum.IntEnum):
    SIGHUP = 1
    SIGINT = 2
    SIGQUIT = 3
    SIGILL = 4
    SIGTRAP = 5
    SIGABRT = 6
    SIGIOT = 6
    SIGBUS = 7
    SIGFPE = 8
    SIGKILL = 9
    SIGUSR1 = 10
    SIGSEGV = 11
    SIGUSR2 = 12
    SIGPIPE = 13
    SIGALRM = 14
    SIGTERM = 15
    SIGSTKFLT = 16
    SIGCHLD = 17
    SIGCONT = 18
    SIGSTOP = 19
    SIGTSTP = 20
    SIGTTIN = 21
    SIGTTOU = 22
    SIGURG = 23
    SIGXCPU = 24
    SIGXFSZ = 25
    SIGVTALRM = 26
    SIGPROF = 27
    SIGWINCH = 28
    SIGIO = 29
    SIGPWR = 30
    SIGSYS = 31

    RTSIG1 = 32
    RTSIG2 = 33
    RTSIG3 = 34
    RTSIG4 = 35
    RTSIG5 = 36
    RTSIG6 = 37
    RTSIG7 = 38
    RTSIG8 = 39
    RTSIG9 = 40
    RTSIG10 = 41
    RTSIG11 = 42
    RTSIG12 = 43
    RTSIG13 = 44
    RTSIG14 = 45
    RTSIG15 = 46
    RTSIG16 = 47
    RTSIG17 = 48
    RTSIG18 = 49
    RTSIG19 = 50
    RTSIG20 = 51
    RTSIG21 = 52
    RTSIG22 = 53
    RTSIG23 = 54
    RTSIG24 = 55
    RTSIG25 = 56
    RTSIG26 = 57
    RTSIG27 = 58
    RTSIG28 = 59
    RTSIG29 = 60
    RTSIG30 = 61
    RTSIG31 = 62
