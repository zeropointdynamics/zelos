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

from multiprocessing import Lock
from typing import Callable


class Scheduler:
    """
    Handles the pausing and stopping of execution of threads in Zelos.

    There are subtlties here due to how changing EIP prevents unicorn
    from stopping appropriately. Specifically, changing EIP while also
    calling stop may invalidate the stop.
    """

    # Each class has its own emu, since each process has its own
    # instance of unicorn. However, we want the stop reasons to be
    # universal, since there should only be one thread running.
    # This was to handle weird thread/process swapping errors. This is
    # why end_reasons was a class variable.
    # TODO: This breaks simultaneous instances of zelos
    _end_reasons = []
    # Used to protect from another python thread initiating user input.
    _user_input_mutex = Lock()

    def __init__(self, threads, emu):
        self.logger = logging.getLogger(__name__)
        self._threads = threads
        self._emu = emu
        # Map of tid to stop address
        self._stop_addr = {}

    def stop(self, stop_reason: str) -> None:
        """
        Stops execution of the running processes, exiting the run loop.
        If there is no process running, this will prevent the next run.

        Args:
            stop_reason: A string passed in for debugging purposes to
                indicate what caused Zelos to stop.

        """
        self.stop_and_exec(stop_reason, lambda: False)

    def stop_and_exec(
        self, stop_reason: str, should_continue: Callable[[], bool]
    ) -> None:
        """
        Stops execution of the running proesses in order to run the
        provided closure. If the `should_continue` closure returns True,
        execution will continue, otherwise the run loop will be exited.

        Args:
            stop_reason: A string passed in for debugging purposes to
                indicate what caused Zelos to stop.
            should_continue: A closure that is run after the running
                process is stopped. We should

        """
        self._end_reasons.append((stop_reason, should_continue))
        self._emu.emu_stop()
        if self._threads.current_thread is not None:
            t = self._threads.current_thread
            self._stop_addr[t.id] = t.getIP()

    # This function is needed specifically for a bug in unicorn for ARM,
    # where stopping in the middle of a block during a code hook results
    # in the ip address being reset to the beginning of the block.

    def _pop_stop_addr(self, tid) -> int:
        return self._stop_addr.pop(tid, None)

    def _resolve_end_reasons(self) -> bool:
        """Returns True if execution should restart."""
        stop_reasons = self._pop_end_reasons()
        if len(stop_reasons) > 0:
            self.logger.debug(f"End reasons are {stop_reasons}")

        should_continue = True
        while len(stop_reasons) > 0:
            (reason, action) = stop_reasons.pop(0)
            if action() is False:
                should_continue = False
            stop_reasons += self._pop_end_reasons()

        return should_continue

    def _pop_end_reasons(self):
        # This copies the list, rather than taking a reference.
        with Scheduler._user_input_mutex:
            temp = Scheduler._end_reasons[:]
            # You can't assign to self.end_reasons, as this will create
            # an instance variable.
            Scheduler._end_reasons.clear()
        return temp

    def _has_end_reasons(self):
        return len(Scheduler._end_reasons) > 0
