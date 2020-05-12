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

from typing import Dict

from zelos.hooks import HookType


# TODO: improve BreakState structure
BreakState = dict


class Breakpoint:
    """
    Keeps track of information regarding a breakpoint.
    """

    def __init__(self, hook_info, is_temporary):
        # Skips this breakpoint this number of times. Values <=0 mean
        # the breakpoint is not skipped
        self.skip_count = 0
        # Read-only
        self._is_temporary = is_temporary
        self._hook_info = hook_info

    @property
    def is_temporary(self):
        return self._is_temporary


class BreakpointManager:
    """
    Manages the state of breakpoints in Zelos.
    """

    def __init__(self, hook_manager):
        self.logger = logging.getLogger(__name__)

        self._breakpoints: Dict[int, Breakpoint] = {}
        self._hook_manager = hook_manager

    def get_breakpoints(self) -> Dict[int, Breakpoint]:
        """
        Returns a dict of address -> Breakpoint
        """
        return self._breakpoints.copy()

    def set_breakpoint(self, address: int, temporary: bool) -> None:
        """
        Sets a breakpoint at the given address if one does not already
        exist there.
        """
        if address in self._breakpoints:
            self.logger.notice(
                f"Breakpoint already set for address {address:x}"
            )
            return

        def hook(zelos, address, size):
            b = self._breakpoints[address]
            if b.skip_count > 0:
                b.skip_count -= 1
                return
            zelos.stop("breakpoint")
            if temporary:
                self.remove_breakpoint(address)

        hook_info = self._hook_manager.register_exec_hook(
            HookType.EXEC.INST,
            hook,
            ip_low=address,
            ip_high=address,
            name=f"breakpoint_{address:x}",
        )
        bp = Breakpoint(hook_info, temporary)
        self._breakpoints[address] = bp
        self.logger.debug(f"Set breakpoint at {address:x}")

    def remove_breakpoint(self, address: int) -> bool:
        """
        Removes a breakpoint if one exists at that address.
        """
        bp = self._breakpoints.get(address, None)
        if bp is None:
            self.logger.error(f"No breakpoint at {address:x} to remove")
            return
        self._hook_manager.delete_hook(bp._hook_info)
        del self._breakpoints[address]

    def _disable_breakpoints_on_start(self, address: int):
        """
        In order to get past breakpoints, we need to disable any
        breakpoints that are at the starting address.
        """
        b = self._breakpoints.get(address, None)
        if b is not None:
            b.skip_count += 1
