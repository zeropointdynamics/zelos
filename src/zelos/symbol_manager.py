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

from zelos.hooks import HookType


class SymbolManager:
    def __init__(self, z):
        self.z = z
        self.logger = logging.getLogger(__name__)
        # list of exports currently hooked in Unicorn
        self.hooked_exports = {}

    def should_auto_simulate(self, module_name, func_name):
        """
        Returns true if the autohooks should be used to simulate apis.
        Modify this function in order to modify autohook behavior
        """
        return False

    def should_setup_permanent_export_hook(self, address):
        # Block translation interrupt, use this to add permanent hooks
        # to blocks that represent the start of exported API functions
        return False

    def setup_permanent_export_hook(self, address):
        funcName = self.z.modules.reverse_module_functions[address]
        self.hooked_exports[funcName] = True
        self.z.hook_manager.register_exec_hook(
            HookType.EXEC.BLOCK,
            self.hook_export,
            name=f"export_{funcName}_{address:x}",
            ip_low=address,
            ip_high=address,
        )

    def hook_export(self, zelos, address, size):
        pass
