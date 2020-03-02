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

from os.path import basename


# This class does not yet depend on any external Helpers. The Manager
# Superclass was intentionally not included here just to keep it clear
# that no dependency existed. If this this class ends up needing these
# things, feel free to put them in.


class Modules:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Map of name -> function implementation.
        self.function_hooks = {}
        # The set of currently loaded modules
        self.modules = []
        # The set of currently base-hooked module functions
        self.module_functions = {}
        # Map of address -> import name
        self.reverse_module_functions = {}

    def get_function_name(self, address):
        return self.reverse_module_functions.get(address, None)

    def get_function_impl(self, function_name, use_function_hooks=True):
        """
        Returns the function name and the hook if a corresponding one
        exists.
        """
        if use_function_hooks:
            hook_struct = self.function_hooks.get(function_name, None)
            if hook_struct is not None:
                return hook_struct.hook
        return None

    def get_module_base(self, module_name):
        module_name = self._normalize_name(module_name)
        for module in self.modules:
            if module_name == module[0]:
                return module[1]
        return 0

    def get_module_name_at_address(self, imagebase):
        for module in self.modules:
            if module[1] == imagebase:
                return module[0]
        return ""

    def is_loaded(self, modulename):
        modulename = self._normalize_name(modulename)
        for module in self.modules:
            if modulename == module[0]:
                return True
        return False

    # Returns the normalized module name with path stripped/lowercased.
    def _normalize_name(self, module_name):
        module_name = basename(module_name)
        module_name = module_name.lower()
        return module_name

    def _save_state(self):
        return ""

    def _load_state(self, data):
        pass
