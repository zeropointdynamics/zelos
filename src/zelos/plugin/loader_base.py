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


class Loader:

    STACK_BASE = 0x001A0000

    def __init__(self, z, state, files, process, triggers, original_file_name):
        self._z = z
        self.state = state
        self.modules = process.modules
        self.files = files
        self.process = process
        self.triggers = triggers
        self.original_file_name = original_file_name
        self.logger = logging.getLogger(__name__)

    @property
    def emu(self):
        return self.process.emu

    @property
    def memory(self):
        return self.process.memory

    def _get_module_name(self, module_name):
        normalized_module_name = self.modules._normalize_name(module_name)

        module_path = self.files.find_library(normalized_module_name)
        if module_path is None:
            module_path = module_name  # support exe's w/out .exe extensions
            normalized_module_name = module_path
        # Try to find the file in the VFS
        if module_path is None:
            module_path = self.files.find_library(module_name)
        return module_path, normalized_module_name

    def _get_entrypoint(self, pe, entrypoint_override):
        if entrypoint_override is None:
            return pe.EntryPoint
        # If the input is the name of an export or an address, start
        # execution of the main thread at that point
        try:
            return int(entrypoint_override, 16)
        except Exception:
            pass
        try:
            return pe.get_export(entrypoint_override).Address
        except Exception:
            pass
        print(
            "entrypoint_override (%s) was neither an export nor an address."
            % entrypoint_override
        )
        return pe.EntryPoint

    """
    Load a new process with specified module path, environment,
    arguments and options
    """

    def load(
        self, module_path, file, thread_name="main", entrypoint_override=None
    ):
        raise NotImplementedError()
