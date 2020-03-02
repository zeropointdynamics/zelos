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


class IManager:
    def __init__(self, helpers):
        self._processes = helpers.processes
        self.triggers = helpers.triggers
        self.handles = helpers.handles
        self.state = helpers.state
        self.logger = logging.getLogger(__name__)

    def get_current_thread(self):
        return self._processes.current_thread

    @property
    def emu(self):
        return self._processes.current_process.emu

    @property
    def scheduler(self):
        return self._processes.current_process.scheduler

    @property
    def hooks(self):
        return self._processes.current_process.hooks

    @property
    def memory(self):
        return self._processes.current_process.memory
