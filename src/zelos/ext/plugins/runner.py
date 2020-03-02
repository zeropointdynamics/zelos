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


class Runner(IPlugin):
    """
    Useful for getting the emulator to run until a desired condition
    """

    def run_to_addr(self, address):
        """ Stops emulator the next time this address is executed"""
        self.zelos.step()
        self.stop_at(address)
        self.zelos.start()

    def stop_at(self, target_addr):
        """ Causes execution to stop at the target_addr """

        def stop_with_interrupt(zelos, address, size):
            current_process = zelos.process
            process_name = current_process.name
            self.logger.debug(
                f"Got to {target_addr:x} in process {process_name}"
            )

            current_process.scheduler.stop("stop_at")

        self.zelos.hook_execution(
            HookType.EXEC.INST,
            stop_with_interrupt,
            name="stop_at_hook",
            ip_low=target_addr,
            ip_high=target_addr,
            end_condition=lambda: True,
        )

    # TODO consider allowing tunability, by giving option to adjust how
    # often a hook can be checked
    # TODO Work on allowing this to delete itself.
    def stop_when(self, condition):
        """
        Stops execution when the condition is found to be true. This
        will only be checked as frequently as the hook type.For example,
        UC_HOOK_BLOCK will only check the condition at the beginning of
        each block"""

        def stop_with_interrupt(zelos, address, size):
            if condition():
                zelos.stop("stop_when")

        self.zelos.hook_execution(
            HookType.EXEC.BLOCK, stop_with_interrupt, name="stop_when_hook"
        )

    def next_ret(self):
        """ Stops emulator after the next ret instruction """
        zelos = self.zelos
        while True:
            zelos.step()
            byte = zelos.memory.read(zelos.regs.getIP(), 1)
            if byte[0] == 0xC3:
                zelos.step()
                return

    def next_write(self, target_addr):
        """
        Stops emulator after the next time the target address is
        written to
        """

        def hook(zelos, access, address, size, value):
            print("Writing %x (%d bytes) to %x" % (value, size, address))
            zelos.stop("next_write")

        self.zelos.hook_memory(
            HookType.MEMORY.WRITE,
            hook,
            name="temp_memwrite_hook",
            mem_low=target_addr,
            mem_high=target_addr,
            end_condition=lambda: True,
        )
        self.zelos.start()
