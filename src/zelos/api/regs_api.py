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


class RegsApi:
    """
    Allows accessing registers directly by their name.

    Methods also exist for accessing registers that hold the
    instruction, stack, and frame pointers in a platform agnostic way,
    as well as functions for manipulating the stack.

    .. code-block:: python

        from zelos import Zelos, HookType

        # 32 bit x86 binary
        z = Zelos("binary_to_emulate")

        # Increment the starting address by 2
        z.regs.eip = z.regs.eip + 2

        # A platform agnostic way of adjusting the Instruction Pointer
        z.regs.setIP(z.regs.getIP() + 2)

    """

    def __init__(self, zelos):
        # Called on super() object to avoid triggering the __setattr__
        # on the RegsApi class.
        super().__setattr__("_zelos", zelos)

    @property
    def _current_thread(self):
        return self._zelos.internal_engine.current_thread

    def __getattr__(self, attr):
        return self._current_thread.get_reg(attr)

    def __setattr__(self, attr, value):
        self._current_thread.set_reg(attr, value)

    def getIP(self) -> int:
        """
        Returns the platform-agnostic instruction pointer. On x86, this
        returns the value of the EIP register. On ARM, this returns the
        value of register R15. On MIPS, this returns the value of the
        PC register.
        """
        return self._current_thread.getIP()

    def setIP(self, new_ip: int) -> None:
        """
        Sets the instruction pointer. On x86, this sets the value of the
        EIP register. On ARM, this sets the value of register R15. On
        MIPS this sets the value of the PC register.
        """
        self._current_thread.setIP(new_ip)

    def getSP(self) -> int:
        """
        Returns the platform-agnostic stack pointer. On x86, this
        returns the value of the ESP register. On ARM, this returns the
        value of register R13. On MIPS, this returns the value of the
        SP register.
        """
        return self._current_thread.getSP()

    def setSP(self, new_sp: int) -> None:
        """
        Sets the stack pointer. On x86, this sets the value of the
        ESP register. On ARM, this sets the value of register R13. On
        MIPS this sets the value of the SP register.
        """
        self._current_thread.setSP(new_sp)

    def getFP(self) -> int:
        """
        Returns the platform-agnostic frame pointer. On x86, this
        returns the value of the EBP register. On ARM, this returns the
        value of register R11. On MIPS, this returns the value of
        register $30.
        """
        return self._current_thread.getFP()

    def setFP(self, new_fp: int) -> None:
        """
        Sets the frame pointer. On x86, this sets the value of the
        EBP register. On ARM, this sets the value of register R11. On
        MIPS this sets the value of register $30.
        """
        return self._current_thread.setFP(new_fp)

    def getstack(self, offset: int) -> int:
        """
        Returns data that is `offset * word_size` bytes from the top of
        the stack.
        """
        return self._current_thread.getstack(offset)

    def setstack(self, offset: int, val: int) -> None:
        """
        Sets data that is `offset * word_size` bytes from the top of
        the stack.
        """
        self._current_thread.setstack(offset, val)

    def popstack(self) -> int:
        """
        Pop an item from the top of the stack.
        """
        return self._current_thread.popstack()

    def pushstack(self, data: int) -> None:
        """
        Push an item to the top of the stack.
        """
        return self._current_thread.pushstack(data)
