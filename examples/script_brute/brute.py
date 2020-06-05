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

from os import path

from zelos import Zelos


DATA_DIR = path.dirname(path.abspath(__file__))


def brute():
    z = Zelos(path.join(DATA_DIR, "password.bin"), inst=True)
    # The address of strcmp observed above
    strcmp_address = 0x00400BB6
    # run to the address of call to strcmp and break
    z.set_breakpoint(strcmp_address, True)
    z.start()

    # Execution is now STOPPED at address 0x00400BB6

    # get initial reg values of rdi & rsi before strcmp is called
    rdi = z.regs.rdi  # user input
    rsi = z.regs.rsi  # 'real' password

    # 'brute force' the correct string
    for i in range(9, -1, -1):

        # write our bruteforced guess to memory
        z.memory.write_string(rdi, str(i) + "point")

        # Address of the test instr
        test_address = 0x00400BBB
        # run to the address of test instr and break
        z.set_breakpoint(test_address, True)
        z.start()

        # execute one step, in this case the test instr
        z.step()

        # check the zf bit for result of test
        flags = z.regs.flags
        zf = (flags & 0x40) >> 6
        if zf == 1:
            # if correct, run to completion
            z.start()
            return

        # otherwise, reset ip to strcmp func & set regs
        z.regs.setIP(strcmp_address)
        z.regs.rdi = rdi
        z.regs.rsi = rsi


if __name__ == "__main__":
    brute()
