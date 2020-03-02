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

import sys

from os import path

from zelos import Zelos


DATA_DIR = path.dirname(path.abspath(__file__))


def patch_mem():
    z = Zelos(path.join(DATA_DIR, "password_check.bin"))
    # The address of the cmp instr
    target_address = 0x0040107C
    # run to the address of cmp and stop
    z.internal_engine.plugins.runner.run_to_addr(target_address)

    # Execution is now STOPPED at address 0x0040107C

    # Write 0x0 to address [rbp - 0x38]
    z.memory.write_int(z.regs.rbp - 0x38, 0x0)
    # resume execution
    z.start()


def patch_reg():
    z = Zelos(path.join(DATA_DIR, "password_check.bin"))
    # The address of the first time eax is used above
    target_address = 0x00401810
    # run to the target address and stop
    z.internal_engine.plugins.runner.run_to_addr(target_address)

    # Execution is now STOPPED at address 0x00401810

    # Set eax to 0x0
    z.regs.eax = 0x0
    # Resume execution
    z.start()


def patch_code():
    from keystone import KS_ARCH_X86, KS_MODE_64, Ks

    z = Zelos(path.join(DATA_DIR, "password_check.bin"))
    # The address of the cmp instr
    target_address = 0x0040107C
    # run to the address of cmp and stop
    z.internal_engine.plugins.runner.run_to_addr(target_address)

    # Execution is now STOPPED at address 0x0040107C

    # Code we want to insert
    code = b"NOP; NOP; CMP eax, eax"
    # Assemble with keystone
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)

    # replace the four bytes at this location with our code
    for i in range(len(encoding)):
        z.memory.write_uint8(target_address + i, encoding[i])

    # resume execution
    z.start()


if __name__ == "__main__":
    fn = "mem"
    if len(sys.argv) > 1:
        if sys.argv[1] in ["mem", "reg", "code"]:
            fn = sys.argv[1]
    if fn == "mem":
        patch_mem()
    elif fn == "reg":
        patch_reg()
    else:
        patch_code()
