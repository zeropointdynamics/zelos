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


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


def run_traceon():
    z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
    z.plugins.trace.traceon(0x08131B16)
    z.start()


def run_traceoff():
    z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), verbosity=1)
    z.plugins.trace.traceoff(0x08048B73)
    z.start()


def run_sys_traceon():
    z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
    z.plugins.trace.traceon_syscall("write")
    z.start()


def run_sys_traceoff():
    z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"), verbosity=1)
    z.plugins.trace.traceoff_syscall("brk")
    z.start()


if __name__ == "__main__":
    fn = "traceon"
    if len(sys.argv) > 1:
        if sys.argv[1] in [
            "traceon",
            "traceoff",
            "sys_traceon",
            "sys_traceoff",
        ]:
            fn = sys.argv[1]
    if fn == "traceon":
        run_traceon()
    elif fn == "traceoff":
        run_traceoff()
    elif fn == "sys_traceon":
        run_sys_traceon()
    else:
        run_sys_traceoff()
