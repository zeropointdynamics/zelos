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
import unittest

from unittest.mock import Mock

from zelos import Zelos
from zelos.ext.platforms.linux.syscall_manager import X86SyscallManager


class SyscallManagerTest(unittest.TestCase):
    def test_syscall_override(self):
        z = Zelos(None)
        sm = X86SyscallManager(z.internal_engine)
        sm.register_overrides({"getuid": [1, 2]})
        sys_func = sm._name2syscall_func["getuid"]
        p = Mock()
        self.assertEqual(1, sys_func(sm, p))
        self.assertEqual(2, sys_func(sm, p))
        sys_func(sm, p)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
