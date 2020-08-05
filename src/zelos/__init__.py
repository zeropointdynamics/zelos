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
__version__ = "0.2.1.dev0"

__title__ = "zelos"
__description__ = "A comprehensive binary emulation platform."
__url__ = "https://github.com/zeropointdynamics/zelos"
__uri__ = __url__
__doc__ = __description__ + " <" + __uri__ + ">"

__author__ = "Zeropoint Dynamics"
__email__ = "zelos@zeropointdynamics.com"

__license__ = "AGPLv3"
__copyright__ = "Copyright (c) 2017-2020 Zeropoint Dynamics"

import os
import sys

import colorama

from .api.zelos_api import Zelos, ZelosCmdline
from .emulator.base import MemoryRegion
from .engine import Engine
from .exceptions import (
    InvalidHookTypeException,
    InvalidRegException,
    OutOfMemoryException,
    UnsupportedBinaryError,
    ZelosException,
    ZelosLoadException,
    ZelosRuntimeException,
)
from .hooks import HookType
from .memory import ProtType
from .plugin import CommandLineOption, IPlugin, ISubcommand


__all__ = [
    "Zelos",
    "ZelosCmdline",
    "Engine",
    "ZelosException",
    "ZelosLoadException",
    "ZelosRuntimeException",
    "InvalidRegException",
    "InvalidHookTypeException",
    "UnsupportedBinaryError",
    "OutOfMemoryException",
    "IPlugin",
    "ISubcommand",
    "CommandLineOption",
    "HookType",
    "ProtType",
    "MemoryRegion",
]

""" Initialize colorama only once """
colorama.init()

# FIXME for OSS release
private_path = os.path.abspath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        os.pardir,
        os.pardir,
        os.pardir,
    )
)
sys.path.insert(0, private_path)
