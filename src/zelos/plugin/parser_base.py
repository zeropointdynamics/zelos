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

from zelos.enums import ProtType


PERM_NONE = ProtType.NONE
PERM_READ = ProtType.READ
PERM_WRITE = ProtType.WRITE
PERM_EXEC = ProtType.EXEC
PERM_RWX = ProtType.RWX
PERM_RX = ProtType.RX
PERM_RW = ProtType.RW
PERM_GUARD = 8


class Section(object):
    def __init__(self):
        self.Name = ""
        self.Address = 0x0
        self.Size = 0x0
        self.VirtualSize = 0x0
        self.Permissions = 0x0
        self.Alignment = 0x0

    def string(self):
        return "Section(Name={0.Name}, Perms=0x{0.Permissions:02x},"
        "Address=0x{0.Address:08x}, VirtualSize=0x{0.VirtualSize:08x},"
        "Alignment=0x{0.Alignment:04x})".format(self)

    def __str__(self):
        return self.string()

    def __repr__(self):
        return self.string()


class Imports(object):
    def __init__(self):
        self.ModuleName = ""
        self.Entries = []

    def string(self):
        return "Imports(Name={0.ModuleName}, Count={1})".format(
            self, len(self.Entries)
        )

    def __str__(self):
        return self.string()

    def __repr__(self):
        return self.string()


class ImportEntry(object):
    def __init__(self, base, import_data):
        self.Entries = []
        self.Address = base + import_data.iat_address
        self.Name = import_data.name
        self.Ordinal = 0
        self.IsOrdinal = False
        if import_data.is_ordinal:
            self.IsOrdinal = True
            self.Ordinal = import_data.ordinal

    def string(self):
        return "Import(Name={0.Name}, Address=0x{0.Address:08x}".format(self)

    def __str__(self):
        return self.string()

    def __repr__(self):
        return self.string()


class Export(object):
    def __init__(self):
        self.Name = ""
        self.Address = 0x0
        self.Ordinal = 0x0
        self.IsExtern = False
        self.ExternModule = ""
        self.ExternFunction = ""

    def string(self):
        extern = ", [EXTERN]" if self.IsExtern else ""
        return "Export(Name={0}, Address=0x{1:08x}{2})".format(
            self.Name[:20], self.Address, extern
        )

    def __str__(self):
        return self.string()

    def __repr__(self):
        return self.string()


class Symbol(object):
    def __init__(self):
        self.Name = ""
        self.Address = 0x0
        self.Size = 0x0
        self.Type = 0x0


class Parser(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.Filepath = ""
        self.Magic = ""
        self.Architecture = "x86"
        self.Mode = "32"
        self.Bits = 32
        self.Filename = ""  # e.g. ntdll.dll, libc.so
        self.ShortName = ""  # e.g. ntdll, libc
        self.ImageBase = 0x0
        self.EntryPoint = 0x0
        self.Metadata = {}  # e.g. PIE, ASLR, etc. (dict of misc key values)
        self.Imports = []  # [module: [(addr, fnName),], module2: ]
        self.Exports = []
        self.Sections = []
        self.Data = ""  # blob of all section data, including virtual data
        self.Size = 0x0
        self.VirtualSize = 0x0
        self.HeaderSize = 0x0
        self.StackSize = 0x0
        self.HeapSize = 0x0
        self.RelocDwords = None
        self.Symbols = None

    # Parse the binary. Returns False if the format is not supported.
    def parse(self, filename, filedata="", options={}):
        raise NotImplementedError()

    def string(self):
        return "Binary(Name={0.ShortName}, Address=0x{0.ImageBase:08x},"
        "VirtualSize=0x{0.VirtualSize:08x}, Arch={0.Architecture},"
        "Mode={0.Bits})".format(self)

    def __str__(self):
        return self.string()

    def __repr__(self):
        return self.string()
