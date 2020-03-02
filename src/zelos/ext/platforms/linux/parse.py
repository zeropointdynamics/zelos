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
from os.path import basename, exists, splitext

import lief

import zelos.util as util

from zelos.exceptions import UnsupportedBinaryError
from zelos.file_system import FileSystem
from zelos.plugin import Parser, Section


class LiefELF(Parser):
    def __init__(self, file_system: FileSystem, path: str, binary):
        super().__init__()
        self._files = file_system
        self.ExtraCmdlineArg = None
        self.parse(path, binary)

    def file_format(self):
        return "ELF"

    def _get_interpreter(self, binary):
        try:
            return binary.interpreter
        except Exception:
            return None

    def _find_interpreter(self, requested_interpreter, binary):
        if requested_interpreter == "":
            self.logger.notice("Requested interpreter is blank")
        linker_path = self._files.emulated_path_to_host_path(
            requested_interpreter
        )
        if linker_path is not None and exists(linker_path):
            return linker_path

        machine = binary.header.machine_type
        if machine == lief.ELF.ARCH.i386:
            path = "/lib/ld-linux.so.2"
        elif machine == lief.ELF.ARCH.ARM:
            path = "/lib/ld-linux.so.3"
        else:
            self.logger.notice("No default interpreter for this arch")
            return ""
        self.logger.verbose(f"Attempting with default linker {path}")
        default_linker_path = self._files.emulated_path_to_host_path(path)
        if default_linker_path is not None and exists(default_linker_path):
            return default_linker_path
        raise UnsupportedBinaryError(
            f"Couldn't find linker {requested_interpreter}"
        )

    def _setup_dynamic_binary(self, requested_interpreter, binary):
        """
        Dynamic binaries need to run the appropriate linker, and pass
        the executable as a commandline argument
        """
        self.logger.verbose(
            f"Requested {requested_interpreter} to load dynamic binary"
        )

        linker_path = self._find_interpreter(requested_interpreter, binary)

        self.ExtraCmdlineArg = requested_interpreter
        linker_binary = lief.parse(linker_path)
        return (linker_path, linker_binary)

    def parse(self, path, binary):
        interpreter = self._get_interpreter(binary)
        if interpreter is not None:
            # TODO: automatically do setup to run dynamic linux binaries
            (path, binary) = self._setup_dynamic_binary(interpreter, binary)
        self.Filepath = path
        self.binary = binary

        # Refer parsed binary and symbols for better logging
        # @@NOTE binary.get_function_address on binary.symbols invokes
        # a _lot_ of brk()
        functions = {}
        for symbol in binary.static_symbols:
            if symbol.is_function:
                text_sections = binary.get_section(".text")
                text_va = text_sections.virtual_address
                text_offset = text_sections.offset
                text_base = text_va - text_offset
                symbol_offset = symbol.value - text_base
                if symbol_offset > 0:
                    functions[symbol.value] = symbol.name
        self.exported_functions = functions

        # Parse Architecture
        machine = binary.header.machine_type
        if machine == lief.ELF.ARCH.i386:
            self.Architecture = "x86"
            self.Mode = "32"
            self.Bits = 32
        elif machine == lief.ELF.ARCH.x86_64:
            self.Architecture = "x86_64"
            self.Mode = "64"
            self.Bits = 64
        elif machine == lief.ELF.ARCH.ARM:
            self.Architecture = "arm"
            self.Mode = "32"
            self.Bits = 32
        # When looking at other archs, this gives information about
        # stack for arm:
        # https://stackoverflow.com/questions/1802783/initial-state-of-program-registers-and-stack-on-linux-arm/6002815#6002815
        elif machine == lief.ELF.ARCH.MIPS:
            self.Architecture = "mips"
            self.mode = "32"
            self.bits = 32
        else:
            raise UnsupportedBinaryError(f"Unsupported arch {machine} for ELF")

        if binary.is_pie:
            raise UnsupportedBinaryError("Can't handle PIE binaries")

        self.Data = [0] * binary.virtual_size

        # TODO: More time should be invested here to figure out whether
        # this is legit.
        # lets arbitrarily load things at 0x0b000000
        self.logger.debug(f"Binary's imagebase is {binary.imagebase:x}")
        relocated_base = 0 if binary.imagebase != 0 else 0xB000000
        base = relocated_base + binary.imagebase
        self.base = base

        # Only load segments that are the LOAD type.
        segments_to_load = []
        for s in binary.segments:
            if s.type == lief.ELF.SEGMENT_TYPES.LOAD:
                segments_to_load.append(s)
        if len(segments_to_load) == 0:
            raise UnsupportedBinaryError("No loadable segment")

        for segment in segments_to_load:

            virtual_offset = segment.virtual_address - binary.imagebase
            self.Data[
                virtual_offset : virtual_offset + len(segment.content)
            ] = segment.content
            self.logger.debug(
                f"Load segment from {binary.imagebase + virtual_offset:x} to"
                f" {binary.imagebase+virtual_offset+len(segment.content):x}"
            )
            for s in segment.sections:
                section = Section()
                section.Name = s.name
                alignment = s.alignment
                section.Size = util.align(s.size, alignment)
                section.VirtualSize = util.align(s.size, alignment)
                section.Address = relocated_base + s.virtual_address
                section.Permissions = 7
                section.Alignment = 0 if s.alignment < 2 else s.alignment
                # print(s)
                # print(dir(s))
                self.Sections.append(section)
                offset = section.Address - self.base
                self.logger.verbose(
                    "Adding data for section %s at offset %x of size %x",
                    s.name,
                    offset,
                    len(s.content),
                )

        # Load the ELF header and the program/section headers.
        ph_offset = binary.header.program_header_offset
        ph_data_size = (
            binary.header.program_header_size * binary.header.numberof_segments
        )
        self.Data[
            : ph_offset + ph_data_size
        ] = binary.get_content_from_virtual_address(
            binary.imagebase, ph_offset + ph_data_size
        )

        self.set_tls_data(binary)

        # Set Misc. Binary Attributes
        self.Filename = basename(self.Filepath)
        self.Shortname = splitext(self.Filename)[0]
        self.ImageBase = base
        self.EntryPoint = relocated_base + binary.entrypoint
        self.VirtualSize = binary.virtual_size
        self.HeaderAddress = base + binary.header.program_header_offset
        self.HeaderSize = binary.header.program_header_size
        self.NumberOfProgramHeaders = binary.header.numberof_segments
        return

    def set_tls_data(self, binary):
        """ Used to init the tls data of an elf file"""
        self.Tls = bytearray()

        tdata_sections = self._get_tdata_like_sections(binary)
        if len(tdata_sections) > 0:
            s = tdata_sections[0]
            self.Tls.extend(bytearray(s.content))

        tbss_sections = self._get_tbss_like_sections(binary)
        if len(tbss_sections) > 0:
            s = tbss_sections[0]
            self.Tls.extend(bytearray(s.size))

    def _get_tdata_like_sections(self, binary):
        tdata_sections = [
            s
            for s in binary.sections
            if lief.ELF.SECTION_FLAGS.TLS in s
            and s.type == lief.ELF.SECTION_TYPES.PROGBITS
        ]
        if len(tdata_sections) > 1:
            self.logger.notice(
                f"Unexpected number of tdata-like sections: "
                f"{len(tdata_sections)}"
            )
        return tdata_sections

    def _get_tbss_like_sections(self, binary):
        tbss_sections = [
            s
            for s in binary.sections
            if lief.ELF.SECTION_FLAGS.TLS in s
            and s.type == lief.ELF.SECTION_TYPES.NOBITS
        ]
        if len(tbss_sections) > 1:
            self.logger.notice(
                f"Unexpected number of tbss-like sections: "
                f"{len(tbss_sections)}"
            )
        return tbss_sections


def print_tls(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"

    print("== TLS ==")
    tls = binary.tls
    callbacks = tls.callbacks
    print(format_hex.format("Address of callbacks:", tls.addressof_callbacks))
    if len(callbacks) > 0:
        print("Callbacks:")
        for callback in callbacks:
            print("  " + hex(callback))

    print(format_hex.format("Address of index:", tls.addressof_index))
    print(format_hex.format("Size of zero fill:", tls.sizeof_zero_fill))
    print(
        "{:<33} 0x{:<10x} 0x{:<10x}".format(
            "Address of raw data:",
            tls.addressof_raw_data[0],
            tls.addressof_raw_data[1],
        )
    )
    print(format_hex.format("Size of raw data:", len(tls.data_template)))
    print(format_hex.format("Characteristics:", tls.characteristics))
    print(format_str.format("Section:", tls.section.name))
    print(format_str.format("Data directory:", str(tls.directory.type)))
    print(("Callbacks:", tls.callbacks))
    for cb in tls.callbacks:
        print(format_hex.format("  Callback:", cb))
    print("")
