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
import base64
import json
import logging

from os.path import abspath, basename

from termcolor import colored

from zelos import CommandLineOption, IPlugin, Zelos


CommandLineOption(
    "export_mem", action="store_true", help="Export memory regions."
)

CommandLineOption(
    "export_insts", action="store_true", help="Export instructions."
)

CommandLineOption(
    "export_funcs", action="store_true", help="Export functions."
)


class Overlay(IPlugin):
    """
    Provides functionality for exporting memory & instruction overlays.
    """

    def __init__(self, z: Zelos):
        super().__init__(z)

        self.logger = logging.getLogger(__name__)

        self.mem = True if z.config.export_mem else False
        self.insts = True if z.config.export_insts else False
        self.funcs = True if z.config.export_funcs else False

        if (self.insts or self.funcs) and z.config.verbosity == 0:
            self.logger.error(
                (
                    f"You will not get instruction comments or function "
                    f"information if you are not running in verbose mode. "
                    f'Include this flag ("-vv") if you want instruction '
                    f"comments or function information in your overlay. "
                    f"For an additional speedup, consider also including "
                    f'the fasttrace flag ("-vv --fasttrace").'
                )
            )
        if self.mem or self.insts or self.funcs:
            original_file_name = basename(z.main_binary_path)

            def closure():
                with open(f"{original_file_name}.zmu", "w") as f:
                    self.export(
                        f, mem=self.mem, insts=self.insts, funcs=self.funcs
                    )
                print(
                    f"Wrote overlay to: " f"{abspath(original_file_name)}.zmu"
                )

            self.zelos.hook_close(closure)

        self.max_section_size = 0x100000000
        self.max_pct_zero = 0.999999

    def _bad_section(self, data):
        # if size is too large, this is a bad section
        if len(data) > self.max_section_size:
            self.logger.info(f"Data too large: 0x{len(data):x}")
            return True

        # if the data contains mostly zeros, we can ignore it
        pct_zeros = data.count(b"\x00") / (1.0 * len(data))
        if pct_zeros > self.max_pct_zero:
            self.logger.info(f"Mostly zeros, pct: {pct_zeros}")
            return True

        return False

    def _dump_section(self, name, addr, perm, data, out_map):
        if "base_address" not in out_map:
            out_map["base_address"] = addr
        section = {}
        section["name"] = name
        section["address"] = addr
        section["permissions"] = perm
        section["data"] = base64.b64encode(data).decode()
        return section

    def _dump_heap(self, data):
        """ Truncate unused portion of heap data. """
        for i in range(len(data) - 1, 0, -1):
            if data[i] != 0:
                return data[: i + 1]
        return data

    def export(self, outfile=None, mem=False, insts=False, funcs=False):
        """
        Exports memory, instruction, or function info of the main binary.

        Args:
            outfile: A file-like object to which output will be written. If
                not specified, snapshot will create a file with the name
                "memory_dump.zmu" to which output will be written.
            mem: Bool that determines whether or not to export mapped memory
                regions
            insts: Bool that determines whether or not to export traced
                instructions
            funcs: Bool that determines whether or not to export traced
                functions

        """
        out_map = {}
        out_map["entrypoint"] = self.zelos.main_binary.EntryPoint
        out_map["sections"] = []
        out_map["functions"] = []
        out_map["comments"] = []

        if mem:
            regions = self.zelos.memory.get_regions()
            for region in sorted(regions):
                addr = region.address
                size = region.size
                perm = region.prot
                name = "<unk>"
                kind = "<unk>"
                region = self.zelos.memory.get_region(addr)
                if region is not None:
                    name = region.name
                    kind = region.kind
                if addr == 0x80000000:
                    continue  # GDT only
                dumped = False

                # Dump main binary
                if kind == "main" or name == "main":
                    section_name = name
                    tmpname = name.split(" ")
                    if len(tmpname) > 1:
                        section_name = tmpname[1]
                    data = self.zelos.memory.read(addr, size)
                    section = self._dump_section(
                        section_name, addr, perm, data, out_map
                    )
                    dumped = True

                # Dump main and thread stacks binary
                if kind == "stack" and "dll_main" not in name:
                    section_name = f"stack_{name}"
                    data = self.memory.read(addr, size)
                    section = self._dump_section(
                        section_name, addr, perm, data, out_map
                    )
                    dumped = True

                # Dump heap, sections, virtualalloc'd regions. Note that
                # currently we don't make use of dynamically allocated heaps,
                # and so they are excluded. Once that changes, we should
                # include them here
                if (
                    (kind == "heap" and name != "heap")
                    or kind == "valloc"
                    or kind == "section"
                ):
                    section_name = f"{kind}_{name}"
                    data = self.memory.read(addr, size)
                    if kind == "heap" and name == "main_heap":
                        data = self._dump_heap(data)

                    section = self._dump_section(
                        section_name, addr, perm, data, out_map
                    )
                    dumped = True

                line = (
                    f"Region: 0x{addr:08x} Size: 0x{size:08x} "
                    f"Perm: 0x{perm:x} \t{kind}\t\t{name}"
                )

                if dumped is True and self._bad_section(data):
                    dumped = False

                if dumped:
                    print(colored(line, "white", attrs=["bold"]))
                    out_map["sections"].append(section)
                else:
                    print(line)

        if insts:
            for c in self.zelos.plugins.trace.comments:
                cmt = {}
                cmt["address"] = c.address
                cmt["thread_id"] = c.thread_id
                cmt["text"] = c.text
                out_map["comments"].append(cmt)

        if funcs:
            for addr in self.zelos.plugins.trace.functions_called.keys():
                function = {}
                function["address"] = addr
                function["name"] = f"traced_{addr:x}"
                function["is_import"] = False
                out_map["functions"].append(function)

        r = json.dumps(out_map)
        loaded_r = json.loads(r)

        if outfile is None:
            with open("overlay.zmu", "w") as f:
                f.write(
                    "DISAS\n" + json.dumps(loaded_r, indent=4, sort_keys=True)
                )
        else:
            outfile.write(
                "DISAS\n" + json.dumps(loaded_r, indent=4, sort_keys=True)
            )
