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
import os

from termcolor import colored

from zelos import CommandLineOption, IPlugin, Zelos


CommandLineOption(
    "snapshot", action="store_true", help="Output a snapshot of memory."
)


class Snapshotter(IPlugin):
    """
    Provides functionality for memory snapshots.
    """

    def __init__(self, z: Zelos):
        super().__init__(z)

        self.logger = logging.getLogger(__name__)

        if z.config.snapshot:
            if z.config.verbosity == 0:
                self.logger.error(
                    (
                        f"You will not get instruction comments without "
                        f'running in verbose mode. Include this flag ("-vv") '
                        f"if you want instruction comments in your snapshot. "
                        f"For an additional speedup, consider also including "
                        f'the fasttrace flag ("-vv --fasttrace").'
                    )
                )
            original_file_name = z.internal_engine.original_file_name

            def closure():
                with open(f"{original_file_name}.zmu", "w") as f:
                    self.snapshot(f)
                self.logger.info(
                    f"Wrote snaphot to: "
                    f"{os.path.abspath(original_file_name)}.zmu"
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

    def snapshot(self, outfile=None):
        """
        Dumps memory regions.

        Args:
            outfile: A file-like object to which output will be written. If
                not specified, snapshot will create a file with the name
                "memory_dump.zmu" to which output will be written.
        """
        out_map = {}
        out_map[
            "entrypoint"
        ] = self.zelos.internal_engine.main_module.EntryPoint
        out_map["sections"] = []
        out_map["functions"] = []
        out_map["comments"] = []

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
                # Temporary hack. The MEW packer requires executable
                # header section. But, we mark it non-executable for the
                # dump.
                if section_name == ".pe":
                    section = self._dump_section(
                        section_name, addr, 0x1, data, out_map
                    )
                else:
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

            # Dump heap, sections, virtualalloc'd regions. Note that currently
            # we don't make use of dynamically allocated heaps, and so they are
            # excluded. Once that changes, we should include them here
            if (
                (kind == "heap" and name != "heap")
                or kind == "valloc"
                or kind == "section"
            ):
                section_name = f"{kind}_{name}"
                data = self.memory.read(addr, size)
                if kind == "heap" and name == "main_heap":
                    # Truncate unused portion of heap
                    data = data[
                        : self.zelos.internal_engine.memory.heap.current_offset
                        - self.zelos.internal_engine.memory.HEAP_BASE
                    ]

                section = self._dump_section(
                    section_name, addr, perm, data, out_map
                )
                dumped = True

            line = (
                f"Region: 0x{addr:08x} Size: 0x{size:08x} "
                f"Perm: 0x{perm:x} \t{kind}\t\t{name}"
            )

            if dumped is True and self._bad_section(data):
                # Doppler cannot handle files that are this large at the
                # moment.
                dumped = False

            if dumped:
                print(colored(line, "white", attrs=["bold"]))
                out_map["sections"].append(section)
            else:
                print(line)

        for c in self.zelos.plugins.trace.comments:
            cmt = {}
            cmt["address"] = c.address
            cmt["thread_id"] = c.thread_id
            cmt["text"] = c.text
            out_map["comments"].append(cmt)

        for addr in self.zelos.plugins.trace.functions_called.keys():
            function = {}
            function["address"] = addr
            function["name"] = "traced_{0:x}".format(addr)
            function["is_import"] = False
            out_map["functions"].append(function)

        r = json.dumps(out_map)
        loaded_r = json.loads(r)

        if outfile is None:
            with open("memory_dump.zmu", "w") as f:
                f.write(
                    "DISAS\n" + json.dumps(loaded_r, indent=4, sort_keys=True)
                )
        else:
            outfile.write(
                "DISAS\n" + json.dumps(loaded_r, indent=4, sort_keys=True)
            )
