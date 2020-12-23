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

import glob
import os
import pathlib

from collections import defaultdict
from io import StringIO
from itertools import islice
from pathlib import Path
from typing import Generator, List

import zelos

from zelos import CommandLineOption, IPlugin, Zelos


CommandLineOption(
    "yara_file",
    type=str,
    action="append",
    default=[],
    help="Scan memory for yara rules in the specified file(s)",
)
CommandLineOption(
    "yara_file_glob",
    type=str,
    default=None,
    help="Scan memory for yara rules in all files specified by the given glob",
)
CommandLineOption(
    "yara_rule",
    type=str,
    action="append",
    default=[],
    help="Scan memory for the specified yara rule string(s).",
)
CommandLineOption(
    "yara_outfile",
    type=str,
    default=None,
    help="Dump matches to the specified YAML file.",
)
CommandLineOption(
    "yara_pid",
    type=int,
    default=None,
    help="Only scan memory in the specified pid, otherwise scan all.",
)
CommandLineOption(
    "yara_memdump",
    type=str,
    default=None,
    help="Dump matching memory regions to file in the specified directory.",
)
CommandLineOption(
    "yara_brief",
    action="store_true",
    help="Only dump the list of matching rules, exclude match string details.",
)
CommandLineOption(
    "yara_xrefs",
    action="store_true",
    help="Count memory cross-references (pointers) for each match.",
)
CommandLineOption(
    "yara_max",
    type=int,
    default=None,
    help="Maximum number of yara matches per region (default: unlimited).",
)


def _get_scan_regions(
    memory: zelos.memory.Memory,
) -> Generator[zelos.MemoryRegion, None, None]:
    for mr in sorted(memory.get_regions()):
        # Skip "heap", which is a staging area for zelos, not the user
        # mode heap.
        if mr.kind == "heap":
            continue
        yield mr


class YaraString:
    """ Represents a string component of a yara rule match. """

    def __init__(self, address: int, yara_string, xrefs: int = 0):
        self._s = yara_string
        self._address = address
        self._xrefs = xrefs

    @property
    def address(self) -> int:
        return self._address

    @property
    def offset(self) -> int:
        return self._s[0]

    @property
    def value(self) -> bytearray:
        return self._s[2]

    @property
    def xrefs(self) -> int:
        return self._xrefs


class YaraMatch:
    """ Represents a yara rule match. """

    def __init__(
        self,
        yara_match,
        process: zelos.processes.Process,
        mr: zelos.MemoryRegion,
        count_xrefs: bool = False,
    ):
        self._m = yara_match
        self._pid = process.pid
        self._process = process
        self._mr = mr
        self._strings = yara_match.strings
        self._yara_strings = None
        self._count_xrefs = count_xrefs
        self._xref_cnts = []
        self._xref_total = 0
        if count_xrefs:
            for s in self._strings:
                cnt = self._do_xref_count(mr.start + s[0], process.memory)
                self._xref_total += cnt
                self._xref_cnts.append(cnt)

    @property
    def description(self) -> str:
        desc = self._m.meta.get("description", None)
        if desc is None:
            desc = self._m.meta.get("Description", None)
        return desc

    @property
    def namespace(self) -> str:
        return self._m.namespace

    @property
    def rule(self) -> str:
        return self._m.rule

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def region_desc(self) -> str:
        return f"{self._mr}"

    @property
    def region_address(self) -> int:
        return self._mr.start

    @property
    def xrefs(self) -> int:
        return self._xref_total

    @property
    def strings(self) -> List[YaraString]:
        if self._yara_strings is None:
            if self._count_xrefs:
                self._yara_strings = [
                    YaraString(
                        self.region_address + s[0], s, xrefs=self._xref_cnts[i]
                    )
                    for i, s in enumerate(self._strings)
                ]
            else:
                self._yara_strings = [
                    YaraString(self.region_address + s[0], s)
                    for i, s in enumerate(self._strings)
                ]

        return self._yara_strings

    def yaml(self, brief: bool = False) -> str:
        """
        Get YAML-formatted output for this match.

        Args:
            brief: if True, omit rule string match details.

        Returns:
            A YAML-formatted string.
        """
        f = StringIO()
        f.write(f"- {self.namespace}_{self.rule}:\n")
        if self.description is not None:
            f.write(f'\tdescription: "{self.description}"\n')
        f.write(f"\tpid: {self.pid}\n")
        f.write(f"\tnamespace: {self.namespace}\n")
        f.write(f"\trule: {self.rule}\n")
        f.write(f'\tregion_desc: "{self.region_desc}"\n')
        f.write(f"\tregion_address: 0x{self.region_address:x}\n")
        if self._count_xrefs:
            f.write(f"\txrefs: {self.xrefs}\n")
        if not brief:
            f.write(f"\tstrings:\n")
            for i, s in enumerate(self.strings):
                f.write(f"\t\taddress: 0x{self._mr.start + s.offset:x}\n")
                f.write(f"\t\t\toffset: 0x{s.offset:x}\n")
                f.write(f'\t\t\tvalue: "{s.value[:1000]}"\n')
                if self._count_xrefs:
                    f.write(f"\t\t\txrefs: {s.xrefs}\n")
        return f.getvalue()

    def info(self, brief: bool = False) -> str:
        """
        Get match summary information.

        Args:
            brief: if True, omit rule string match details.

        Returns:
            A one-line informational string.
        """
        if brief:
            return f"Matched rule: {self.namespace}.{self.rule}"
        else:
            for i, s in enumerate(self.strings):
                xref_info = ""
                if self._count_xrefs:
                    xref_info = f" xrefs: {self._xref_cnts[i]}"
                return (
                    f"Matched {self.namespace}.{self.rule} "
                    f"0x{s.address:08x} +0x{s.offset:x}{xref_info} "
                    f"{s.value[:100]}"
                )

    def memdump(self, directory: str) -> str:
        """
        Dumps the match memory region data to the specified directory.

        Args:
            directory: folder to dump the region to.

        Returns:
            The full path of the dumped memory region file.
        """
        filename = os.path.join(
            directory, f"PID{self.pid}_0x{self.region_address:x}.mem"
        )
        pathlib.Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, "wb") as f:
            f.write(self._mr.get_data())
            return filename
        return None

    def _do_xref_count(
        self, address: int, memory: zelos.memory.Memory, max_count=100
    ) -> int:
        ptr = memory.emu.pack(address)
        total_cnt = 0
        for mr in _get_scan_regions(memory):
            data = mr.get_data()
            total_cnt += data.count(ptr)
            if total_cnt > max_count:
                return max_count
        return total_cnt


class YaraScan(IPlugin):
    """
    YaraScan plugin scans memory using Yara rules.
    """

    def __init__(self, z: Zelos):
        super().__init__(z)
        self._yara = None
        self._z = z
        self._rules = None
        self._cmdline_rules = None
        if (
            len(z.config.yara_file) == 0
            and len(z.config.yara_rule) == 0
            and z.config.yara_file_glob is None
        ):
            return
        self._hook_closure()

    def _hook_closure(self):
        if not self.import_yara():
            return
        z = self._z

        def closure() -> None:
            self.compile(
                files=z.config.yara_file,
                rules=z.config.yara_rule,
                glob_string=z.config.yara_file_glob,
            )
            self._log("scanning memory...")
            list(
                islice(
                    self.matches(
                        pid=z.config.yara_pid,
                        yamldump=z.config.yara_outfile,
                        memdump=z.config.yara_memdump,
                        brief=z.config.yara_brief,
                        xrefs=z.config.yara_xrefs,
                    ),
                    z.config.yara_max,
                )
            )

        z.hook_close(closure)

    def import_yara(self):
        try:
            import yara

            self._yara = yara
        except ModuleNotFoundError:
            self._log(f"optional dependency `yara-python` not installed.")
            self._log(f"yara rules will be IGNORED.")
            self._log(f"try `pip install yara-python`.")
            return False
        return True

    def _log(self, s: str) -> None:
        self._z.logger.info(f"{s}")

    def _match(self, data: bytes):
        if self._cmdline_rules is not None:
            for m in self._cmdline_rules.match(data=data):
                yield m
        if self._rules is not None:
            for m in self._rules.match(data=data):
                yield m

    def matches(
        self,
        pid: int = None,
        memdump: str = None,
        yamldump: str = None,
        brief: bool = False,
        xrefs: bool = False,
    ) -> Generator[YaraMatch, None, None]:
        """
        Scan memory for the previously compiled yara rules.

        Args:
            pid: process ID to scan. All processes scanned if `None`.
            memdump: directory to dump matching regions, or `None`.
            yamldump: yaml output file, or `None`.
            brief: if True, only output rule matches.
            xrefs: if True, count number of references to each match.

        Returns:
            A generator yielding YaraMatch.
        """
        yamlfile = None
        if yamldump is not None:
            pathlib.Path(yamldump).parent.mkdir(parents=True, exist_ok=True)
            yamlfile = open(yamldump, "w")
        for process in self._z.internal_engine.processes.process_list:
            if pid is not None and process.pid != pid:
                continue
            for mr in _get_scan_regions(process.memory):
                if not brief:
                    self._log(f"PID:{process.pid} {mr}")
                for m in self._match(bytes(mr.get_data())):
                    match = YaraMatch(m, process, mr, xrefs)
                    self._log(match.info(brief))
                    if memdump is not None:
                        self._log(f"Wrote {match.memdump(memdump)}")
                    if yamlfile is not None:
                        yamlfile.write(match.yaml(brief))
                    yield match
        if yamlfile is not None:
            yamlfile.close()

    def compile(
        self, files: List[str], rules: List[str], glob_string: str = None
    ) -> int:
        """
        Compile yara rules.

        Args:
            files: list of yara rule files to compile.
            rules: list of strings that will create rules on-the-fly.
            glob_string: python glob file string. All matching files
                will be included as rule files.

        Returns:
            The number of files and rules loaded.
        """
        if not self.import_yara():
            return 0
        sources = {}
        for i, rule in enumerate(rules):
            if rule[0] not in ("{", "/"):
                rule = f'"{rule}" wide ascii nocase'
            sources[f"cmdline"] = (
                f"rule rule{i}"
                + " { strings: $a = "
                + rule
                + " condition: $a }"
            )
        filepaths = {}
        if glob_string is not None:
            files = files + glob.glob(glob_string, recursive=True)
        stem_cnt = defaultdict(int)
        for filepath in files:
            stem = Path(filepath).stem
            stem_cnt[stem] += 1
            if stem_cnt[stem] != 1:
                stem += str(stem_cnt[stem])
            filepaths[stem] = os.path.abspath(filepath)
        self._log(
            f"loading rules: {len(rules)} command line rule(s); "
            f"{len(files)} rule file(s)"
        )
        self._rules = self._yara.compile(filepaths=filepaths)
        self._cmdline_rules = self._yara.compile(sources=sources)
        return len(files) + len(rules)
