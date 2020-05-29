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

from collections import defaultdict
from pathlib import Path

from zelos import CommandLineOption, IPlugin, Zelos


CommandLineOption(
    "yara_file",
    type=str,
    action="append",
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
    help="Only dump the list of matching rules, exclude match details.",
)
CommandLineOption(
    "yara_xrefs",
    action="store_true",
    help="Count memory cross-references (pointers) for each match.",
)


class YaraScan(IPlugin):
    def __init__(self, z: Zelos):
        super().__init__(z)
        self._rules = None
        self._cmdline_rules = None
        if (
            z.config.yara_file is None
            and z.config.yara_rule is None
            and z.config.yara_file_glob is None
        ):
            return
        self._yara = None
        try:
            import yara

            self._yara = yara
        except ModuleNotFoundError:
            self._log(f"optional dependency `yara-python` not installed.")
            self._log(f"yara rules will be IGNORED.")
            self._log(f"try `pip install yara-python`.")
            return
        self._z = z

        def closure():
            self._load_rules(
                z.config.yara_file, z.config.yara_rule, z.config.yara_file_glob
            )
            self._log("scanning memory...")
            self._scan(pid=z.config.yara_pid, brief=z.config.yara_brief)
            self._log(f"Wrote matches to: {z.config.yara_outfile}")

        z.hook_close(closure)

    def _log(self, s):
        self._z.logger.info(f"{s}")

    def _load_rules(
        self, files: str = [], rules: str = [], glob_string: str = None
    ):
        if files is None:
            files = []
        if rules is None:
            rules = []
        sources = {}
        for i, rule in enumerate(rules):
            if rule[0] not in ("{", "/"):
                rule = '"' + rule + '" wide ascii nocase'
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

    def _count_xrefs(self, address):
        # TODO: count pointers to the given address across all memory
        return 0

    def _match(self, data):
        for m in self._cmdline_rules.match(data=data):
            yield m
        for m in self._rules.match(data=data):
            yield m

    def _scan(self, pid=None, brief=False):
        for process in self._z.internal_engine.processes.process_list:
            if pid is not None and process.pid != pid:
                continue
            memory = process.memory
            for mr in sorted(memory.get_regions()):
                if mr.kind == "heap":
                    continue
                if not brief:
                    self._log(f"PID:{process.pid} {mr}")
                for m in self._match(bytes(mr.get_data())):
                    for s in m.strings:
                        offset = s[0]
                        value = s[2]
                        address = mr.start + offset
                        if not brief:
                            self._log(
                                f"Matched {m.namespace}.{m.rule} "
                                f"0x{address:08x} +0x{offset:x} {value[:100]}"
                            )
