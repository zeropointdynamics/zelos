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

import functools
import io

from typing import List, Optional

from zelos.enums import ProtType


class ProcFilesystem:
    """
    Handles requests to /proc
    """

    def __init__(self, kernel):
        self._files = {"maps": self._maps, "task": self._task}
        self._kernel = kernel

    def new_proc_file(self, emulated_filepath: str) -> Optional[int]:
        file_generator = self._get_file_generator(emulated_filepath)
        return file_generator()

    def list_dir(self, emulated_filepath: str) -> List[str]:
        # return ["26971"]
        return [str(self._kernel.z.current_thread.id)]
        # return [
        #  str(t.id)
        #  for t in self._kernel.z.current_process.threads.get_active_threads()
        # ]
        return [
            "fd",
            "fdinfo",
            "ns",
            "net",
            "environ",
            "auxv",
            "status",
            "personality",
            "limits",
            "sched",
            "comm",
            "syscall",
            "cmdline",
            "stat",
            "statm",
            "maps",
            "children",
            "numa_maps",
            "mem",
            "cwd",
            "root",
            "exe",
            "mounts",
            "mountinfo",
            "clear_refs",
            "smaps",
            "smaps_rollup",
            "pagemap",
            "attr",
            "wchan",
            "stack",
            "schedstat",
            "cpuset",
            "cgroup",
            "oom_score",
            "oom_adj",
            "oom_score_adj",
            "loginuid",
            "sessionid",
            "io",
            "uid_map",
            "gid_map",
            "projid_map",
            "setgroups",
            "patch_state",
        ]

    def is_handled(self, emulated_filepath: str) -> bool:
        return self._get_file_generator(emulated_filepath) is not None

    def _get_file_generator(self, emulated_filepath: str):
        if not emulated_filepath.startswith("/proc/"):
            return None
        rest = emulated_filepath[len("/proc/") :]

        if "/" not in rest:
            return None
        token, rest = rest.split("/", 1)

        p = self._get_target_process(token)

        if "/" not in rest:
            token = rest
            rest = ""
        else:
            token, rest = rest.split("/", 1)

        for prefix, generator in self._files.items():
            if token.startswith(prefix):
                return functools.partial(generator, emulated_filepath, p)
        return None

    def _get_target_process(self, token: str) -> Optional["Process"]:
        if token == "self":
            return self._kernel.z.current_process
        pid = try_int(token)
        if pid is not None:
            p = self._kernel.z.processes.get_process(pid)
            if p is not None:
                return p
        return None

    def _maps(self, emulated_path, p) -> int:
        s = ""
        for r in p.memory.get_regions():
            if r.address + r.size <= 0xFFFFFFFF:
                area = f"{r.address:08x}-{r.address+r.size:08x}"
            else:
                area = f"{r.address:16x}-{r.address+r.size:16x}"

            perms = ["-", "-", "-", "-"]
            if r.prot & ProtType.READ != 0:
                perms[0] = "r"
            if r.prot & ProtType.WRITE != 0:
                perms[1] = "w"
            if r.prot & ProtType.EXEC != 0:
                perms[2] = "x"
            perms[3] = "s" if r.shared else "p"
            perms = "".join(perms)

            offset = "00000000"
            dev = "00:00"
            inode = "0"
            pathname = "/zelos/test"

            s += " ".join([area, perms, offset, dev, inode, pathname]) + "\n"

        file_contents = io.BytesIO(s[:-1].encode())
        return self._kernel.z.handles.new_file(
            emulated_path, file=file_contents, close_on_cleanup=False
        )

    def _task(self, emulated_path, p):
        return self._kernel.z.handles.new_file(
            emulated_path, is_dir=True, close_on_cleanup=False
        )


def try_int(val: str) -> Optional[int]:
    try:
        return int(val)
    except ValueError:
        return None
