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
import os
import posixpath

from inspect import getfile

import lief

from zelos import CommandLineOption
from zelos.hooks import HookType
from zelos.plugin import OSPlugin

from .loader import ElfLoader, LinuxMode
from .parse import LiefELF
from .signals import Signals
from .syscall_manager import construct_syscall_manager


CommandLineOption(
    "linux_rootfs",
    action="append",
    default=[],
    help="Specify the rootfs directory for an emulated architecture. Can "
    "be specified multiple times to set the rootfs for different "
    "architectures, and the appropriate rootfs will be used during "
    "emulation. Format: '--linux_rootfs ARCH,PATH'. ARCH is 'x86', "
    "'x86-64', 'arm', or 'mips'. PATH is the absolute host path to the "
    "directory to be used as rootfs.",
)


class Linux(OSPlugin):
    NAME = "Linux"

    def __init__(self, z):
        super().__init__(z)
        self.initial_parse = False

    def parse(self, path, binary_data):
        binary = lief.parse(binary_data)
        if binary.format != lief.EXE_FORMATS.ELF:
            return None

        arch = {
            lief.ELF.ARCH.i386: "x86",
            lief.ELF.ARCH.x86_64: "x86_64",
            lief.ELF.ARCH.ARM: "arm",
            lief.ELF.ARCH.MIPS: "mips",
        }[binary.header.machine_type]
        if not self.initial_parse:
            self._first_parse_setup(arch)
        emulated_path = self._get_emulated_path(self.z.config, path)
        if self.z is not None:
            self.z.cmdline_args.insert(0, emulated_path)

        # TODO: /proc/self/exe needs to be a symbolic link to be read
        # properly with readlink/readlinkat
        self.z.files.add_file(path, emulated_path="/proc/self/exe")

        # TODO: synchronize this path with the main zelos rootfs
        parsed_file = LiefELF(self.z.files, path, binary)
        if parsed_file is None:
            return None

        return parsed_file

    def _get_emulated_path(self, config, path: str) -> str:
        if config.virtual_path is not None:
            dir_path = config.virtual_path
        else:
            dir_path = os.path.dirname(path)

        if config.virtual_filename is not None:
            filename = config.virtual_filename
        else:
            filename = os.path.basename(path)
        return posixpath.join(dir_path, filename)

    def load(self, file, process, entrypoint_override=None):
        process.loader = ElfLoader(
            self.z,
            self.z.state,
            self.z.files,
            process,
            self.z.triggers,
            os.path.basename(self.z.main_module.Filepath),
        )

        process.loader.load(
            self.z.main_module.Filepath,
            self.z.main_module,
            entrypoint_override=entrypoint_override,
        )

    def _first_parse_setup(self, arch):
        self.z.zos.syscall_manager = construct_syscall_manager(arch, self.z)

        # On first parse, register process & thread creation hooks
        LinuxMode(arch, self.z)
        self.z.hook_manager.register_thread_hook(
            HookType.THREAD.CREATE, self._init_thread
        )
        init_process = functools.partial(self._init_process, arch)
        self.z.hook_manager.register_process_hook(
            HookType.PROCESS.CREATE, init_process
        )
        self.initial_parse = True

        if self.z.config.virtual_path is None:
            self.z.config.virtual_path = "/home/admin/zelos_dir/"

        self.z.files.setup(self.z.config.virtual_path)

        rootfs = {}
        for s in self.z.config.linux_rootfs:
            try:
                k, v = s.split(",")
                rootfs[k] = v
            except ValueError:
                self.z.logger.error(
                    f"Incorrectly formatted input to '--linux_rootfs': {s}"
                )
                self.z.logger.warn(
                    "Falling back to default rootfs for this architecture"
                )
                continue

        if arch in rootfs:
            if self.z.files.mount_folder(rootfs[arch]):
                self.z.logger.verbose(f"Rootfs set to {rootfs[arch]}")
                return
            self.z.logger.warn("Falling back to default rootfs")
        self.z.files.mount_folder(self._get_arch_subfolder(arch))

    def _init_process(self, arch, p):
        p.zos.signals = Signals(arch, p)

    def _init_thread(self, thread, stack_setup):
        # if self.z.state.arch != "mips":
        #     self.z.current_process.threads.stack_min = 0xff000000
        #     z.current_process.threads.stack_max = 0xffff0000
        self.populate_thread_stack(thread)
        if stack_setup is not None:
            stack_setup(thread)

        thread.save_context()

    def populate_thread_stack(self, thread):
        """ This populates the stack of a new thread"""
        thread.setSP(thread.stack_base)
        thread.setFP(thread.stack_base)

        # This was _populate_process_stack. Right now we are doign
        # this for every thread, we need to investigate whether this is
        # truly the case, or only for the "main thread"

        # Mimic the stack of a newly initialized process
        entryStack = [
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
        ]
        for value in reversed(entryStack):
            thread.pushstack(value)

    def _get_arch_subfolder(self, arch):
        subfolder = {
            "x86": "linux-x86",
            "x86_64": "linux-x86-64",
            "arm": "linux-armv7",
            "mips": "linux-mips",
        }[arch]

        zelos_dir = os.path.dirname(
            os.path.realpath(getfile(self.z.__class__))
        )
        env_dir = os.path.join(zelos_dir, "ext", "env")
        return os.path.join(env_dir, subfolder)
