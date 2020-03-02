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
import ntpath
import os
import posixpath

from collections import defaultdict
from typing import Optional

from zelos.exceptions import ZelosException


class PathTranslator:
    """
    PathTranslator manages the relationship between paths in the
    emulated environment. It will mimic whatever path it is initialized
    with.
    """

    def __init__(self, file_prefix):
        # Determine what type of path it is
        # Ntpath includes posixpaths, so be sure to test
        # posix first :P
        if posixpath.isabs(file_prefix):
            self._is_absolute_path = posixpath.isabs
            self.emulated_join = posixpath.join
            self.working_directory = "/"
        elif ntpath.isabs(file_prefix):
            self._is_absolute_path = ntpath.isabs
            self.emulated_join = ntpath.join
            self.working_directory, _ = ntpath.splitdrive(file_prefix)
        else:
            raise ZelosException(
                (
                    f"Path {file_prefix} is not an absolute "
                    "filepath of any system I know of."
                )
            )

        self.logger = logging.getLogger(__name__)
        self.added_files = {}
        self.mounted_folders = defaultdict(list)

    def is_absolute_path(self, emulated_path):
        return self._is_absolute_path(emulated_path)

    def change_working_directory(self, emulated_path):
        emulated_path = self._normalize_emulated_path(emulated_path)
        self.working_directory = emulated_path

    def add_file(self, real_path, emulated_path=None):
        if not os.path.isfile(real_path):
            self.logger.error(
                f"Unable to locate file {real_path} for inclusion in "
                f"emulated filesystem"
            )
            return False
        if emulated_path is None:
            emulated_path = self.emulated_join(
                self.working_directory, os.path.basename(real_path)
            )
        emulated_path = self._normalize_emulated_path(emulated_path)
        self.added_files[emulated_path] = real_path
        return True

    def mount_folder(self, real_path, emulated_path=None):
        if not os.path.isdir(real_path):
            self.logger.error(
                f"Unable to locate folder {real_path} for mounting"
            )
            return False
        if emulated_path is None:
            emulated_path = self.working_directory
        emulated_path = self._normalize_emulated_path(emulated_path)
        self.mounted_folders[emulated_path].append(real_path)
        return True

    def _normalize_emulated_path(self, emulated_path):
        """
        If emulated path is None, defaults to the working directory
        """
        if emulated_path is None:
            emulated_path = self.working_directory
        if emulated_path.startswith("./"):
            emulated_path = emulated_path[2:]
        if not self.is_absolute_path(emulated_path):
            emulated_path = self.emulated_join(
                self.working_directory, emulated_path
            )
        return emulated_path

    def emulated_path_to_host_path(self, emulated_path: str) -> Optional[str]:
        # Order for checking files
        # Sandbox (since these files could be modified versions of
        #   files elsewhere)
        # added files (individual ones)
        # mounted folders
        emulated_path = self._normalize_emulated_path(emulated_path)

        path = self.get_sandbox_path(emulated_path)
        if path is not None:
            self.logger.debug(f"From sandbox path: {emulated_path} -> {path}")
            return path

        path = self.added_files.get(emulated_path, None)
        if path is not None:
            self.logger.debug(f"From added file: {emulated_path} -> {path}")
            return path

        for emu_mount, real_mounts in self.mounted_folders.items():
            for real_mount in real_mounts:
                self.logger.debug(
                    f"Checking {emu_mount}->{real_mount} for {emulated_path} "
                )
                if emulated_path.startswith(emu_mount):
                    real_path = os.path.join(
                        real_mount, emulated_path[len(emu_mount) :]
                    )
                    if os.path.lexists(real_path):
                        self.logger.debug(
                            f"From mounted folder: "
                            f"{emulated_path} -> {real_path}"
                        )
                        return real_path

        self.logger.debug(f"No real path for '{emulated_path}'")
        return None

    def get_sandbox_path(self, emulated_path):
        return None


class FileSystem(PathTranslator):
    # TODO: We need to allow /tmp directory to be accessed, otherwise
    # cloud stuff probably won't work.
    def __init__(self, z, processes, hook_manager):
        self.directories = []
        self.z = z
        self.handles = z.handles
        self._processes = processes
        self._hook_manager = hook_manager
        self.logger = logging.getLogger(__name__)

        # Written files go into an isolated virtual file system
        self.sandbox_path = "sandbox"
        self.sandboxed_files = dict()

        self.fds = []

    def __del__(self):
        for fd in self.fds:
            try:
                fd.close()
            except Exception:
                pass

    def setup(self, file_prefix):
        PathTranslator.__init__(self, file_prefix)
        self.zelos_file_prefix = file_prefix

    def create_file(self, emulated_path):
        """
        Creates file with the given name. Returns the handle used to
        access it
        """
        handle_num = self.handles.new_file(emulated_path)
        handle = self.handles.get(handle_num)
        handle.data["offset"] = 0
        return handle_num

    def get_file_by_name(self, filename):
        handle_num = self.handles.get_by_name(filename)
        return handle_num

    def get_filename(self, handle):
        handle_data = self.handles.get(handle)
        return "" if handle_data is None else handle_data.Name

    def get_file_offset(self, handle):
        handle_data = self.handles.get(handle)
        return 0 if handle_data is None else handle_data.data["offset"]

    def set_file_offset(self, handle, new_offset):
        handle_data = self.handles.get(handle)
        if handle_data is not None:
            handle_data.data["offset"] = new_offset

    def create_file_mapping(self, handle):
        new_handle_num = self.handles.new("file_mapping", "0x%x" % handle)
        new_handle = self.handles.get(new_handle_num)
        new_handle.data["file"] = handle
        return new_handle_num

    def get_file_mapping(self, handle):
        handle_data = self.handles.get(handle)
        return 0 if handle_data is None else handle_data.data["file"]

    def write_to_sandbox(self, orig_filename, data, offset=0):
        if orig_filename == "":
            return
        # TODO: There should be a generalized way to map between the
        # windows vision of the files and the internal zelos vision.
        if orig_filename.startswith(self.zelos_file_prefix):
            orig_filename = orig_filename[len(self.zelos_file_prefix) :]

        self.z.triggers.tr_file_write(orig_filename, data)

        orig_filename = str(orig_filename).lower()
        filename = self.sandboxed_files.get(orig_filename, "")
        if len(filename) == 0:
            filename = (
                orig_filename.replace("\\", "_")
                .replace("/", "_")
                .replace(":", "_")
            )
            while filename != filename.replace("..", "."):
                filename = filename.replace("..", ".")
            filename = os.path.join(self.sandbox_path, filename)
            self.sandboxed_files[orig_filename] = filename
            print(os.path.dirname(os.path.abspath(filename)))
            print(os.path.abspath(self.sandbox_path))
            if os.path.dirname(os.path.abspath(filename)) != os.path.abspath(
                self.sandbox_path
            ):
                print(
                    "[Sandbox] Filename attempts to escape sandbox, "
                    "ignoring this file write..."
                )
                return
            print("[Sandbox] Created file {0}".format(filename))
        if not os.path.exists(self.sandbox_path):
            os.makedirs(self.sandbox_path)
        if os.path.exists(filename):
            f = self.unsafe_open(filename, "r+b")
        else:
            f = self.unsafe_open(filename, "wb")
        f.seek(offset)
        f.write(data)
        f.close()

    def list_dir(self, orig_filename):
        path = self.find_library(orig_filename)
        if path is None:
            return None
        return os.listdir(path)

    def open_library(self, orig_filename):
        path = self.find_library(orig_filename)
        if path is None:
            return None
        fd = open(path, "rb")
        self.fds.append(fd)
        return fd

    def find_library(self, orig_filename):
        """
        Second return value is True if this was a library found in the
        library path.
        """
        if orig_filename == "":
            return None

        if orig_filename.startswith(self.zelos_file_prefix):
            orig_filename = orig_filename[len(self.zelos_file_prefix) :]

        # Handle the /proc virtual subsystem # linux specific
        # if orig_filename.startswith("/proc"):
        #     return self.handle_proc_virtual_filesystem(orig_filename)

        # bytearrays cannot be hashed, ensure this is a string when
        # checking dicts
        path = self._find_path(orig_filename)
        if path is None:
            path = self._find_path(orig_filename.lower())
        return path

    # def handle_proc_virtual_filesystem(self, filename):
    #     # TODO: insert the current processes filepath here. Or some
    #     # other way of getting the filepath of the current process.
    #     # if filename == '/proc/self/exe':
    #     #     return self._processes.current_process.module_path
    #     return None

    def unsafe_open(self, *args, **kwargs):
        """
        Ensures that the file opened by this call is closed upon call to
        `Engine.close`. This function does not validate that the
        filepath is restricted appropriately, and thus should not be
        used in syscalls, or anywhere else that executing code has
        control over the inputs to the binary.
        """
        f = open(*args, **kwargs)
        self._hook_manager.register_close_hook(f.close)
        return f

    def _find_path(self, filename):
        """
        TODO: consolidate the filepath checking code to be more
        sensical, probably using the idea of mount points
        """
        if filename in self.sandboxed_files:
            return self.sandboxed_files[filename]

        # For absolute linux paths, remove the first slash

        return self.emulated_path_to_host_path(filename)

        # for d in self.library_path:
        #     p = os.path.join(d, filename)
        #     self.logger.debug(f'Looking for path {p}')
        #     if not p.startswith(d):
        #         continue
        #     if os.path.exists(p):
        #         return p

        # return None
