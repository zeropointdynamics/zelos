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
from tempfile import TemporaryDirectory
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
            self.working_directory = "/"
            self.emulated_path_module = posixpath
        elif ntpath.isabs(file_prefix):
            self.working_directory, _ = ntpath.splitdrive(file_prefix)
            self.emulated_path_module = ntpath
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
        return self.emulated_path_module.isabs(emulated_path)

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
            emulated_path = self.emulated_path_module.join(
                self.working_directory, os.path.basename(real_path)
            )
        # If the emulated_path ends in a slash, keep the name of the
        # original binary, but place within the emulated_path
        if self.emulated_path_module.basename(emulated_path) == "":
            emulated_path = self.emulated_path_module.join(
                emulated_path, os.path.basename(real_path)
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
            emulated_path = self.emulated_path_module.join(
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
                if not emulated_path.startswith(emu_mount):
                    continue

                path_within_mounted_folder = self.emulated_path_module.relpath(
                    emulated_path, emu_mount
                )
                real_path = os.path.join(
                    real_mount, path_within_mounted_folder
                )
                real_path = os.path.normpath(real_path)
                if os.path.lexists(real_path):
                    self.logger.debug(
                        f"From mounted folder: {emulated_path} -> {real_path}"
                    )
                    return real_path

        self.logger.debug(f"No real path for '{emulated_path}'")
        return None

    def get_sandbox_path(self, emulated_path):
        return None


class FileSystem(PathTranslator):
    # TODO: We need to allow /tmp directory to be accessed, otherwise
    # cloud stuff probably won't work.
    def __init__(self, z, hook_manager, persistent_sandbox_path: str = None):
        self.directories = []
        self.z = z
        self._hook_manager = hook_manager
        self.logger = logging.getLogger(__name__)

        # Written files go into an isolated virtual file system
        if persistent_sandbox_path:
            self.sandbox_path = persistent_sandbox_path
        else:
            self._temp_dir_object = TemporaryDirectory()
            self.sandbox_path = self._temp_dir_object.name
        self.sandboxed_files = dict()

        self.fds = []

    @property
    def handles(self):
        return self.z.handles

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
        return handle_num

    def get_file_by_name(self, filename):
        handle_num = self.handles.get_by_name(filename)
        return handle_num

    def get_filename(self, handle):
        handle_data = self.handles.get(handle)
        return "" if handle_data is None else handle_data.Name

    def get_file_offset(self, handle):
        handle_data = self.handles.get(handle)
        return 0 if handle_data is None else handle_data.tell()

    def set_file_offset(self, handle, new_offset):
        handle_data = self.handles.get(handle)
        if handle_data is not None:
            handle_data.seek(new_offset)

    def create_file_mapping(self, handle):
        new_handle_num = self.handles.new("file_mapping", "0x%x" % handle)
        new_handle = self.handles.get(new_handle_num)
        new_handle.data["file"] = handle
        return new_handle_num

    def get_file_mapping(self, handle):
        handle_data = self.handles.get(handle)
        return 0 if handle_data is None else handle_data.data["file"]

    def open_sandbox_file(
        self, orig_filename: str, create_if_not_exists: bool = False
    ):
        if orig_filename == "":
            return None
        # TODO: There should be a generalized way to map between the
        # windows vision of the files and the internal zelos vision.
        if orig_filename.startswith(self.zelos_file_prefix):
            orig_filename = self.emulated_path_module.relpath(
                orig_filename, self.zelos_file_prefix
            )
            orig_filename = self.emulated_path_module.normpath(orig_filename)

        orig_filename = str(orig_filename).lower()
        filename = self.sandboxed_files.get(orig_filename, "")
        if len(filename) == 0:
            if not create_if_not_exists:
                return None
            filename = self._make_sandbox_filename(orig_filename)
            if filename is None:
                return None

            self.sandboxed_files[orig_filename] = filename
            self.logger.debug(f"[Sandbox] Created file {filename}")
        if not os.path.exists(self.sandbox_path):
            os.makedirs(self.sandbox_path)
        if os.path.exists(filename):
            return self.unsafe_open(filename, "r+b")
        return self.unsafe_open(filename, "w+b")

    def _make_sandbox_filename(self, orig_filename: str) -> str:
        filename = (
            orig_filename.replace("\\", "_")
            .replace("/", "_")
            .replace(":", "_")
        )
        while filename != filename.replace("..", "."):
            filename = filename.replace("..", ".")
        filename = os.path.join(self.sandbox_path, filename)

        if os.path.dirname(os.path.abspath(filename)) != os.path.abspath(
            self.sandbox_path
        ):
            self.logger.info(os.path.dirname(os.path.abspath(filename)))
            self.logger.info(os.path.abspath(self.sandbox_path))
            self.logger.error(
                "[Sandbox] Filename attempts to escape sandbox, "
                "ignoring this file write..."
            )
            return None
        return filename

    def write_to_sandbox(self, orig_filename, data, offset=0):
        self.z.triggers.tr_file_write(orig_filename, data)
        f = self.open_sandbox_file(orig_filename, create_if_not_exists=True)
        if f is None:
            return
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
        self.logger.debug(
            f'Opening file "{orig_filename}" (real path: "{path}")'
        )
        # Windows throws permission errors if you try to open a
        # directory. Manually throw this exception to keep things
        # uniform.
        if os.path.isdir(path):
            raise IsADirectoryError()
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
            orig_filename = self.emulated_path_module.relpath(
                orig_filename, self.zelos_file_prefix
            )
            orig_filename = self.emulated_path_module.normpath(orig_filename)

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

    def unsafe_open(self, filename, *args, **kwargs):
        """
        Ensures that the file opened by this call is closed upon call to
        `Engine.close`. This function does not validate that the
        filepath is restricted appropriately, and thus should not be
        used in syscalls, or anywhere else that executing code has
        control over the inputs to the binary.
        """
        # Windows throws a permission error when opening a directory.
        # This makes sure behavior is the same.
        if os.path.isdir(filename):
            raise IsADirectoryError()
        f = open(filename, *args, **kwargs)
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
