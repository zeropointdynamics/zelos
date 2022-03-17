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
from __future__ import print_function

import io
import logging
import os
import sys

from collections import defaultdict
from typing import List, Optional, Tuple

from termcolor import colored

from zelos.hooks import HookType

from .pipe import Pipe


class Handle(object):
    def __init__(self, name, parent_thread, access=0):
        self.Refs = 0
        self.Access = 0
        self.Name = name
        self.data = {}

        self.parent_thread = parent_thread

    def __str__(self):
        return f"{self.category()}\tRefs {self.Refs}\tAccess"
        f" {self.Access:08x}\t\t{self.Name}"

    def close(self) -> None:
        """
        Closes an instance of this handle, maintaining the number of
        references to the underlying object.
        """
        if self.Refs == 0:
            logging.getLogger(__name__).notice(
                "Tried to close handle, but there are no more refs."
            )
            return
        self.Refs -= 1
        if self.Refs == 0:
            self.cleanup()
        return

    def cleanup(self) -> None:
        """
        Override this if there is an action that needs to be taken when
        there are no more references to the underlying object.
        """
        pass

    def category(self) -> str:
        """
        Returns:
            The type of object this handle represents.
        """
        s = type(self).__name__
        return s.replace("Handle", "").lower()


class FileHandle(Handle):
    def __init__(
        self,
        name,
        file_system,
        parent_thread,
        access=0,
        is_dir=False,
        file=None,
        close_on_cleanup=True,
    ):
        super().__init__(name, parent_thread, access)
        self._file_system = file_system
        self._file = None
        self._close_on_cleanup = close_on_cleanup
        self.is_dir = is_dir
        if is_dir:
            return
        if file is not None:
            self._file = file
            return
        # Keep in mind that only files that are in the sandbox are
        # writable.
        try:
            self._file = file_system.open_library(name)
            if self._file is None:
                self._file = self._file_system.open_sandbox_file(
                    name, create_if_not_exists=True
                )
        except IsADirectoryError:
            self.is_dir = True

    def truncate(self, size) -> None:
        if size > 0x100 * 0x1000 * 0x1000:
            self._file_system.logger.warning("Limiting truncate to 0x100 MB")

        try:
            self._file.truncate(size)
        except io.UnsupportedOperation:
            self._copy_on_write()
            self._file.truncate(size)

    def size(self) -> int:
        fileno = self._file.fileno()
        return os.fstat(fileno).st_size

    def tell(self) -> int:
        return self._file.tell()

    def seek(self, offset: int, whence: int = 0) -> None:
        if self._file is None:
            return
        self._file.seek(offset, whence)
        return self._file.tell()
        # if whence == 0:  # SEEK_SET
        #     self.Offset = offset
        # elif whence == 1:  # SEEK_CUR
        #     self.Offset += offset
        # elif whence == 2:  # SEEK_END
        #     self.Offset = self.Size - offset

    def write(self, data: bytes) -> int:
        if self._file is None:
            return 0
        try:
            self._file.write(data)
        except io.UnsupportedOperation:
            self._copy_on_write()
            self._file.write(data)
            self._file.flush()
        return len(data)

    def _copy_on_write(self):
        # We should replace the file that we are using with one in
        # the sandbox that contains the same data, that way we can
        # write it.
        offset = self._file.tell()
        f = self._file_system.open_sandbox_file(
            self.Name, create_if_not_exists=True
        )
        original_file_contents = self._file.read()
        f.write(original_file_contents)
        f.seek(offset)
        self._file = f

    def read(self, size: int) -> bytes:
        if self._file is None:
            return bytes()
        return self._file.read(size)

    def cleanup(self) -> None:
        if self._file is not None and self._close_on_cleanup:
            self._file.close()


class SocketHandle(Handle):
    def __init__(self, name, parent_thread, socket, access=0):
        super().__init__(name, parent_thread, access)
        self.socket = socket

    def cleanup(self) -> None:
        self.socket.close()


class RegistryKeyHandle(Handle):
    def __init__(self, name, parent_thread, access=0, attributes=None):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes


class SectionHandle(Handle):
    def __init__(self, name, parent_thread, access=0, attributes=None):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes


class SymbolicLinkObjectHandle(Handle):
    def __init__(self, name, parent_thread, access=0, attributes=None):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes


class WorkerFactoryHandle(Handle):
    def __init__(self, name, parent_thread, access=0, attributes=None):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes


class ObjectHandle(Handle):
    def __init__(self, name, parent_thread, access=0, attributes=None):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes


class KeyedEventHandle(Handle):
    def __init__(self, name, parent_thread, access=0, attributes=None):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes


class ProcessHandle(Handle):
    def __init__(
        self, name, parent_thread, pid, access=0, attributes=None, flags=None
    ):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes
        self.pid = pid
        self.flags = flags


class ThreadHandle(Handle):
    def __init__(
        self,
        name,
        parent_thread,
        pid,
        tid,
        access=0,
        attributes=None,
        flags=None,
    ):
        super().__init__(name, parent_thread, access)
        self.object_attributes = attributes
        self.pid = pid
        self.tid = tid
        self.flags = flags

    def __str__(self) -> str:
        return f"ThreadHandle tid:{self.tid:x}, Refs {self.Refs}\tAccess"
        f" {self.Access:08x}\t\t{self.Name}"


class PipeInHandle(Handle):
    def __init__(self, name, pipe, parent_thread=None, access=0):
        super().__init__(name, parent_thread, access)
        self.pipe = pipe

    def write(self, data: bytes) -> int:
        bytes_written = self.pipe.write(data)
        return bytes_written

    def cleanup(self) -> None:
        self.pipe.write_end_closed = True


class PipeOutHandle(Handle):
    def __init__(self, name, pipe, parent_thread=None, access=0):
        super().__init__(name, parent_thread, access)
        self.pipe = pipe

    def read(self, size: int) -> bytes:
        return self.pipe.read(size)

    def cleanup(self) -> None:
        self.pipe.read_end_closed = True


class StreamHandle(Handle):
    pass


class StdIn(StreamHandle):
    def __init__(self, parent_thread="unknown"):
        super().__init__("StdIn", parent_thread)

    def read(self, size: int) -> bytes:
        return b""


class StdOut(StreamHandle):
    def __init__(self, parent_thread="unknown"):
        super().__init__("StdOut", parent_thread)

    def write(self, data):
        print(f'{colored("[StdOut]:", "green")} \'{data}\'')


class StdErr(StreamHandle):
    def __init__(self, parent_thread="unknown"):
        super().__init__("StdErr", parent_thread)

    def write(self, data):
        print(f'{colored("[StdErr]:", "red")} \'{data}\'')


class Handles:
    def __init__(self, processes, hook_manager, file_system):
        self.processes = processes
        self.file_system = file_system
        self.logger = logging.getLogger(__name__)
        self.handle_dict = defaultdict(dict)
        self.closed_handles = dict()
        # TODO Add function for managing handle indices, so anybody who
        # modifies handle-creation code in the future does not
        # accidentally break internal index rules (being a multiple of
        # 4, for example)

        # Handles must be a multiple of 4.
        # Lower two bits used by usermode.
        #   see devblogs.microsoft.com/oldnewthing/20050121-00/?p=36633
        self.handle_index = 4

        def init_handles(p):
            # Add some default system handles
            try:
                # Don't passthrough if
                #  * stdin is terminal
                #  * not TextIoWrapper (tests replace stdin)
                passthrough_stdin = not sys.stdin.isatty() and isinstance(
                    sys.stdin, io.TextIOWrapper
                )
            except ValueError:  # stdin was closed
                self.logger.notice(
                    "stdin was closed, not redirecting to emulated stdin"
                )
                passthrough_stdin = False

            # Passthrough allows the emulated process to read stdin
            # passed to Zelos
            if passthrough_stdin:
                self.logger.info("Passing stdin to emulated program")
                self.new_file(
                    "stdin_redirect",
                    handle_num=0,
                    file=sys.stdin.buffer,
                    pid=p.pid,
                    close_on_cleanup=False,
                )
            else:
                self.add_handle(StdIn(), handle_num=0, pid=p.pid)
            self.add_handle(StdOut(), handle_num=1, pid=p.pid)
            self.add_handle(StdErr(), handle_num=2, pid=p.pid)

        hook_manager.register_process_hook(
            HookType.PROCESS.CREATE, init_handles
        )

    def add_handle(self, handle, handle_num=None, pid=None) -> int:
        """Returns the handle id for the handle"""
        if pid is None:
            pid = self.processes.current_process.pid
        if handle_num is None:
            handle_num = self._get_handle_num(pid=pid)
        if self.exists(handle_num, pid):
            self.close(handle_num, pid)
            self.logger.notice(f"Closed existing handle at '{handle_num}'")
        handle.Refs += 1
        return self._add_handle(handle_num, handle, pid)

    def get(
        self, handle_num: int, pid: Optional[int] = None
    ) -> Optional[Handle]:
        """
        Return the handle object with the given index, or None if it
        does not exist
        """
        if pid is None:
            pid = self.processes.current_process.pid
        return self._get_handle(handle_num, pid)

    def exists(self, handle_num: int, pid: Optional[int] = None) -> bool:
        """
        Returns true if the given handle_num already exists for the pid
        """
        handle = self.get(handle_num, pid=pid)
        return handle is not None

    # Return a new {File,Section,Event,Key,Mutant,Directory,Desktop,
    # ALPC Port,Semaphore,WindowStation,etc.} handle

    def _current_thread_name(self) -> str:
        try:
            curr_thread = self.processes.current_process.current_thread
            return curr_thread.name
        except AttributeError:
            return "none"

    def new(self, T, name, access=0, handle_num=None):
        """
        Used to create handles that are not one we already support
        """
        parent_thread = self._current_thread_name()
        handle = Handle(name, parent_thread, access)
        handle.Type = T
        handle_num = self.add_handle(handle, handle_num=handle_num)
        return handle_num

    def new_file(
        self,
        name,
        access=0,
        handle_num=None,
        is_dir=False,
        file=None,
        pid=None,
        close_on_cleanup=True,
    ):
        parent_thread = self._current_thread_name()
        handle = FileHandle(
            name,
            self.file_system,
            parent_thread,
            access,
            is_dir,
            file=file,
            close_on_cleanup=close_on_cleanup,
        )
        handle_num = self.add_handle(handle, handle_num=handle_num, pid=pid)
        return handle_num

    def new_socket(self, name, socket, access=0, handle_num=None):
        parent_thread = self._current_thread_name()
        handle = SocketHandle(name, parent_thread, socket, access)
        handle_num = self.add_handle(handle, handle_num=handle_num)
        return handle_num

    def new_regkey(self, name, access=0, attributes=None, handle_num=None):
        parent_thread = self._current_thread_name()
        handle = RegistryKeyHandle(name, parent_thread, access, attributes)
        handle_num = self.add_handle(handle, handle_num=handle_num)
        return handle_num

    def new_process(
        self,
        name,
        pid,
        attributes,
        parent_thread="unknown",
        access=0,
        handle_num=None,
        flags=None,
    ):
        handle = ProcessHandle(
            name, parent_thread, pid, access, attributes, flags
        )
        handle_num = self.add_handle(handle, handle_num=handle_num)
        return handle_num

    def new_thread(
        self,
        name,
        pid,
        tid,
        attributes,
        parent_thread="unknown",
        access=0,
        handle_num=None,
        flags=None,
    ):
        handle = ThreadHandle(
            name, parent_thread, pid, tid, attributes, access, flags
        )
        handle_num = self.add_handle(handle, handle_num=handle_num)
        return handle_num

    def new_pipe(self, name, access=0):
        parent_thread = self._current_thread_name()
        pipe = Pipe()

        out_handle = PipeOutHandle(
            name + "_out", pipe, parent_thread=parent_thread, access=access
        )
        in_handle = PipeInHandle(
            name + "_in", pipe, parent_thread=parent_thread, access=access
        )
        out_handle_num = self.add_handle(out_handle)
        in_handle_num = self.add_handle(in_handle)
        return (out_handle_num, in_handle_num)

    def get_by_name(
        self, name: str, pid: Optional[int] = None
    ) -> Optional[int]:
        """
        Gets the numeric identifier for the first handle that has the
        specified name.

        Args:
            name: The name of the handle to retrieve.
            pid: The id of the process to get the handle from. Defaults
                 to None (all processes).

        Returns:
            The handle number corresponding to the specified name if one
            exists. If no such handle exists, returns None.
        """
        for handle_num, h in self._all_handles(pid):
            if h.Name == name:
                return handle_num
        return None

    def get_by_type(
        self, class_type: type, pid: Optional[int] = None
    ) -> List[Handle]:
        """
        Returns all handles of the given type.

        Args:
            class_type: Specifies the type that all returned handles
                should be an instance of.
            pid: The id of the process to get the handle from. Defaults
                 to None (all processes).

        Returns:
            All handles that are an instance of the specified type.
        """
        return [
            h for _, h in self._all_handles(pid) if isinstance(h, class_type)
        ]

    def get_by_parent_thread(
        self, parent_thread_name: str
    ) -> List[Tuple[int, Handle]]:
        """
        Gets all handles created by the specified thread

        Args:
            parent_thread_name: Restricts the handles given back to
                those created by the thread with this name.

        Returns:
            A list of tuples containing the handle num and handle of
            all the handles created by the parent thread.
        """
        return [
            (num, h)
            for (num, h) in self._all_handles(None)
            if h.parent_thread == parent_thread_name
        ]

    def close(self, handle_num: int, pid: Optional[int] = None) -> None:
        """
        Close this handle. If there are more references to the
        underlying object, it will remain open and only decrement the
        reference count.

        Args:
            handle_num: The handle_id of the handle you want to close
            pid: The process you want to edit the handles of. Defaults
                to the current process.

        """
        if pid is None:
            pid = self.processes.current_process.pid

        h = self.get(handle_num, pid)
        if h is None:
            self.logger.notice(
                f"Unable to close 0x{handle_num:x} in pid 0x{pid:x}"
            )
            return

        h.close()
        self._del_handle(handle_num, pid)

    def close_all(self, pid: Optional[int] = None) -> None:
        """
        Closes all handles present in the specified process.

        Args:
            pid: The pid of the process to close all handles of.
                Defaults to all handles in all processes.
        """
        for num, _ in self._all_handles(pid=pid):
            self.close(num, pid=pid)

    def _add_handle(self, handle_num, handle, pid):
        self.handle_dict[pid][handle_num] = handle
        return handle_num

    def _del_handle(self, handle_num, pid):
        process_handle_dict = self.handle_dict[pid]
        del process_handle_dict[handle_num]

    def _clear(self):
        self.handle_dict.clear()

    def _get_handle(self, handle_num: int, pid: int) -> Optional[Handle]:
        try:
            return self.handle_dict[pid][handle_num]
        except KeyError:  # this handle doesn't exist.
            return None

    def _all_handles(self, pid=None):
        handles = []
        if pid is not None:
            return [
                (num, h) for num, h in self.handle_dict.get(pid, {}).items()
            ]

        # Return all handles across processes
        for process_handle_dict in self.handle_dict.values():
            handles.extend(
                [(num, h) for num, h in process_handle_dict.items()]
            )
        return handles

    def _get_handle_num(self, requested_num=None, pid=None):
        """
        Allocates a handle number if not provided, and checks if the
        handle is valid.
        """
        handle_num = requested_num
        if handle_num is None:
            self.handle_index += 4
            handle_num = self.handle_index

        if self.exists(handle_num, pid=pid):
            self.logger.error(f"Handle {handle_num} has already been taken")
            return None
        return handle_num

    def _save_state(self):
        context = {
            "handles": self._all_handles(None),
            "closed_handles": self.closed_handles.copy(),
            "handle_index": self.handle_index,
        }
        return context

    def _load_state(self, data):
        self._clear()
        for (num, h) in data["handles"]:
            self._add_handle(num, h, self.processes.current_process)
        self.handles = data["handles"]
        self.closed_handles = data["closed_handles"]
        self.handle_index = data["handle_index"]

    def __str__(self):
        s = "Handles"
        for k, h in sorted(self._all_handles(None)):
            s += f"0x{k:x}: {h}\n"
        return s

    def __repr__(self):
        return self.__str__()
