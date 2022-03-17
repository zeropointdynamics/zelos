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
import ctypes
import datetime
import enum
import io
import os
import time

from os import path

from zebracorn import UcError

from zelos import handles
from zelos.enums import ProtType
from zelos.exceptions import ZelosLoadException
from zelos.threads import ThreadState
from zelos.util import align, dumpstruct, str2struct, struct2str

from ..signals import Signal
from . import syscall_structs as structs
from . import syscall_utils as sys_utils
from . import syscalls_socket as socketcall
from .syscalls_const import FCNTL_COMMANDS, PRCTL, SysError


def ptr2struct(z, addr, struct_class):
    """
    Returns an instance of struct_class read starting from addr
    """
    data = z.memory.read(addr, ctypes.sizeof(struct_class))
    instance = struct_class()
    str2struct(instance, bytes(data))
    return instance


def get_pchar_array(z, addr, size=-1):
    """
    Reads a set of string pointers starting at addr up to the first
    null pointer (with a max of size, if specified)
    Returns a list of null-terminated strings read from those pointers.
    """
    if addr == 0:
        return []
    result = []
    i = 0
    while i != size:
        pstr = z.memory.read_int(addr + i * z.state.bytes)
        if pstr == 0:
            break
        result.append(z.memory.read_string(pstr))
        i += 1
    return result


def sys_brk(k, p):
    # Returns the location of the system break.
    args = k.get_args([("void*", "addr")])
    if args.addr == 0:
        return p.memory.heap.current_offset

    # asking for more memory
    memory_to_alloc = args.addr - p.memory.heap.current_offset
    if memory_to_alloc > 0:
        k.logger.debug(
            f"sys_brk heap manager allocs "
            f"{memory_to_alloc:x}, {memory_to_alloc}"
        )
        p.memory.heap.alloc(memory_to_alloc, name="sys_brk", align=0x1)
    elif memory_to_alloc < 0:
        p.memory.heap.dealloc(-memory_to_alloc)
    # Always return the new location of the break. If failure, this is
    # the same as the old location.
    return p.memory.heap.current_offset


def sys_syscall(k, p):
    _ = k.get_args([("long", "number")])
    return 0


def sys_close(k, p):
    args = k.get_args([("int", "fd")])
    if k.z.handles.get(args.fd) is None:
        return SysError.EBADF
    k.z.handles.close(args.fd)
    return 0


def sys_cacheflush(k, p):
    k.get_args([])
    return 0


def sys_unlink(k, p):
    k.get_args([("const char*", "pathname")])
    return 0


def sys_uname(k, p):
    args = k.get_args([("struct utsname*", "buf")])
    uname_data = (
        "Linux",  # sysname
        "zelos-tower",  # nodename
        "4.18.0-25-generic",  # release
        "#26~18.04.1-Ubuntu SMP Thu Jun 27 07:28:31 UTC 2019",
        "armv7l",
        "(none)",
    )
    for i, data in enumerate(uname_data):
        padded_data = data + "\x00" * (64 - len(data))
        p.memory.write_string(args.buf + 65 * i, padded_data)
    return 0


def sys_creat(k, p):
    args = k.get_args([("const char*", "pathname"), ("mode_t", "mode")])
    O_CREAT = 0x40
    O_WRONLY = 0x1
    O_TRUNC = 0x200
    args.flags = O_CREAT | O_WRONLY | O_TRUNC
    return xopen(k, p, args)


def sys_open(k, p):
    args = k.get_args([("const char*", "pathname"), ("int", "flags")])
    return xopen(k, p, args)


def sys_openat(k, p):
    args = k.get_args(
        [("int", "dirfd"), ("const char*", "pathname"), ("int", "flags")]
    )
    return xopen(k, p, args)


def xopen(k, p, args):
    # TODO: impl. the different modes
    # O_ACCMODE = 0x3
    # O_RDONLY = 0x0
    # O_WRONLY = 0x1
    # O_RDWR = 0x2
    # O_CREAT = 0x40
    # O_EXCL = 0x80
    # O_NOCTTY = 0x100
    # O_TRUNC = 0x200
    # O_APPEND = 0x400
    # O_NONBLOCK = 0x800

    pathname_s = p.memory.read_string(args.pathname)
    path = k.z.files.find_library(pathname_s)
    k.z.triggers.tr_file_open(pathname_s)
    if path is not None:
        handle_num = k.z.handles.new_file(pathname_s)
        retval = handle_num
    elif args.flags & 0x200 != 0 or args.flags & 0x40 != 0:
        handle_num = k.z.handles.new_file(pathname_s)
        retval = handle_num
    else:
        return SysError.ENOENT
    return retval


def sys_readv(k, p):
    args = k.get_args(
        [("int", "fd"), ("const struct iovec*", "iov"), ("int", "iovcnt")]
    )

    handle = k.z.handles.get(args.fd)
    if handle is None:
        return 0

    bytes_read = 0
    for i in range(args.iovcnt):
        iovec = p.memory.read_ptr(args.iov + 0x8 * i)
        iov_len = p.memory.read_uint32(args.iov + 0x8 * i + 0x4)
        if iov_len == 0:
            continue
        if isinstance(handle, handles.SocketHandle):
            bread = socketcall._recv(k, p, args.fd, iovec, iov_len)
        elif isinstance(handle, handles.FileHandle):
            data = handle.read(iov_len)
            p.memory.write(iovec, data)
            bread = len(data)
        else:
            continue
        bytes_read += bread

    return bytes_read


def sys_writev(k, p):
    def print_iov(args):
        s = ""
        for i in range(0, args.iovcnt):
            iov_addr = args.iov + i * 2 * p.memory.state.bytes
            base_addr = p.memory.read_ptr(iov_addr)
            bytes_to_read = p.memory.read_int(iov_addr + p.memory.state.bytes)
            try:
                s += repr(bytes(p.memory.read(base_addr, size=bytes_to_read)))[
                    2:-1
                ]
            except Exception:
                pass
        if len(s) == 0:
            return f"*iov=0x{args.iov:x}"
        return f'*iov=0x{args.iov:x} ("{s}")'

    args = k.get_args(
        [("int", "fd"), ("const struct iovec*", "iov"), ("int", "iovcnt")],
        arg_string_overrides={"iov": print_iov},
    )

    bytes_written = 0
    # TODO this should just be a struct with the correct sizes in there.
    word_size = 8 if k.arch == "x86_64" else 4
    for i in range(args.iovcnt):
        iovec = p.memory.read_ptr(args.iov + 2 * word_size * i)
        if iovec == 0:
            break
        iov_len = p.memory.read_uint32(
            args.iov + 2 * word_size * i + word_size
        )
        iov_base_content = p.memory.read(iovec, iov_len)

        handle = k.z.handles.get(args.fd)
        if handle is not None and hasattr(handle, "write"):
            handle.write(iov_base_content)
        else:
            k.print(f"[writev:{args.fd}]: '{iov_base_content}'")
        bytes_written += iov_len
    return bytes_written


def sys_madvise(k, p):
    k.get_args([("void*", "addr"), ("size_t", "length"), ("int", "advice")])
    return 0


def sys_msync(k, p):
    k.get_args([("void*", "addr"), ("size_t", "length"), ("int", "flags")])
    return 0


def sys_mmap(k, p):
    if k.arch == "x86":

        def print_mmap_struct(struct_args):
            args = p.memory.readstruct(
                struct_args.__user, structs.MMAP_ARG_STRUCT32()
            )
            return (
                f"addr=0x{args.addr:x}, length=0x{args.length:x}, "
                f"prot=0x{args.prot:x}, flags=0x{args.flags:x}, "
                f"fd=0x{args.fd:x}, offset=0x{args.offset:x}"
            )

        user_arg = k.get_args(
            [("mmap_arg_struct32*", "__user")],
            arg_string_overrides={"__user": print_mmap_struct},
        )
        args = p.memory.readstruct(
            user_arg.__user, structs.MMAP_ARG_STRUCT32()
        )
    else:
        args = k.get_args(
            [
                ("void*", "addr"),
                ("size_t", "length"),
                ("int", "prot"),
                ("int", "flags"),
                ("int", "fd"),
                ("off_t", "offset"),
            ]
        )

    try:
        return mmapx(k, p, "mmap", args, args.offset)
    except Exception as e:
        k.print("mmap exception: " + str(e))
        return -1


def sys_mmap2(k, p):
    args = k.get_args(
        [
            ("void*", "addr"),
            ("size_t", "length"),
            ("int", "prot"),
            ("int", "flags"),
            ("int", "fd"),
            ("off_t", "pgoffset"),
        ]
    )
    try:
        return mmapx(k, p, "mmap2", args, args.pgoffset * 0x1000)
    except Exception as e:
        k.print("mmap2 exception: " + str(e))
        return -1


def mmapx(k, p, syscall_name, args, offset):
    MAP_SHARED = 0x1
    MAP_FIXED = 0x10
    MAP_ANONYMOUS = 0x20
    memory_region_name = syscall_name
    if args.flags & MAP_ANONYMOUS != 0:
        handle = None
    else:
        handle = k.z.handles.get(args.fd)
    if handle is not None:
        memory_region_name = f"{syscall_name} -> {handle.Name}"

    addr = args.addr
    if addr == 0:
        addr = p.memory.find_free_space(args.length, alignment=0x1000)
    prot = ProtType(args.prot)
    length = align(args.length)

    data = b""
    module_name = ""
    if handle is not None:
        f = k.z.files.open_library(handle.Name)
        if f is not None:
            f.seek(offset)
            data = f.read(args.length)
            f.close()
            module_name = handle.Name

    data += b"\0" * (args.length - len(data))
    shared = args.flags & MAP_SHARED != 0
    try:
        p.memory.map(
            addr,
            length,
            name=memory_region_name,
            kind=syscall_name,
            module_name=module_name,
            shared=shared,
            prot=prot,
        )
    except Exception:
        k.logger.debug(f"Address {addr:x} is already mapped")
        if args.flags & MAP_FIXED > 0:
            # This must be mapped to this region, we should be able to
            # just write over the existing data.
            # This should crash if we are unable to write to the desired
            # region
            p.memory.protect(addr, length, prot)
            pass
        else:
            k.logger.notice(f"Attempting to map {addr} elsewhere")
            addr = p.memory.map_anywhere(
                length,
                name=memory_region_name,
                kind=syscall_name,
                shared=shared,
            )

    p.memory.write(addr, data)

    return addr


def sys_munmap(k, p):
    k.get_args([("void*", "addr"), ("size_t", "length")])
    return 0


def sys_mprotect(k, p):
    args = k.get_args([("void*", "addr"), ("size_t", "len"), ("int", "prot")])
    p.memory.protect(args.addr, args.len, ProtType(args.prot))
    return 0


class USERDESC(ctypes.Structure):
    _fields_ = [
        ("entry_number", ctypes.c_uint32),
        ("base_address", ctypes.c_uint32),
        ("limit", ctypes.c_uint32),
        ("seg_32bit", ctypes.c_ubyte),
        ("contents", ctypes.c_uint16),
        ("read_exec_only", ctypes.c_ubyte),
        ("limit_in_pages", ctypes.c_ubyte),
        ("seg_not_present", ctypes.c_ubyte),
        ("useable", ctypes.c_ubyte),
        # ('lm', ctypes.c_ubyte), # only for x86_64
    ]


# arch/arm/kernel/traps.c:
#     case NR(set_tls):
#         thread->tp_value = regs->ARM_r0;
# #if defined(CONFIG_HAS_TLS_REG)
#         asm ("mcr p15, 0, %0, c13, c0, 3" : : "r" (regs->ARM_r0) );
# #elif !defined(CONFIG_TLS_REG_EMUL)
#         *((unsigned int *)0xffff0ff0) = regs->ARM_r0;
# #endif
#     return 0;


def sys_set_tls(k, p):
    args = k.get_args([("CPUARMState*", "env")])
    k.emu.set_reg("c13_c0_3", args.env)
    k.set_return_value(0)


def sys_set_thread_area(k, p):
    if k.arch == "mips":
        return mips_set_thread_area(k, p)

    from zelos.emulator.x86_gdt import GDT_32

    args = k.get_args([("struct user_desc*", "u_info")])
    userdesc = ptr2struct(k.z, args.u_info, USERDESC)
    p.memory.write_int(args.u_info, 0xC)

    flags = GDT_32.gdt_entry_flags(
        gr=0, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1
    )  # 0x4f3
    p.gdt.set_entry(0xC, userdesc.base_address, 0xFFF, flags)

    tdata = k.z.main_module.Tls
    p.memory.write(userdesc.base_address - len(tdata), bytes(tdata))
    return 0


def mips_set_thread_area(k, p):
    args = k.get_args([("unsigned long", "addr")])
    p.emu.set_reg("cp0_userlocal", args.addr)
    return 0


def sys_read(k, p):
    args = k.get_args([("int", "fd"), ("void*", "buf"), ("size_t", "count")])
    handle = k.z.handles.get(args.fd)
    if handle is None:
        return SysError.EBADF
    if not p.memory.is_writable(args.buf):
        return SysError.EFAULT
    data = ""
    if isinstance(handle, handles.SocketHandle):
        return socketcall._recv(k, p, args.fd, args.buf, args.count)
    if isinstance(handle, handles.PipeOutHandle):
        if handle.pipe.is_empty():
            if handle.pipe.write_end_closed:
                return 0  # End-of-file

            def unpause_when():
                return (not handle.pipe.is_empty()) or (
                    handle.pipe.write_end_closed
                )

            k.pause_syscall(p, condition=unpause_when)
            return
        data = handle.read(args.count)
        p.memory.write(args.buf, data)
        return len(data)
    if isinstance(handle, handles.PipeInHandle):
        return SysError.EBADF
    if isinstance(handle, handles.FileHandle) and handle.is_dir:
        return SysError.EISDIR

    try:
        data = handle.read(args.count)
    except PermissionError:
        return SysError.EACCES
    except io.UnsupportedOperation:
        k.logger.error(f"Unable to read file {handle.Name}")
        return SysError.EACCES

    if len(data) == 0:
        return 0
    try:
        p.memory.write(args.buf, data)
    except UcError:
        return SysError.EFAULT

    return len(data)


def sys_pread64(k, p):
    args = k.get_args(
        [
            ("int", "fd"),
            ("void*", "buf"),
            ("size_t", "count"),
            ("off_t", "offset"),
        ]
    )
    handle = k.z.handles.get(args.fd)

    if handle is None:
        return 0
    current_location = handle.seek(0, 1)
    handle.seek(args.offset)
    try:
        data = handle.read(args.count)
    except PermissionError:
        return SysError.EACCES

    handle.seek(current_location)  # Reset the seek to before the read
    p.memory.write(args.buf, data)
    return len(data)


def sys_geteuid32(k, p):
    k.get_args([])
    return 1000


def sys_geteuid(k, p):
    k.get_args([])
    return 0


def sys_getuid32(k, p):
    k.get_args([])
    return 1000


def sys_getegid32(k, p):
    k.get_args([])
    return 0xD11B


def sys_getgid32(k, p):
    k.get_args([])
    return 0xD11B


def sys_getuid(k, p):
    k.get_args([])
    return 0


def sys_getegid(k, p):
    k.get_args([])
    return 0xD11B


def sys_getgid(k, p):
    k.get_args([])
    return 0xD11B


def sys_setpgid(k, p):
    k.get_args([("pid_t", "pid"), ("pid_t", "pgid")])
    return 0


def sys_setgid32(k, p):
    k.get_args([("gid_t", "gid")])
    return 0


def sys_setuid32(k, p):
    k.get_args([("uid_t", "uid")])
    return 0


def sys_setsid(k, p):
    k.get_args([])
    return 0xD00B


def sys_getgroups(k, p):
    k.get_args([("int", "size"), ("gid_t[]", "list")])
    return 0


# There may be a bug in gcc_coreutils_32_o0_tail with this function
def sys__llseek(k, p):
    args = k.get_args(
        [
            ("unsigned int", "fd"),
            ("unsigned long", "offset_high"),
            ("unsigned long", "offset_low"),
            ("loff_t *", "result"),
            ("unsigned int", "whence"),
        ]
    )
    offset = sys_utils.twos_comp(
        (args.offset_high << 32) | args.offset_low, 64
    )
    file_position = xlseek(k, args.fd, offset, args.whence)
    file_position &= 0xFFFFFFFF
    handle = k.z.handles.get(args.fd)
    k.z.logger.debug(f"File {handle.Name} ({args.fd:x}) to {file_position}")
    p.memory.write_int(args.result, file_position)
    return 0


def sys_lseek(k, p):
    args = k.get_args(
        [("unsigned int", "fd"), ("off_t", "offset"), ("int", "whence")]
    )
    offset = p.emu.to_signed(args.offset)
    file_position = xlseek(k, args.fd, offset, args.whence)
    return file_position


def xlseek(k, fd, offset, whence) -> int:
    """
    Returns the offset from the beginning of the file.
    """
    handle = k.z.handles.get(fd)
    if handle is None:
        return
    return handle.seek(offset, whence)


def sys_readlink(k, p):
    args = k.get_args(
        [("const char*", "pathname"), ("char*", "buf"), ("size_t", "bufsiz")]
    )
    # TODO: This is bypassing the filesystem protections, this should not be
    # allowed without doing a validation in the filesystem first
    # TODO: support symbolic links in emulated filesystem.
    # TODO: sanitize request to readlink
    try:
        pathname = p.memory.read_string(args.pathname)
        if pathname == "/proc/self/exe":
            linked_path = "/proc/self/exe"
        else:
            linked_path = os.readlink(pathname)
        s_len = p.memory.write_string(
            args.buf, linked_path, terminal_null_byte=False
        )
        return s_len
    except OSError:
        return -1


def sys_readlinkat(k, p):
    args = k.get_args(
        [
            ("int", "dirfd"),
            ("const char*", "pathname"),
            ("char*", "buf"),
            ("size_t", "bufsiz"),
        ]
    )
    # TODO: support symbolic links in emulated filesystem.
    # TODO: sanitize request to readlink
    try:
        pathname = p.memory.read_string(args.pathname)
        if pathname == "/proc/self/exe":
            linked_path = "/proc/self/exe"
        else:
            linked_path = os.readlink(pathname)
        s_len = p.memory.write_string(
            args.buf, linked_path, terminal_null_byte=False
        )
        return s_len
    except OSError:
        return -1


def sys_getcwd(k, p):
    args = k.get_args([("char*", "buf"), ("size_t", "size")])
    size = p.memory.write_string(args.buf, k.z.files.zelos_file_prefix)

    return size


def sys_faccessat(k, p):
    args = k.get_args(
        [
            ("int", "dirfd"),
            ("const char*", "pathname"),
            ("int", "mode"),
            ("int", "flags"),
        ]
    )
    pathname_s = p.memory.read_string(args.pathname)
    k.z.triggers.tr_file_check(pathname_s)
    retval = -1
    if k.z.files.find_library(pathname_s) is not None:
        retval = 0
    return retval


def sys_access(k, p):
    args = k.get_args([("const char*", "pathname"), ("int", "mode")])
    pathname_s = p.memory.read_string(args.pathname)
    k.z.triggers.tr_file_check(pathname_s)
    retval = -1
    if k.z.files.find_library(pathname_s) is not None:
        retval = 0

    return retval


class FCNTL(enum.IntEnum):
    """
    FCNTL Flags
    https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h
    """

    O_ACCMODE = 0o00000003
    O_RDONLY = 0o00000000
    O_WRONLY = 0o00000001
    O_RDWR = 0o00000002
    O_CREAT = 0o00000100  # /* not fcntl */
    O_EXCL = 0o00000200  # /* not fcntl */
    O_NOCTTY = 0o00000400  # /* not fcntl */
    O_TRUNC = 0o00001000  # /* not fcntl */
    O_APPEND = 0o00002000
    O_NONBLOCK = 0o00004000
    O_DSYNC = 0o00010000  # /* used to be O_SYNC, see below */
    FASYNC = 0o00020000  # /* fcntl, for BSD compatibility */
    O_DIRECT = 0o00040000  # /* direct disk access hint */
    O_LARGEFILE = 0o00100000
    O_DIRECTORY = 0o00200000  # /* must be a directory */
    O_NOFOLLOW = 0o00400000  # /* don't follow links */
    O_NOATIME = 0o01000000
    O_CLOEXEC = 0o02000000  # /* set close_on_exec */
    __O_SYNC = 0o04000000
    O_SYNC = 0o04010000
    O_PATH = 0o10000000
    __O_TMPFILE = 0o20000000
    O_TMPFILE = 0o20200000
    O_TMPFILE_MASK = 0o20200100
    O_NDELAY = 0o00004000


def sys_fcntl64(k, p):
    return sys_fcntl(k, p)


def sys_fcntl(k, p):
    args = k.get_args([("int", "fd"), ("int_FCNTL", "cmd"), ("int", "arg")])
    cmd_name = FCNTL_COMMANDS.get(args.cmd, "unknown")

    if cmd_name == "F_GETFL":
        # return fd flags
        pass
    elif cmd_name == "F_SETFL":
        handle = k.z.handles.get(args.fd)
        if isinstance(handle, handles.SocketHandle):
            handle.socket.set_nonblock(args.arg & FCNTL.O_NONBLOCK != 0)

    return 0


def sys_lstat(k, p):
    return sys_stat(k, p)


def sys_lstat64(k, p):
    return sys_stat64(k, p)


def sys_stat(k, p):
    stat_struct = structs.get_stat_struct(k.arch)
    return _statx(k, p, stat_struct)


def sys_stat64(k, p):
    return _statx(k, p, structs.STAT64())


def _statx(k, p, struct):
    args = k.get_args(
        [("const char*", "pathname"), ("struct stat*", "statbuf")]
    )
    pathname_s = p.memory.read_string(args.pathname)

    library_path = k.z.files.find_library(pathname_s)
    if library_path is None or not path.exists(library_path):
        return -1

    statinfo = os.stat(library_path)

    retval = _fill_out_stat_struct(statinfo, struct)
    p.memory.writestruct(args.statbuf, struct)
    return retval


def sys_fstat(k, p):
    stat_struct = structs.get_stat_struct(k.arch)
    return _fstatx(k, p, stat_struct)


def sys_fstat64(k, p):
    return _fstatx(k, p, structs.STAT64())


def _fstatx(k, p, struct):
    # TODO: Change _fstatx so the real os.stat isn't called, can lead to
    # unintuitive behavior.
    args = k.get_args([("int", "fd"), ("struct stat*", "statbuf")])
    if args.fd in [0, 1, 2]:
        statinfo = os.fstat(args.fd)
    else:
        handle = k.z.handles.get(args.fd)
        if handle is None:
            k.logger.notice("Invalid handle")
            return -1

        library_path = k.z.files.find_library(handle.Name)
        if library_path is None or not path.exists(library_path):
            return -1

        statinfo = os.stat(library_path)
    retval = _fill_out_stat_struct(statinfo, struct)
    if args.fd in [0, 1, 2]:
        # When st_mode is set from os.fstat, you may get different
        # behavior in zelos when redirecting stdout. You probably want
        # consistent behavior instead.
        struct.st_mode = 8592
    p.memory.writestruct(args.statbuf, struct)

    return retval


def _fill_out_stat_struct(statinfo, stat_struct):
    stat_struct.st_dev = statinfo.st_dev
    stat_struct.st_ino = statinfo.st_ino
    stat_struct.st_mode = statinfo.st_mode
    stat_struct.st_nlink = 1
    stat_struct.st_uid = statinfo.st_uid
    stat_struct.st_gid = statinfo.st_gid
    stat_struct.st_rdev = 0
    stat_struct.st_size = statinfo.st_size
    stat_struct.st_blksize = 4096
    stat_struct.st_blocks = statinfo.st_size // 512 + 1
    stat_struct.st_atime = 0x100
    stat_struct.st_atime_nsec = 0x200
    stat_struct.st_mtime = int(statinfo.st_mtime)
    stat_struct.st_mtime_nsec = 0x400
    stat_struct.st_ctime = 0x500
    stat_struct.st_ctime_nsec = 0x600

    return 0


run_once = None

# class DIRENT64(ctypes.Structure):
#     _fields_ = [
#         ('d_ino', ctypes.c_uint64),
#         ('d_off', ctypes.c_uint64),
#         ('d_reclen', ctypes.c_uint16),
#         ('d_type', ctypes.c_ubyte),
#         ('d_name', ctypes.c_char_p), # Unsure how to handle this since
# # its actually a char array, not a pointer to a char array
#     ]


def sys_getdents(k, p):
    args = k.get_args(
        [
            ("unsigned int", "fd"),
            ("struct linux_dirent *", "dirp"),
            ("unsigned int", "count"),
        ]
    )

    handle = k.z.handles.get(args.fd)
    if handle is None:
        return -1

    folder_contents = handle.data.get("dents", None)
    if folder_contents is None:
        # Get the dents and run this function
        folder_contents = k.z.files.list_dir(handle.Name)
    if len(folder_contents) == 0:
        handle.data["dents"] = folder_contents
        return 0

    prev_struct_start = None
    struct_start = args.dirp
    total_bytes_written = 0
    while len(folder_contents) > 0:
        full_name = os.path.join(handle.Name, folder_contents[-1])
        bytes_written = _write_dirent_x86_64(
            k,
            p,
            full_name,
            folder_contents[-1],
            struct_start,
            prev_struct_start,
            args.dirp + args.count,
        )
        if bytes_written == 0:
            break
        else:
            folder_contents.pop()
            total_bytes_written += bytes_written
        prev_struct_start = struct_start
        struct_start = align(struct_start + bytes_written, alignment=0x4)

    handle.data["dents"] = folder_contents
    return total_bytes_written


def _write_dirent_x86_64(
    k, p, full_name, basename, struct_start, prev_struct_start, max_addr
):
    struct_len = align(len(basename) + 2 + 0x12, 4)
    if struct_start + struct_len > max_addr:
        return 0

    library_path = k.z.files.find_library(full_name)
    if library_path is None or not path.exists(library_path):
        return -1

    statinfo = os.stat(library_path)
    p.memory.write_uint64(struct_start, statinfo.st_ino)
    # This will be overridden in the next call to this func
    p.memory.write_uint64(struct_start + 0x8, 0)  # next struct_start
    p.memory.write_uint16(struct_start + 0x10, struct_len)
    p.memory.write_string(
        struct_start + 0x12, basename, terminal_null_byte=True
    )
    p.memory.write_uint8(struct_start + struct_len - 1, 8)  # regular

    if prev_struct_start is not None:
        p.memory.write_uint64(prev_struct_start + 0x8, struct_start)

    return struct_len


def sys_getdents64(k, p):
    global run_once
    if run_once is not None:
        return 0

    args = k.get_args(
        [
            ("unsigned int", "fd"),
            ("struct linux_dirent64 *", "dirp"),
            ("unsigned int", "count"),
        ]
    )
    #    struct linux_dirent64 {
    #        ino64_t        d_ino;    /* 64-bit inode number */
    #        off64_t        d_off;    /* 64-bit offset to next struct */
    #        unsigned short d_reclen; /* Size of this dirent */
    #        unsigned char  d_type;   /* File type */
    #        char           d_name[]; /* Filename (null-terminated) */
    #    };

    p.memory.write_int(args.dirp + 0x0, 56, sz=8)
    p.memory.write_int(args.dirp + 0x8, 0x0, sz=8)

    p.memory.write_int(args.dirp + 0x12, 6, sz=1)
    s_len = p.memory.write_string(args.dirp + 0x13, "FolderContents")
    struct_size = align(0x13 + s_len, 4)

    # val = bytes([0xb + s_len, 0xb + s_len])
    # from zelos.util import p16
    # val2 = p16(0x13+s_len +0x100 )

    # p.memory.write(args.dirp + 0x10, bytes([0x30]))

    p.memory.write_int(args.dirp + 0x10, struct_size, sz=2)
    run_once = 1
    return struct_size


def sys_ftruncate(k, p):
    k.get_args([("int", "fd"), ("off_t", "length")])
    # TODO
    # handle = k.z.handles.get(args.fd)

    return 0


def sys_write(k, p):
    def print_buf(args):
        s = repr(bytes(p.memory.read(args.buf, size=args.count)))[2:-1]
        return f'buf=0x{args.buf:x} ("{s}")'

    args = k.get_args(
        [("int", "fd"), ("const void*", "buf"), ("size_t", "count")],
        arg_string_overrides={"buf": print_buf},
    )

    s = p.memory.read(args.buf, args.count)

    handle = k.z.handles.get(args.fd)
    # Just fake the write if we don't have the handle
    if handle is None:
        return len(s)
    elif isinstance(handle, handles.PipeOutHandle):
        return SysError.EBADF

    if hasattr(handle, "write"):
        handle.write(s)
    else:
        k.z.triggers.tr_file_write(
            f"{type(handle).__name__}, {handle.Name}", s
        )
        if isinstance(handle, handles.SocketHandle):
            payload = p.memory.read(args.buf, args.count)
            sent_bytes = socketcall._send(k, p, args.fd, payload)
            return sent_bytes
        k.print(s)
    return len(s)


def sys_pwrite64(k, p):
    def print_buf(args):
        s = repr(bytes(p.memory.read(args.buf, size=args.count)))[2:-1]
        return f'buf=0x{args.buf:x} ("{s}")'

    args = k.get_args(
        [
            ("int", "fd"),
            ("const void*", "buf"),
            ("size_t", "count"),
            ("off_t", "offset"),
        ],
        arg_string_overrides={"buf": print_buf},
    )
    s = p.memory.read(args.buf, args.count)

    handle = k.z.handles.get(args.fd)
    # Just fake the write if we don't have the handle
    if handle is None:
        return len(s)
    elif isinstance(handle, handles.PipeOutHandle):
        return SysError.EBADF
    current_location = handle.seek(0, 1)
    handle.seek(args.offset)
    if hasattr(handle, "write"):
        size_of_write = handle.write(s)
    handle.seek(current_location)

    return size_of_write


def sys_dup2(k, p):
    args = k.get_args([("int", "oldfd"), ("int", "newfd")])
    handle = k.z.handles.get(args.oldfd)
    if handle is not None:
        k.z.handles.add_handle(handle, args.newfd)
    return args.newfd


def sys_dup3(k, p):
    args = k.get_args([("int", "oldfd"), ("int", "newfd"), ("int", "flags")])
    handle = k.z.handles.get(args.oldfd)
    if handle is not None:
        k.z.handles.add_handle(handle, args.newfd)
    return args.newfd


def sys_pipe2(k, p):
    args = k.get_args([("int[2]", "pipefd"), ("int", "flags")])
    return _pipe(k, p, args.pipefd, args.flags)


def sys_pipe(k, p):
    args = k.get_args([("int[2]", "pipefd")])
    return _pipe(k, p, args.pipefd, None)


def _pipe(k, p, pipefd, flags):
    (out_handle_num, in_handle_num) = k.z.handles.new_pipe("")
    p.memory.write_int(pipefd, out_handle_num)
    p.memory.write_int(pipefd + 4, in_handle_num)  # valid in x64
    k.logger.info(
        f"Pipe handles are out:{out_handle_num:x} in:{in_handle_num:x}"
    )
    return 0


def sys_ipc(k, p):
    k.get_args(
        [
            ("unsigned int", "call"),
            ("int", "first"),
            ("int", "second"),
            ("int", "third"),
            ("void *", "ptr"),
            ("long", "fifth"),
        ]
    )
    return -1


def sys_socketcall(k, p):
    args = k.get_args([("int", "call"), ("unsigned long *", "callargs")])
    socket_dict = {
        1: socketcall.socket,
        2: socketcall.bind,
        3: socketcall.connect,
        4: socketcall.listen,
        5: socketcall.accept,
        6: socketcall.getsockname,
        7: socketcall.getpeername,
        8: socketcall.socketpair,
        9: socketcall.send,
        10: socketcall.recv,
        11: socketcall.sendto,
        12: socketcall.recvfrom,
        13: socketcall.shutdown,
        14: socketcall.setsockopt,
        15: socketcall.getsockopt,
        16: socketcall.sendmsg,
        17: socketcall.recvmsg,
        18: socketcall.accept4,
        19: socketcall.recvmmsg,
        20: socketcall.sendmmsg,
    }
    retval = socket_dict[args.call](k, p, args.callargs)
    return retval


def sys_socket(k, p):
    return socketcall.socket(k, p, -1)


def sys_bind(k, p):
    return socketcall.bind(k, p, -1)


def sys_connect(k, p):
    return socketcall.connect(k, p, -1)


def sys_listen(k, p):
    return socketcall.listen(k, p, -1)


def sys_accept(k, p):
    return socketcall.accept(k, p, -1)


def sys_getsockname(k, p):
    return socketcall.getsockname(k, p, -1)


def sys_getpeername(k, p):
    return socketcall.getpeername(k, p, -1)


def sys_socketpair(k, p):
    return socketcall.socketpair(k, p, -1)


def sys_send(k, p):
    return socketcall.send(k, p, -1)


def sys_recv(k, p):
    return socketcall.recv(k, p, -1)


def sys_sendto(k, p):
    return socketcall.sendto(k, p, -1)


def sys_recvfrom(k, p):
    return socketcall.recvfrom(k, p, -1)


def sys_shutdown(k, p):
    return socketcall.shutdown(k, p, -1)


def sys_setsockopt(k, p):
    return socketcall.setsockopt(k, p, -1)


def sys_getsockopt(k, p):
    return socketcall.getsockopt(k, p, -1)


def sys_sendmsg(k, p):
    return socketcall.sendmsg(k, p, -1)


def sys_recvmsg(k, p):
    return socketcall.recvmsg(k, p, -1)


def sys_accept4(k, p):
    return socketcall.accept4(k, p, -1)


def sys_recvmmsg(k, p):
    return socketcall.recvmmsg(k, p, -1)


def sys_sendmmsg(k, p):
    return socketcall.sendmmsg(k, p, -1)


class CLONE(enum.IntEnum):
    """
    Cloning Flags
    https://github.com/torvalds/linux/blob/master/include/uapi/linux/sched.h
    """

    VM = 0x00000100
    FS = 0x00000200
    FILES = 0x00000400
    SIGHAND = 0x00000800
    PIDFD = 0x00001000
    PTRACE = 0x00002000
    VFORK = 0x00004000
    PARENT = 0x00008000
    THREAD = 0x00010000
    NEWNS = 0x00020000
    SYSVSEM = 0x00040000
    SETTLS = 0x00080000
    PARENT_SETTID = 0x00100000
    CHILD_CLEARTID = 0x00200000
    DETACHED = 0x00400000
    UNTRACED = 0x00800000
    CHILD_SITTID = 0x01000000
    NEWCGROUP = 0x02000000
    NEWUTS = 0x04000000
    NEWIPC = 0x08000000
    NEWUSER = 0x10000000
    NEWPID = 0x20000000
    NEWNET = 0x40000000
    IO = 0x80000000


def sys_clone(k, p):
    if k.arch == "x86_64":
        args = k.get_args(
            [
                ("unsigned long", "flags"),
                ("void*", "child_stack"),
                ("int*", "ptid"),
                ("int*", "ctid"),
                ("unsigned long", "newtls"),
            ]
        )
    else:
        args = k.get_args(
            [
                ("unsigned long", "flags"),
                ("void*", "child_stack"),
                ("int*", "ptid"),
                ("unsigned long", "newtls"),
                ("int*", "ctid"),
            ]
        )

    child = _new_process(k, p, flags=args.flags)
    try:
        child.memory.write_uint32(args.ctid, child.pid)
    except Exception:
        pass

    # def swap():
    #     k.z.processes.load_process(child.pid)

    # p.scheduler.stop_and_exec("process swap", swap)
    return child.pid


def sys_fork(k, p):
    k.get_args([])

    child_process = _new_process(k, p, CLONE.FILES)
    return child_process.pid


def _new_process(k, p, flags=0x0):
    processes = k.z.processes
    child_pid = processes.new_process()
    child = processes.get_process(child_pid)

    if flags & CLONE.VM > 0:
        # Share memory
        # TODO: Why isn't this working?
        # child.memory = p.memory
        child.memory.copy(p.memory)
    else:
        # duplicate the state of the target process.
        child.memory.copy(p.memory)

    parent_handles = k.z.handles._all_handles(p.pid)
    for num, h in parent_handles:
        k.z.handles.add_handle(h, handle_num=num, pid=child.pid)

    # Create this same thread inside the process
    current_thread = p.current_thread
    child.new_thread(
        k.return_addr(),
        priority=current_thread.priority,
        module_path=current_thread.module_path,
    )
    child.threads.swap_with_next_thread()
    p.current_thread.save_context()
    child.emu.context_restore(p.current_thread.context)
    child.emu.setIP(k.return_addr())
    processes._as_current_process(child, lambda: k.set_return_value(0))
    child.current_thread.save_context()

    return child


# temporary implementation
# @@TODO: handle correctly (parent has to be suspended until
#   child finishes)


def sys_vfork(k, p):
    k.get_args([])
    current_thread_priority = p.current_thread.priority
    t = k.z.processes.new_thread_for_current_process(
        k.return_addr(),
        module_path=p.current_thread.module_path,
        priority=current_thread_priority + 1,
    )

    def thread_swap():
        p.threads.swap_with_thread(tid=t.id)
        k.set_return_value(0)

    p.scheduler.stop_and_exec("thread swap", thread_swap)
    return t.id


def sys_pause(k, p):
    k.get_args([])
    return SysError.EINTR


def sys_wait4(k, p):
    args = k.get_args(
        [
            ("pid_t", "pid"),
            ("int*", "wstatus"),
            ("int", "options"),
            ("struct rusage*", "rusage"),
        ]
    )
    state_changes = k.child_state_changes[p.pid]
    if len(state_changes) > 0:
        if args.pid in [0, 0xFFFFFFFF]:
            return state_changes.pop(0)
        if args.pid in state_changes:
            return state_changes.pop(state_changes.index(args.pid))

    # Wait for any children.
    if args.pid in [0, 0xFFFFFFFF]:
        children = p.get_child_processes()
        if len(children) == 0:
            k.logger.notice(
                f"Can't wait on id {args.pid}, "
                f"couldn't find corresponding thread"
            )
            return SysError.ECHILD

        active_children = [c for c in children if c.is_active]
        if len(active_children) == 0:
            return SysError.ECHILD

        def unpause_when():
            for child in active_children:
                if not child.is_active:
                    return True
            return False

        k.pause_syscall(p, condition=unpause_when)
        # TODO: Should be returning the newly paused thread's pid
        return 0

    target_thread = k.z.processes.get_thread(args.pid)
    if target_thread is None:
        k.logger.notice(
            f"Can't wait on id {args.pid}, "
            f"couldn't find corresponding thread"
        )
        return 0
    # (V) If this thread waits on itself... uh... unsure what to do.
    # Reduce its priority so other threads finish before coming back.
    if target_thread.id == p.current_thread.id:
        target_thread.priority -= 1
        p.scheduler.stop_and_exec(
            "process swap", k.z.processes.swap_with_next_thread
        )
    else:

        def unpause_when():
            return target_thread.state != ThreadState.RUNNING

        p.threads.pause_current_thread(condition=unpause_when)
    return args.pid


def sys_sched_getscheduler(k, p):
    k.get_args([("pid_t", "pid")])
    return 1


def sys_sched_getaffinity(k, p):
    k.get_args(
        [("pid_t", "pid"), ("size_t", "cpusetsize"), ("cpu_set_t *", "mask")]
    )
    return -1


def sys_execve(k, p):
    def print_argv(args):
        vals = get_pchar_array(k.z, args.argv)
        s = " ".join(vals)
        return f'*argv=0x{args.argv:x} ("{s}")'

    def print_envp(args):
        vals = get_pchar_array(k.z, args.envp)
        s = " ".join(vals)
        return f'*envp=0x{args.envp:x} ("{s}")'

    args = k.get_args(
        [
            ("const char*", "pathname"),
            ("char *const", "argv"),
            ("char *const", "envp"),
        ],
        arg_string_overrides={"argv": print_argv, "envp": print_envp},
    )

    argv = get_pchar_array(k.z, args.argv)
    envp = get_pchar_array(k.z, args.envp)
    pathname = p.memory.read_string(args.pathname)

    k.logger.debug("Replacing first argument with pathname")
    if len(argv) > 0:
        argv[0] = pathname

    # FIXME: execve is not working. It executes the main binary's
    #  entrypoint again.
    return

    p.memory.clear()

    p.cmdline_args = argv
    p.environment_variables = envp

    # You can also exec shell files
    try:
        with open(pathname, "rb") as f:
            string = f.readline()
            if string.startswith(b"#! /bin/sh"):
                p.cmdline_args.insert(0, "/bin/sh")
                pathname = "/bin/sh"
    except FileNotFoundError:
        pass
    except PermissionError:
        return SysError.EACCES

    try:
        file = k.z.parse_file(pathname)
        k.z.files.add_file(pathname)
    except ZelosLoadException:
        return SysError.ENOENT

    k.z.os_plugins.load(file, k.z.current_process)

    # If this is successful, this thread essentially ends.
    # TODO: we should have a list of things that can be execve'd, to
    # make this configurable
    p.scheduler.stop_and_exec(
        "execve thread", p.threads.complete_current_thread
    )
    return


def sys_exit(k, p):
    return sys_exit_group(k, p)


def sys_exit_group(k, p):
    args = k.get_args([("int", "status")])

    k.z.processes.handles.close_all(p.pid)

    def exit_thread():
        if args.status == 0:
            p.threads.complete_current_thread()
        else:
            p.threads.fail_current_thread(
                fail_reason=f"syscall Exit_Group status {args.status}"
            )

    p.scheduler.stop_and_exec("exit thread", exit_thread)

    if p.parent_pid is not None:
        parent = k.z.processes.get_process(p.parent_pid)
        k.child_state_changes[parent.pid].append(p.pid)
        # parent.signals.handle_signal(17)


def sys_time(k, p):
    args = k.get_args([("time_t*", "tloc")])
    current_time = time.mktime(
        datetime.datetime.strptime(k.z.date, "%Y-%m-%d").timetuple()
    )
    current_time = round(current_time)
    if args.tloc != 0:
        p.memory.write_int(args.tloc, current_time)
    return current_time


def sys_gettimeofday(k, p):
    args = k.get_args([("struct timeval*", "tv"), ("struct timezone*", "tz")])
    if not args.tv:
        return 0
    current_time = time.mktime(
        datetime.datetime.strptime(k.z.date, "%Y-%m-%d").timetuple()
    )
    second, microsecond = str(current_time).split(".")
    try:
        p.memory.write_uint32(args.tv + 0x0, int(second))
        p.memory.write_uint32(args.tv + 0x4, int(microsecond))
        return 0
    except Exception:
        pass

    return -1


def sys_clock_gettime(k, p):
    args = k.get_args([("clockid_t", "clk_id"), ("struct timespec *", "res")])
    current_time = time.mktime(
        datetime.datetime.strptime(k.z.date, "%Y-%m-%d").timetuple()
    )
    second, microsecond = str(current_time).split(".")
    try:
        p.memory.write_uint32(args.res + 0x0, int(second))
        p.memory.write_uint32(args.res + 0x4, int(microsecond))
        return 0
    except Exception:
        pass
    return -1


def sys_set_robust_list(k, p):
    k.get_args([("struct robust_list_head *", "head"), ("size_t", "len")])
    return 0


def sys_set_tid_address(k, p):
    k.get_args([("int*", "tidptr")])
    return p.current_thread.id


def sys_getpid(k, p):
    k.get_args([])
    return p.pid


def sys_getppid(k, p):
    k.get_args([])
    return p.parent_pid


def sys_times(k, p):
    k.get_args([("struct tms*", "buf")])
    #    struct tms {
    #        clock_t tms_utime;  /* user time */
    #        clock_t tms_stime;  /* system time */
    #        clock_t tms_cutime; /* user time of children */
    #        clock_t tms_cstime; /* system time of children */
    #    };
    return 0xDEED


class __SYSCTL_ARGS(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_uint32),  # integer vector describing variable
        ("nlen", ctypes.c_uint32),  # length of this vector
        ("oldval", ctypes.c_uint32),  # 0 or address where to store old value
        # available room for old value, overwritten by size of old value
        ("oldlenp", ctypes.c_uint32),
        ("newval", ctypes.c_uint32),  # 0 or address of new value */
        ("newlen", ctypes.c_uint32),  # size of new value */)
    ]


def sys__sysctl(k, p):
    args = k.get_args([("struct __sysctl_args*", "sys_args")])
    __sysctl_args = ptr2struct(k.z, args.sys_args, __SYSCTL_ARGS)
    dumpstruct(__sysctl_args)
    return 0


class IOCTLS(enum.IntEnum):
    """
    IOCTL INTERNAL (PARTIAL)
    https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/ioctls.h
    """

    FIONREAD = 0x541B


def sys_ioctl(k, p):
    args = k.get_args(
        [("int", "fd"), ("unsigned long", "request"), ("void *", "data")]
    )

    k.z.handles.get(args.fd)
    if args.data == 0:
        return -1

    data = p.memory.read_uint32(args.data)
    k.print(f"IOCTL: {data}")

    handle = k.z.handles.get(args.fd)
    if isinstance(handle, handles.SocketHandle):
        FIONBIO = 0x5421
        FIONREAD = 0x541B
        if args.request == FIONBIO:
            handle.socket.set_nonblock(data)
            return 0
        elif args.request == FIONREAD:
            sock_data = handle.socket.peek()
            len_avail = len(sock_data)
            p.memory.write_uint32(args.data, len_avail)
            return 1

    return -1


def sys_arch_prctl(k, p):
    args = k.get_args(
        [("int_ARCH_PRCTL", "option"), ("unsigned long", "addr")]
    )
    if args.option == 0x1001:
        sys_utils.set_gs(p, args.addr)
    elif args.option == 0x1002:
        sys_utils.set_fs(p, args.addr)

    return 0


def sys_prctl(k, p):
    args = k.get_args(
        [
            ("int", "option"),
            ("unsigned long", "arg2"),
            ("unsigned long", "arg3"),
            ("unsigned long", "arg4"),
            ("unsigned long", "arg5"),
        ]
    )

    if args.option == PRCTL.PR_SET_NAME:
        proc_name = p.memory.read_string(args.arg2)
        k.print(f"PRCTL[PR_SET_NAME]: setting process name to [{proc_name}]")

    return 0


def sys_umask(k, p):
    k.get_args([("mode_t", "mask")])
    return 0o777


def sys_statfs(k, p):
    args = k.get_args([("const char*", "path"), ("struct statfs *", "buf")])
    statfs = structs.STATFS()
    statfs.f_bsize = 0x1000
    statfs.f_frsize = 0x1000
    statfs.f_namemax = 0x8F
    p.memory.writestruct(args.buf, statfs)
    return 0


def sys_alarm(k, p):
    args = k.get_args([("unsigned int", "seconds")])
    return args.seconds


def sys_rt_sigaction(k, p):
    args = k.get_args(
        [
            ("int", "signum"),
            ("const sigaction*", "act"),
            ("struct sigaction *", "oldact"),
        ]
    )
    if args.act != 0:
        new_sigaction = p.memory.readstruct(args.act, structs.SIGACTION())
        p.zos.signals.set_signal_action(args.signum, new_sigaction.sa_handler)
    return 0


def sys_rt_sigprocmask(k, p):
    args = k.get_args(
        [
            ("int", "how"),
            ("const kernel_sigset_t*", "set"),
            ("kernel_sigset_t *", "oldset"),
            ("size_t", "sigsetsize"),
        ]
    )
    old_signal_mask = p.zos.signals.get_signal_mask()
    if args.oldset != 0:
        p.memory.write_uint32(args.oldset, old_signal_mask)
    if args.set != 0:
        sigset = p.memory.read_uint32(args.set)

        if args.how == 0:  # SIG_BLOCK
            new_signal_mask = old_signal_mask | sigset
        elif args.how == 1:  # SIG_UNBLOCK
            new_signal_mask = old_signal_mask & ~sigset
        elif args.how == 2:  # SIG_SETMASK
            new_signal_mask = sigset

        p.zos.signals.set_signal_mask(new_signal_mask)

    # TODO: Attempt to handle any signals that are no longer blocked.
    # p.zos.signals.handle_signal_queue()
    return 0


class RLIMIT(ctypes.Structure):
    _fields_ = [("rlim_cur", ctypes.c_uint32), ("rlim_max", ctypes.c_uint32)]


def sys_ugetrlimit(k, p):
    args = k.get_args([("int", "resource"), ("struct rlimit*", "rlim")])
    rlimit = RLIMIT()
    RLIM_INFINITY = 0xFFFFFFFF
    rlimit.rlim_cur = RLIM_INFINITY
    rlimit.rlim_max = RLIM_INFINITY
    data = struct2str(rlimit)
    p.memory.write(args.rlim, bytes(data))
    return 0


def sys_setrlimit(k, p):
    k.get_args([("int", "resource"), ("const struct rlimit *", "rlim")])
    return 0


def sys_prlimit64(k, p):
    k.get_args(
        [
            ("pid_t", "pid"),
            ("int", "resource"),
            ("const struct rlimit *", "rlim"),
            ("struct rlimit*", "old_limit"),
        ]
    )
    return 0


def _read_fd_set(k, p, fd_set_ptr):
    if fd_set_ptr == 0:
        return []
    fds = []
    for i in range(0, 1024 // 8, 32 // 8):
        val = p.memory.read_uint32(fd_set_ptr + i)
        for bit in range(32):
            if val & 2 ** bit != 0:
                fds.append((i // 4) * 32 + bit)
    return fds


def _write_fd_set(k, p, fd_set_ptr, fds):
    if fd_set_ptr == 0:
        return
    for i in range(0, 1024 // 8, 32 // 8):
        val = int(0)
        for bit in range(32):
            fd = (i // 4) * 32 + bit
            if fd in fds:
                val |= 1 << bit
        p.memory.write_uint32(fd_set_ptr + i, val)


def sys_select(k, p):
    return sys__newselect(k, p)


def sys__newselect(k, p):
    args = k.get_args(
        [
            ("int", "nfds"),
            ("fd_set*", "readfds"),
            ("fd_set*", "writefds"),
            ("fd_set*", "exceptfds"),
            ("struct timeval*", "timeout"),
        ]
    )
    # Get the set(s) of FDs requested
    readfds = _read_fd_set(k, p, args.readfds)
    writefds = _read_fd_set(k, p, args.writefds)
    exceptfds = _read_fd_set(k, p, args.exceptfds)

    # Dump FD sets
    if len(readfds) > 0:
        k.print(f"readfds: {', '.join([hex(x) for x in readfds])}")
    if len(writefds) > 0:
        k.print(f"writefds: {', '.join([hex(x) for x in writefds])}")
    if len(exceptfds) > 0:
        k.print(f"exceptfds: {', '.join([hex(x) for x in exceptfds])}")

    # Select is only supported on sockets right now. Always
    # return 'ready' for all other types of FDs
    sockets = k.z.network.handles.get_by_type(handles.SocketHandle)
    if len(sockets) == 0:
        return len(readfds) + len(writefds) + len(exceptfds)

    # Perform the select implemented by socket
    (in_ready, out_ready, ex_ready) = k.z.network.select.select(
        readfds, writefds, exceptfds, timeout=0.1
    )

    # Dump FD sets that were signalled
    if len(in_ready) > 0:
        k.print(f"signaled readfds: {', '.join([hex(x) for x in in_ready])}")
    if len(out_ready) > 0:
        k.print(f"signaled writefds: {', '.join([hex(x) for x in out_ready])}")
    if len(ex_ready) > 0:
        k.print(f"signaled exceptfds: {', '.join([hex(x) for x in ex_ready])}")

    # Selectively set only the FDs that were signalled
    _write_fd_set(k, p, args.readfds, in_ready)
    _write_fd_set(k, p, args.writefds, out_ready)
    _write_fd_set(k, p, args.exceptfds, ex_ready)

    count = len(in_ready) + len(out_ready) + len(ex_ready)

    return count


def sys_futex(k, p):
    args = k.get_args(
        [
            ("int*", "uaddr"),
            ("int", "futex_op"),
            ("int", "val"),
            # or: uint32_t val2
            ("const struct timespec*", "timeout"),
            ("int*", "uaddr2"),
            ("int", "val3"),
        ]
    )
    operation = args.futex_op & 0xF
    if operation == 1:
        # Futex wake
        # This should be implemented through shared memory?

        # TODO: The number of waiting threads that will be awoken is
        #       determined by args.val: How to communicate this to the
        #       waiting threads?
        # p.memory.write_uint32(args.uaddr, args.val)

        return 1  # Number of waiters woken
    if operation == 0:
        # Futex wait
        # Will resume when expected value changes

        return 0
    if operation == 9:
        mem_val = p.memory.read_uint32(args.uaddr)
        if mem_val == args.val:
            return 0
        return -1  # They need to be the same when this operation starts
    return 0


def sys_nanosleep(k, p):
    k.get_args(
        [("const struct timespec*", "req"), ("struct timespec *", "rem")]
    )
    return 0


def sys_chmod(k, p):
    k.get_args([("const char*", "pathname"), ("mode_t", "mode")])
    return 0


def sys_chown(k, p):
    k.get_args(
        [("const char*", "pathname"), ("uid_t", "owner"), ("gid_t", "group")]
    )
    return 0


def sys_chdir(k, p):
    k.get_args([("const char*", "pathname")])
    return 0


def sys_mkdir(k, p):
    k.get_args([("const char*", "pathname"), ("mode_t", "mode")])
    return 0


def sys_rmdir(k, p):
    k.get_args([("const char*", "pathname")])
    return 0


# technically, single-threaded process should return pid


def sys_gettid(k, p):
    k.get_args([])
    return p.current_thread.id


def sys_mincore(k, p):
    k.get_args(
        [("void*", "addr"), ("size_t", "length"), ("unsigned char*", "vec")]
    )
    return -1


def sys_fadvise64(k, p):
    k.get_args(
        [
            ("int", "fd"),
            ("off_t", "offset"),
            ("off_t", "len"),
            ("int", "advice"),
        ]
    )
    return 0


def sys_sigaltstack(k, p):
    k.get_args([("stack_t*", "ss"), ("stack_t*", "oldss")])
    return 0


def sys_kill(k, p):
    args = k.get_args([("pid_t", "pid"), ("int", "sig")])
    if args.pid in [-1, 0xFFFFFFFF, 0, 1]:
        # TODO handle these cases.
        return -1
    process = k.z.processes.get_process(args.pid)
    if process is None:
        return SysError.ESRCH

    try:
        Signal(args.sig)
    except ValueError:
        return SysError.EINVAL

    process.zos.signals.handle_signal(args.sig)

    # if args.pid == 0:
    #     current_tid = p.current_thread.id
    #     for child in p.threads.get_child_threads(current_tid):
    #         p.threads.kill_thread(child.id)
    # if 0 < args.pid and args.pid <= 0xffff:
    #     k.z.processes.kill_process(args.pid)
    return 0


def sys_tgkill(k, p):
    k.get_args([("int", "tgid"), ("int", "tid"), ("int", "sig")])
    return 0


class POLL(enum.IntFlag):
    """
    POLL INTERNAL
    https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/poll.h
    """

    POLLIN = 0x0001
    POLLPRI = 0x0002
    POLLOUT = 0x0004
    POLLERR = 0x0008
    POLLHUP = 0x0010
    POLLNVAL = 0x0020
    POLLRDNORM = 0x0040
    POLLRDBAND = 0x0080
    POLLWRNORM = 0x0100
    POLLWRBAND = 0x0200
    POLLMSG = 0x0400
    POLLREMOVE = 0x1000
    POLLRDHUP = 0x2000


class POLLFD(ctypes.Structure):
    _fields_ = [
        ("fd", ctypes.c_int32),
        ("events", ctypes.c_short),
        ("revents", ctypes.c_short),
    ]


def sys_poll(k, p):
    args = k.get_args(
        [("struct pollfd *", "fds"), ("nfds_t", "nfds"), ("int", "timeout")]
    )
    # parse the file descriptors of interest
    sz = ctypes.sizeof(POLLFD())
    fds = {}
    for i in range(args.nfds):
        pollfd = POLLFD()
        fd_addr = args.fds + i * sz
        pollfd_data = p.memory.read(fd_addr, sz)
        str2struct(pollfd, bytes(pollfd_data))
        fds[fd_addr] = pollfd

    fds_poll = [(v.fd, v.events) for k, v in fds.items()]

    e = ", ".join([f"fd={x[0]:x} events={repr(POLL(x[1]))}" for x in fds_poll])
    k.print("polled_fds: " + e)

    revents = k.z.network.select.poll(fds_poll, timeout=0.1)

    e = ", ".join([f"fd={x[0]:x} events={repr(POLL(x[1]))}" for x in revents])
    k.print("signaled_fds: " + e)

    # commit pollfd struct changes
    ready_fds = 0
    for i in range(len(fds_poll)):
        revent = revents[i][1]
        if revent >= 0:
            fd_addr = args.fds + i * sz
            v = fds[fd_addr]
            v.revents = revent
            pollfd_data = struct2str(v)
            p.memory.write(fd_addr, struct2str(v))
            ready_fds += 1

    return ready_fds
