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


# Validated on x64
class SIGACTION(ctypes.Structure):
    _fields_ = [
        ("sa_handler", ctypes.c_uint64),
        ("sa_flags", ctypes.c_uint64),
        ("sa_restorer", ctypes.c_uint64),
        ("sa_mask", ctypes.c_uint64),
    ]


class IOVEC(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_uint64), ("iov_len", ctypes.c_uint64)]


class MSGHDR(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_uint64),
        ("msg_namelen", ctypes.c_uint64),
        ("msg_iov", ctypes.c_uint64),
        ("msg_iovlen", ctypes.c_uint64),
        ("msg_control", ctypes.c_uint64),
        ("msg_controllen", ctypes.c_uint64),
        ("msg_flags", ctypes.c_uint64),
    ]


class MMSGHDR(ctypes.Structure):
    _fields_ = [("msg_hdr", MSGHDR), ("msg_len", ctypes.c_uint64)]


def get_stat_struct(arch):
    if arch == "arm":
        return ARMSTAT()
    else:
        return STAT()


class ARMSTAT(ctypes.Structure):
    # This is intended for the arm architecture.
    # Retrieved from arm-linux-gnueabi/include/asm/stat
    _fields_ = [
        ("st_dev", ctypes.c_uint32),  # integer vector describing variable */
        ("st_ino", ctypes.c_uint32),  # length of this vector */
        (
            "st_mode",
            ctypes.c_uint16,
        ),  # 0 or address where to store old value */
        # Note nlink and mode are switched for arm...
        ("st_nlink", ctypes.c_uint16),
        ("st_uid", ctypes.c_uint16),
        ("st_gid", ctypes.c_uint16),
        ("st_rdev", ctypes.c_uint32),
        ("st_size", ctypes.c_uint32),
        ("st_blksize", ctypes.c_int32),
        ("st_blocks", ctypes.c_int32),
        ("st_atime", ctypes.c_int32),
        ("st_atime_nsec", ctypes.c_uint32),
        ("st_mtime", ctypes.c_int32),
        ("st_mtime_nsec", ctypes.c_uint32),
        ("st_ctime", ctypes.c_int32),
        ("st_ctime_nsec", ctypes.c_uint32),
        # ('__unused4', ctypes.c_uint32),
        # ('__unused5', ctypes.c_uint32),
    ]


class STAT(ctypes.Structure):
    # This is intended for 64 bit architectures.
    # https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/stat.h
    _fields_ = [
        ("st_dev", ctypes.c_uint64),  # integer vector describing variable */
        ("st_ino", ctypes.c_uint64),  # length of this vector */
        ("st_nlink", ctypes.c_uint64),
        (
            "st_mode",
            ctypes.c_uint32,
        ),  # 0 or address where to store old value */
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("__pad0", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("st_size", ctypes.c_uint64),
        ("st_blksize", ctypes.c_int32),
        ("st_blocks", ctypes.c_int64),
        ("st_atime", ctypes.c_int64),
        ("st_atime_nsec", ctypes.c_uint64),
        ("st_mtime", ctypes.c_int64),
        ("st_mtime_nsec", ctypes.c_uint64),
        ("st_ctime", ctypes.c_int64),
        ("st_ctime_nsec", ctypes.c_uint64),
        # ('__unused4', ctypes.c_uint32),
        # ('__unused5', ctypes.c_uint32),
    ]


class STAT64(ctypes.Structure):
    # Used on 32 bit systems
    # https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/stat.h
    _fields_ = [
        ("st_dev", ctypes.c_uint64),  # integer vector describing variable */
        ("__pad0", ctypes.c_uint32),
        ("st_ino", ctypes.c_uint32),  # length of this vector */
        (
            "st_mode",
            ctypes.c_uint32,
        ),  # 0 or address where to store old value */
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("__pad1", ctypes.c_uint32),
        ("st_size", ctypes.c_int32),
        ("st_blksize", ctypes.c_int32),
        ("__pad2", ctypes.c_int32),  # 0 or address of new value */
        ("st_blocks", ctypes.c_int64),
        ("st_atime", ctypes.c_int32),
        ("st_atime_nsec", ctypes.c_uint32),
        ("st_mtime", ctypes.c_int32),
        ("st_mtime_nsec", ctypes.c_uint32),
        ("st_ctime", ctypes.c_int32),
        ("st_ctime_nsec", ctypes.c_uint32),
        # ('__unused4', ctypes.c_uint32),
        # ('__unused5', ctypes.c_uint32),
    ]
