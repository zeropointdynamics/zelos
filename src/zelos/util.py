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
import struct
import time

from io import BytesIO


def p8(x):
    return struct.pack("<B", x)


def u8(x):
    return struct.unpack("<B", x)[0]


def p16(x):
    return struct.pack("<H", x)


def u16(x):
    return struct.unpack("<H", x)[0]


def p32(x):
    return struct.pack("<I", x)


def u32(x):
    return struct.unpack("<I", x)[0]


def p64(x):
    return struct.pack("<Q", x)


def u64(x):
    return struct.unpack("<Q", x)[0]


def align(addr, alignment=0x1000):
    # rounds up to nearest alignment
    mask = ((1 << 64) - 1) & -alignment
    return (addr + (alignment - 1)) & mask


def align_down(addr, alignment=0x1000):
    # rounds down to nearest alignment
    mask = ((1 << 64) - 1) & -alignment
    return addr & mask


def struct2str(s):
    return BytesIO(s).read()


def str2struct(struct_obj, data):
    # Read the given data into the given initialized Structure
    fit = min(len(data), ctypes.sizeof(struct_obj))
    ctypes.memmove(ctypes.addressof(struct_obj), bytes(data), fit)


def dumpstruct(struct_obj, indent_level=0):
    indent = "  " * indent_level
    for field in struct_obj._fields_:
        val = getattr(struct_obj, field[0])
        try:
            val = hex(val)
        except Exception:
            pass
        print(f"{indent}{field[0]}: {val}")


def columnate(input_list, num_columns, delimiter=", "):
    """Prints a list of values in a desired number of columns"""
    lines = []
    for i in range(0, len(input_list), num_columns):
        line_data = input_list[i : i + num_columns]
        lines.append(delimiter.join(line_data))
    return "\n".join(lines)


class Timer:
    def __init__(self):
        self.start = 0
        self.timeout = 0

    def begin(self, timeout):
        self.start = time.time()
        self.timeout = timeout

    # Warning to those trying to make this work by sleeping in another
    # thread. It didn't work. Please make tests when changing this
    # implementation.
    def is_timed_out(self):
        if self.timeout == 0:
            return False
        time_elapsed = time.time() - self.start
        if time_elapsed < self.timeout:
            return False
        # Disable the timeout until someone specifies a timeout again.
        self.start = 0
        self.timeout = 0
        return True


# This key is not intended for security, this is so that we can upload
# malware to our build server and not worry about AV engines and the
# like
ENCRYPTION_KEY = 0xAF


def file_encrypt(filename):
    """ Encrypt malware so it doesn't cause issues with AV"""
    with open(filename, "rb") as f:
        file_data = bytearray(f.read())
    encrypted_data = bytearray([byte ^ ENCRYPTION_KEY for byte in file_data])
    with open("{0}.zenc".format(filename), "wb") as f:
        f.write(b"ZENC" + encrypted_data)


def in_mem_decrypt(filedata):
    """ Decrypt malware in memory"""
    assert filedata.startswith(
        b"ZENC"
    ), "Attempted to decrypt an unencrypted input file"
    filedata = filedata[len("ZENC") :]
    decrypted_data = [byte ^ ENCRYPTION_KEY for byte in filedata]
    return decrypted_data


def found_domain(z, domain):
    return domain in z.network.attempted_connections
