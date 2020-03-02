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

from ..signals import Signal, sigmask_string
from .syscall_utils import twos_comp
from .syscalls_const import (
    ARCH_PRCTL_OPTIONS,
    FCNTL_COMMANDS,
    protocol_families,
)


def get_arg_string(z, arg):
    type_str = arg.type
    name = arg.name
    val = arg.value
    val_s = ""
    if type_str in [
        "LPCSTR",
        "const char*",
        "LPCCH",
        "PCHAR",
        "LPTSTR",
        "LPSTR",
        "PCSTR",
        "const void*",
    ]:
        val_s = z.memory.read_string(val)
        val_s = repr(bytes(val_s, "utf8"))[2:-1]
        arg_string = '{0}=0x{1:x} ("{2}")'.format(name, val, val_s)
    elif type_str in ["LPCWSTR", "PCWSTR", "PCWCH", "LPCTSTR"]:
        val_s = z.memory.read_wstring(val)
        val_s = repr(bytes(val_s, "utf8"))[2:-1]
        arg_string = '{0}=0x{1:x} ("{2}")'.format(name, val, val_s)
    elif type_str in ["DWORD*"]:
        val_pointed_to = z.memory.read_int(val) if val != 0 else 0
        arg_string = "*{0}=0x{1:x} ({2})".format(name, val, val_pointed_to)
    elif name == "sockfd":
        socket_handle = z.handles.get(val)
        socket_name = ""
        if socket_handle is not None:
            if hasattr(socket_handle, "socket"):
                sock = socket_handle.socket
                domain = str(sock.domain).split(".")[1]
                sock_type = str(sock.type).split(".")[1]
                host = sock.host_and_port[0]
                if host is None:
                    host = "?"
                port = sock.host_and_port[1]
                if port is None:
                    port = "?"
                socket_name = f" ({domain}:{sock_type}:{host}:{str(port)})"
            else:
                socket_name = (
                    " (" + socket_handle.data.get("dst_name", "?") + ")"
                )
        arg_string = "{0}=0x{1:x}{2}".format(name, val, socket_name)
    elif type_str in ["int_DOMAIN"]:
        family = protocol_families[val]
        arg_string = f"{name}=0x{val:x} ({family})"
    elif type_str in ["int_FCNTL"]:
        cmd_name = FCNTL_COMMANDS.get(val, "unknown")
        arg_string = f"{name}=0x{val:x} ({cmd_name})"
    elif type_str in ["off_t"]:
        val = twos_comp(val, z.state.bits)
        arg_string = f"{name}=0x{val:x}"
    elif type_str in ["pid_t"]:
        if val > 0xFFFFF:
            val = twos_comp(val, 32)
        arg_string = f"{name}=0x{val:x}"
    elif type_str in ["int_ARCH_PRCTL"]:
        cmd_name = ARCH_PRCTL_OPTIONS.get(val, "unknown")
        arg_string = f"{name}=0x{val:x} ({cmd_name})"
    elif name in ["signum"]:
        try:
            signal_name = Signal(val).name
        except Exception:
            signal_name = "unknown"
        arg_string = f"{name}={signal_name}"
    elif type_str in ["const kernel_sigset_t*"] and val != 0:
        sigmask = z.memory.read_uint32(val)
        signals_blocked = sigmask_string(sigmask)
        arg_string = f"{name}=0x{val:x} ({signals_blocked})"
    elif type_str in ["int"] and name in ["fd"]:
        handle = z.processes.handles.get(val)
        handle_category = (
            handle.category() if handle is not None else "unknown"
        )
        arg_string = f"{name}=0x{val:x} ({handle_category})"
    elif type_str in ["fd_set*"]:
        if val == 0:
            arg_string = f"{name}=0x{val:x} ()"
        else:
            fds = _parse_fdset(z, val)
            arg_string = (
                f"{name}=0x{val:x} ({','.join([hex(x) for x in fds])})"
            )
    else:
        arg_string = "{0}=0x{1:x}".format(name, val)
    if val_s != "":
        z.triggers.api_strings.add(val_s)
    return arg_string


def _parse_fdset(z, addr):
    """
    Parse the individual fd's that are 'ready' from an fd_set. An fd
    is 'ready' when its corresponding bit is set in the fd_set. The
    fd_set is an array of bitmasks, where the ith bit of the
    jth element corresponds to the fd value (j * 32) + i.
    """
    fds = []
    for i in range(0, 1024 // 8, 32 // 8):
        val = z.memory.read_uint32(addr + i)
        for bit in range(32):
            if val & 2 ** bit != 0:
                fds.append((i // 4) * 32 + bit)
    return fds
