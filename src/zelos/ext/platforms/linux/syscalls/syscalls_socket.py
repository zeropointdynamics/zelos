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

import zelos.network.dns as dns

from zelos.ext.platforms.linux.network import (
    _host_to_bytes,
    _port_to_bytes,
    get_host_and_port,
)
from zelos.ext.platforms.linux.syscalls.syscalls_const import (
    SOCKADDR_IN,
    SocketFamily,
    SocketOptionsIp,
    SocketOptionsIPV6,
    SocketOptionsLevels,
    SocketOptionsSocket,
    SocketOptionsTcp,
    SocketProtocol,
    SocketType,
)
from zelos.util import dumpstruct, str2struct, struct2str

from . import syscall_structs as structs


def _parse_sockaddr_in(p, addr, size):
    class SOCKADDR_IN(ctypes.Structure):
        _fields_ = [
            ("sin_family", ctypes.c_ushort),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", ctypes.c_uint32),
            ("sin_zero", ctypes.c_char * 8),
        ]

    sockaddr_in = SOCKADDR_IN()
    str2struct(sockaddr_in, bytes(p.memory.read(addr, size)))


def _parse_sockaddr(p, addr, size):
    class SOCKADDR(ctypes.Structure):
        _fields_ = [
            ("sa_family", ctypes.c_ushort),
            ("sa_addr", ctypes.c_char * 14),
        ]

    sockaddr = SOCKADDR()
    str2struct(sockaddr, bytes(p.memory.read(addr, size)))


def _create_sockaddr_in(domain, host, port):
    import socket

    struct_bytes = b""
    if domain == socket.AF_INET:
        domain = SocketFamily.AF_INET
    else:
        domain = SocketFamily.AF_INET6
    s_in = SOCKADDR_IN()
    s_in.sin_family = domain
    s_in.sin_addr = _host_to_bytes(host, domain)
    s_in.sin_port = _port_to_bytes(port)
    struct_bytes = struct2str(s_in)
    return struct_bytes


def _socket_linux_to_python(domain, type, protocol):
    """
    Convert Linux socket domain, type and protocol constants into their
    equivalent python constants.
    """
    import socket

    domain_map = {
        SocketFamily.AF_INET: socket.AF_INET,
        SocketFamily.AF_INET6: socket.AF_INET6,
    }
    type_map = {
        SocketType.SOCK_STREAM: socket.SOCK_STREAM,
        SocketType.SOCK_DGRAM: socket.SOCK_DGRAM,
        SocketType.SOCK_RAW: socket.SOCK_RAW,
    }
    proto_map = {
        SocketProtocol.IPPROTO_TCP: socket.IPPROTO_TCP,
        SocketProtocol.IPPROTO_UDP: socket.IPPROTO_UDP,
        SocketProtocol.IPPROTO_RAW: socket.IPPROTO_RAW,
        SocketProtocol.IPPROTO_ICMP: socket.IPPROTO_ICMP,
        SocketProtocol.IPPROTO_IP: socket.IPPROTO_IP,
    }

    if not hasattr(socket, "SOCK_CLOEXEC"):
        # Windows support
        socket.SOCK_CLOEXEC = 0x80000
        socket.SOCK_NONBLOCK = 0x800
        socket.AF_UNIX = 0x1

    cloexec = bool(type & SocketType.SOCK_CLOEXEC)
    nonblock = bool(type & SocketType.SOCK_NONBLOCK)
    type &= ~(SocketType.SOCK_CLOEXEC | SocketType.SOCK_NONBLOCK)

    try:
        domain = domain_map[domain]
        type = type_map[type]
        protocol = proto_map[protocol]
    except Exception:
        raise Exception(f"Unsupported socket({domain}, {type}, {protocol}")

    if cloexec:
        type |= socket.SOCK_NONBLOCK
    if nonblock:
        type |= socket.SOCK_CLOEXEC

    return (domain, type, protocol)


def _socktopt_linux_to_python(level, name):
    """
    Convert Linux socktop level and name constants into their
    equivalent python constants.
    """
    import socket

    level_map = {
        SocketOptionsLevels.SOL_SOCKET: socket.SOL_SOCKET,
        SocketOptionsLevels.IPPROTO_TCP: socket.IPPROTO_TCP,
        SocketOptionsLevels.IPPROTO_IPV6: socket.IPPROTO_IPV6,
        SocketOptionsLevels.IPPROTO_IP: socket.IPPROTO_IP,
    }
    opt_map = {
        socket.SOL_SOCKET: {
            SocketOptionsSocket.SO_REUSEADDR: socket.SO_REUSEADDR,
            SocketOptionsSocket.SO_KEEPALIVE: socket.SO_KEEPALIVE,
        },
        socket.IPPROTO_TCP: {SocketOptionsTcp.TCP_NODELAY: socket.TCP_NODELAY},
        socket.IPPROTO_IPV6: {
            SocketOptionsIPV6.IPV6_V6ONLY: socket.IPV6_V6ONLY
        },
        socket.IPPROTO_IP: {
            SocketOptionsIp.IP_HDRINCL: socket.IP_HDRINCL,
            SocketOptionsIp.IP_OPTIONS: socket.IP_OPTIONS,
        },
    }
    try:
        level = level_map[level]
        name = opt_map[level][name]
    except Exception:
        raise (f"unsupported sockopt option:" f"level: {level} name: {name}")
    return (level, name)


def socket(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p,
        "socket",
        args_addr,
        [("int_DOMAIN", "domain"), ("int", "type"), ("int", "protocol")],
    )

    try:
        (domain, type, protocol) = _socket_linux_to_python(
            args.domain, args.type, args.protocol
        )
        socket_handle_num = sm.z.network.create_socket(domain, type, protocol)
    except Exception as e:
        print("socket error :", e)
        return -1
    return socket_handle_num


def bind(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p,
        "bind",
        args_addr,
        [
            ("int", "sockfd"),
            ("const struct sockaddr*", "addr"),
            ("socklen_t", "addrlen"),
        ],
    )
    _parse_sockaddr(p, args.addr, args.addrlen)
    socket_handle = sm.z.handles.get(args.sockfd)
    sock = socket_handle.socket
    addr = bytes(p.memory.read(args.addr, args.addrlen))
    (host, port) = get_host_and_port(sock.domain, addr)
    sm.print(f"binding socket 0x{args.sockfd:x} to ({host}, {port})")
    return sock.bind((host, port))


def connect(sm, p, args_addr):
    def print_addr(args):
        socket_handle = sm.z.handles.get(args.sockfd)
        if socket_handle is None:
            return "{0}=0x{1:x}".format("addr", args.addr)
        sock = socket_handle.socket
        sockaddr = bytes(p.memory.read(args.addr, args.addrlen))
        (host, port) = get_host_and_port(sock.domain, sockaddr)
        return f"dest_addr=0x{args.addr:x} ({host}:{port})"

    args = sm._get_socketcall_args(
        p,
        "connect",
        args_addr,
        [
            ("int", "sockfd"),
            ("const struct sockaddr*", "addr"),
            ("socklen_t", "addrlen"),
        ],
        arg_string_overrides={"addr": print_addr},
    )
    # _parse_sockaddr(p, args.addr, args.addrlen)
    socket_handle = sm.z.handles.get(args.sockfd)
    if socket_handle is None:
        sm.logger.error("Invalid socket handle")
        return -1
    socket = socket_handle.socket
    addr = p.memory.read(args.addr, args.addrlen)

    host, port = get_host_and_port(socket.domain, bytes(addr))
    socket_handle.data["dst_name"] = f"{host}:{port}"
    socket_handle.data["host"] = host
    socket_handle.data["port"] = port

    status = socket.connect((host, port))
    return status


def listen(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p, "listen", args_addr, [("int", "sockfd"), ("int", "backlog")]
    )

    socket_handle = sm.z.handles.get(args.sockfd)
    if socket_handle is None:
        sm.logger.error("Invalid socket handle")
        return -1
    socket = socket_handle.socket

    socket.listen(args.backlog)

    return 0


def accept(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p,
        "accept",
        args_addr,
        [
            ("int", "sockfd"),
            ("struct sockaddr *", "addr"),
            ("socklen_t *", "addrlen"),
        ],
    )

    socket_handle = sm.z.handles.get(args.sockfd)
    if socket_handle is None:
        sm.logger.error("Invalid socket handle")
        return -1
    socket = socket_handle.socket

    socket.accept()

    return args.sockfd + 1


def getsockname(sm, p, args_addr):
    sm._get_socketcall_args(
        p,
        "getsockname",
        args_addr,
        [
            ("int", "sockfd"),
            ("struct sockaddr *", "addr"),
            ("socklen_t *", "addrlen"),
        ],
    )
    return 0


def getpeername(sm, p, args_addr):
    sm._get_socketcall_args(
        p,
        "getpeername",
        args_addr,
        [
            ("int", "sockfd"),
            ("struct sockaddr *", "addr"),
            ("socklen_t *", "addrlen"),
        ],
    )
    return 0


def socketpair(sm, p, args_addr):
    sm._get_socketcall_args(
        p,
        "socketpair",
        args_addr,
        [
            ("int", "domain"),
            ("int", "type"),
            ("int", "protocol"),
            ("int *", "sv"),
        ],
    )
    return 0


def send(sm, p, args_addr):
    def print_buf(args):
        s = repr(bytes(p.memory.read(args.buf, size=args.len)))[2:-1]
        return f'buf=0x{args.buf:x} ("{s}")'

    args = sm._get_socketcall_args(
        p,
        "send",
        args_addr,
        [
            ("int", "sockfd"),
            ("const void*", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
        ],
        arg_string_overrides={"buf": print_buf},
    )
    payload = p.memory.read(args.buf, args.len)
    return _send(sm, p, args.sockfd, payload, args.flags)


def sendto(sm, p, args_addr):
    def print_buf(args):
        s = repr(bytes(p.memory.read(args.buf, size=args.len)))[2:-1]
        return f'buf=0x{args.buf:x} ("{s}")'

    def print_dst(args):
        socket_handle = sm.z.handles.get(args.sockfd)
        if socket_handle is None:
            return "{0}=0x{1:x}".format("dest_addr", args.dest_addr)
        sock = socket_handle.socket
        sockaddr = bytes(p.memory.read(args.dest_addr, args.addrlen))
        (host, port) = get_host_and_port(sock.domain, sockaddr)
        return f"dest_addr=0x{args.dest_addr:x} ({host}:{port})"

    args = sm._get_socketcall_args(
        p,
        "sendto",
        args_addr,
        [
            ("int", "sockfd"),
            ("const void*", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
            ("const struct sockaddr*", "dest_addr"),
            ("socklen_t", "addrlen"),
        ],
        arg_string_overrides={"buf": print_buf, "dest_addr": print_dst},
    )
    socket_handle = sm.z.handles.get(args.sockfd)
    if socket_handle is None:
        sm.logger.notice(f"Could not find socket {args.sockfd}")
        return -1
    sock = socket_handle.socket
    sockaddr = bytes(p.memory.read(args.dest_addr, args.addrlen))
    (host, port) = get_host_and_port(sock.domain, sockaddr)
    payload = p.memory.read(args.buf, args.len)

    if socket_handle.data.get("port", 0) == 53:
        target = dns.parse_dns_request(payload)
        if target is not None:
            sm.print_info(f"DNS Request: {target}")
            sm.z.network.add_attempted_connection(target, "sendto")

    return sock.sendto(payload, (host, port), args.flags)


def _send(sm, p, sockfd, payload, flags=0):
    socket_handle = sm.z.handles.get(sockfd)
    if socket_handle is None:
        sm.logger.notice(f"Invalid socket fd 0x{sockfd:x}")
        return -1
    sock = socket_handle.socket
    sent_len = sock.send(payload, flags)

    if socket_handle.data.get("port", 0) == 53:
        target = dns.parse_dns_request(payload)
        if target is not None:
            sm.print_info(f"DNS Request: {target}")
            sm.z.network.add_attempted_connection(target, "sendto")

    return sent_len


def recv(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p,
        "recv",
        args_addr,
        [
            ("int", "sockfd"),
            ("void *", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
        ],
    )
    return _recv(sm, p, args.sockfd, args.buf, args.len, args.flags)


def recvfrom(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p,
        "recvfrom",
        args_addr,
        [
            ("int", "sockfd"),
            ("void *", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
            ("struct sockaddr *", "src_addr"),
            ("socklen_t *", "addrlen"),
        ],
    )
    socket_handle = sm.z.handles.get(args.sockfd)
    sock = socket_handle.socket

    try:
        (data, domain, host, port) = sock.recvfrom(args.len, args.flags)
        if args.src_addr != 0 and args.addrlen != 0:
            sockaddr = _create_sockaddr_in(domain, host, port)
            p.memory.write(args.src_addr, sockaddr)
            p.memory.write_uint32(args.addrlen, len(sockaddr))
        if len(data) > 0:
            p.memory.write(args.buf, data)
        return len(data)
    except Exception as e:
        print("[recvfrom] error: " + str(e))
        return -1


def _recv(sm, p, sockfd, buf, _len, flags=0):
    socket_handle = sm.z.handles.get(sockfd)
    if socket_handle is None:
        return -1
    sock = socket_handle.socket
    has_data = sock.peek()
    if has_data:
        data = sock.recv(_len, flags)
        sm.print(f"received: '{data}'")
        p.memory.write(buf, data)
        return len(data)
    return 0


def shutdown(sm, p, args_addr):
    sm._get_socketcall_args(
        p, "shutdown", args_addr, [("int", "sockfd"), ("int", "how")]
    )
    return 0


def setsockopt(sm, p, args_addr):
    arg_list = [
        ("int", "sockfd"),
        ("int", "level"),
        ("int", "optname"),
        ("const void*", "optval"),
        ("socklen_t", "optlen"),
    ]
    args = sm._get_socketcall_args(p, "setsockopt", args_addr, arg_list)

    socket_handle = sm.z.handles.get(args.sockfd)
    if socket_handle is None:
        sm.logger.error("Invalid socket handle")
        return -1
    socket = socket_handle.socket

    optval = p.memory.read(args.optval, args.optlen)

    try:
        (level, name) = _socktopt_linux_to_python(args.level, args.optname)
        return socket.setsockopt(args.level, args.optname, optval)
    except Exception as e:
        print("[setsockopt] failed:", e)

    return 0


def getsockopt(sm, p, args_addr):
    sm._get_socketcall_args(
        p,
        "getsockopt",
        args_addr,
        [
            ("int", "sockfd"),
            ("int", "level"),
            ("int", "optname"),
            ("void *", "optval"),
            ("socklen_t *", "optlen"),
        ],
    )
    return 0


def sendmsg(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p,
        "sendmsg",
        args_addr,
        [("int", "sockfd"), ("const struct msghdr*", "msg"), ("int", "flags")],
    )
    msghdr = p.memory.readstruct(args.msg, structs.MSGHDR())
    return _sendmsg(sm, p, args.sockfd, msghdr, args.flags)


def sendmmsg(sm, p, args_addr):
    args = sm._get_socketcall_args(
        p,
        "sendmmsg",
        args_addr,
        [
            ("int", "sockfd"),
            ("struct mmsghdr*", "msgvec"),
            ("unsigned int", "vlen"),
            ("int", "flags"),
        ],
    )
    mmsg_addr = args.msgvec
    for i in range(args.vlen):
        msghdr = p.memory.readstruct(mmsg_addr, structs.MSGHDR())
        bytes_sent = _sendmsg(sm, p, args.sockfd, msghdr, args.flags)
        msg_len_addr = mmsg_addr + ctypes.sizeof(msghdr)
        int_size = p.memory.write_int(msg_len_addr, bytes_sent)
        mmsg_addr += ctypes.sizeof(msghdr) + int_size
    return args.vlen


def _sendmsg(sm, p, sockfd, msghdr, flags):
    dumpstruct(msghdr)

    iovec_array = p.memory.readstructarray(
        msghdr.msg_iov, msghdr.msg_iovlen, structs.IOVEC()
    )

    gathered_results = b""
    for iovec in iovec_array:
        gathered_results += p.memory.read(iovec.iov_base, iovec.iov_len)

    sent_len = _send(sm, p, sockfd, gathered_results, flags)

    return sent_len


def recvmsg(sm, p, args_addr):
    sm._get_socketcall_args(
        p,
        "recvmsg",
        args_addr,
        [("int", "sockfd"), ("struct msghdr *", "msg"), ("int", "flags")],
    )
    return 0


def accept4(sm, p, args_addr):
    sm._get_socketcall_args(
        p,
        "accept4",
        args_addr,
        [
            ("int", "sockfd"),
            ("struct sockaddr *", "addr"),
            ("socklen_t *", "addrlen"),
            ("int", "flags"),
        ],
    )
    return 0


def recvmmsg(sm, p, args_addr):
    sm._get_socketcall_args(
        p,
        "recvmmsg",
        args_addr,
        [
            ("int", "sockfd"),
            ("struct mmsghdr *", "msgvec"),
            ("unsigned int", "vlen"),
            ("int", "flags"),
            ("struct timespec *", "timeout"),
        ],
    )
    return 0
