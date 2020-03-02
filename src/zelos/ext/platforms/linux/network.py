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

import ipaddress
import socket

import zelos.util as zelos_util

from .syscalls.syscalls_const import SOCKADDR_IN, SOCKADDR_IN6, SocketFamily


def _bytes_to_host(b, domain):
    """
    Converts an integer containing the domain to a string represnting
    the ip of the host.
    """
    if domain == SocketFamily.AF_INET:
        b_htonl = socket.htonl(b)
        return str(ipaddress.IPv4Address(b_htonl))
    return None


def _host_to_bytes(host, domain):
    if domain == SocketFamily.AF_INET:
        return int.from_bytes(ipaddress.IPv4Address(host).packed, "little")
    return -1


def _bytes_to_port(b):
    return socket.htons(b)


def _port_to_bytes(port):
    return socket.ntohs(port)


def get_host_and_port(domain, struct_bytes):
    host = "255.255.255.255"
    port = 65536
    if len(struct_bytes) == 0:
        return (None, None)
    if domain == SocketFamily.AF_INET:
        s_in = SOCKADDR_IN()
        zelos_util.str2struct(s_in, bytes(struct_bytes))
        host = _bytes_to_host(s_in.sin_addr, domain)
        port = _bytes_to_port(s_in.sin_port)
    elif domain == SocketFamily.AF_INET6:
        s_in6 = SOCKADDR_IN6()
        zelos_util.str2struct(s_in6, bytes(struct_bytes))
        host = _bytes_to_host(s_in6.sin6_addr, domain)
        port = _bytes_to_port(s_in6.sin6_port)
    return (host, port)
