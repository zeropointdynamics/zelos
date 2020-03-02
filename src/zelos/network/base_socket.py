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

import queue
import socket

from collections import defaultdict

import dnslib

from pypacker.layer3 import ip
from pypacker.layer4 import tcp

from zelos.handles import SocketHandle


class BaseSocket:
    """
    This socket pretends that every connection succeeds. Every return
    should succeed and return all zeros.
    """

    def __init__(self, network_manager, domain, sock_type, protocol):
        """
        Initialize a socket of the specified type. Raises an exception
        if the socket type is not supported.

        Args:
            network_manager: A reference to the `Network` object.
            domain: socket domain (as defined in python `socket`).
            type: socket type (as defined in python `socket`).
            protocol: socket protocol (as defined in python `socket`).
        """
        if not hasattr(socket, "SOCK_CLOEXEC"):
            # Windows support
            socket.SOCK_CLOEXEC = 0x80000
            socket.SOCK_NONBLOCK = 0x800
            socket.AF_UNIX = 0x1

        sock_type &= ~(socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        sock_type = socket.SocketKind(sock_type)

        self._errno = 0
        self.network = network_manager
        self.domain = domain
        self.type = sock_type
        self.protocol = protocol
        self.host_and_port = (None, None)
        self._is_nonblock = True

        self.history = defaultdict(list)
        self.sock = None

        if domain == socket.AF_UNIX:
            raise Exception("[BaseSocket] AF_UNIX domain not supported.")

        if sock_type == socket.SOCK_RAW:
            self.sock = RawSocketSimulator(self.domain)

    @property
    def errno(self):
        """
        The last error that occurred (see python `errno`) for any method
        of this class that returns -1 or raises an exception.
        """
        return self._errno

    def setsockopt(self, level, name, value):
        """
        Sets socket options.

        Args:
            level: option level (as defined in python `socket`)
            name: option name (as defined in python `socket`)
            value: option value (type depends on option name)

        Returns:
            0 on success, -1 on failure.
        """
        return 0

    def set_nonblock(self, is_nonblock: bool):
        """
        Sets the socket blocking option.

        Args:
            is_nonblock: if True, makes the socket non-blocking.
        """
        self._is_nonblock = is_nonblock

    def is_nonblock(self):
        """
        Gets the socket blocking status.

        Returns:
            True if the socket is non_blocking, False otherwise.
        """
        return self._is_nonblock

    def connect(self, host_and_port):
        """
        Connects the socket.

        Args:
            host_and_port: A tuple of the form (host: string, port: int)

        Returns:
            0 on success, -1 on failure.
        """
        self.host_and_port = host_and_port
        if self.sock is None and host_and_port[1] == 53:
            self.sock = DnsSocketSimulator(
                self.domain, host_and_port[0], host_and_port[1]
            )
        self.history["connect"].append(host_and_port)
        return 0

    def close(self):
        """
        Closes the socket.
        """
        pass

    def bind(self, host_and_port):
        """
        Binds the socket to a port.

        Args:
            host_and_port: A tuple of the form (host: string, port: int)

        Returns:
            0 on success, -1 on failure.
        """
        self.host_and_port = host_and_port
        self.history["bind"].append(host_and_port)
        return 0

    def listen(self, backlog: int = 0):
        """
        Socket listen.

        Returns:
            0 on success, -1 on failure.
        """
        return 0

    def accept(self):
        """
        Accepts a new connection on the listening socket.

        Returns:
            0 on success, -1 on failure.
        """
        return 0

    def peek(self):
        """
        Peek at readable data on the socket.

        Returns:
            A byte array containing the observed data.
        """
        return b"0" * 1

    def send(self, data: bytes, flags: int = 0):
        """
        Sends data over the socket.

        Args:
            data: The byte array to send.
            flags: socket send flags

        Returns:
            The length of the data sent.
        """
        host = self.host_and_port[0]
        port = self.host_and_port[1]

        if self.sock is None and port == 53:
            self.sock = DnsSocketSimulator(self.domain, host, port)

        if self.sock is not None:
            return self.sock.send(data, flags)

        self.history["send"].append(data)
        return len(data)

    def recv(self, bufsize: int, flags: int):
        """
        Receive data from the socket.

        Args:
            bufsize: maximum size of data to receive.
            flags: socket recv flags

        Returns:
            A byte array of the data received, or None.
        """
        # If sock exists, use it's simulated receiver
        if self.sock is not None:
            return self.sock.recv(bufsize, flags)
        return b"0" * bufsize

    def recvfrom(self, bufsize: int, flags: int = 0):
        """
        Receive data from a non-streaming (i.e. non-TCP) protocol.

        Args:
            bufsize: maximum size of data to receive.
            flags: socket recv flags

        Returns:
            The tuple (data received, domain, host, port).
        """
        # If sock exists, use it's simulated receiver
        if self.sock is not None:
            return self.sock.recvfrom(bufsize, flags)
        return (
            b"0" * bufsize,
            self.domain,
            self.host_and_port[0],
            self.host_and_port[1],
        )

    def sendto(self, data: bytes, host_and_port, flags: int = 0):
        """
        Send data over non-streaming (i.e. non-TCP) protocol.
        If host and port are not None, send to that address. Otherwise,
        send to the address given during socket connect.

        Args:
            host_and_port: A tuple of the form (host: string, port: int)
            flags: socket recv flags

        Returns:
            The length sent.
        """
        if self.host_and_port is not None and host_and_port[0] is not None:
            self.host_and_port = host_and_port
        port = self.host_and_port[1]

        if self.sock is None and port == 53:
            self.sock = DnsSocketSimulator(
                self.domain, host_and_port[0], host_and_port[1]
            )

        if self.sock is not None:
            return self.sock.sendto(data, self.host_and_port, flags)

        self.history["sendto"].append([data, host_and_port])
        return len(data)


class DnsSocketSimulator:
    """
    Simulate DNS requests and responses.
    """

    def __init__(self, domain, host=None, port=None):
        self.hostname = ""
        self.domain = domain
        self.host_and_port = (host, port)
        self.query = None
        self.dns_id = None

    def send(self, payload, flags=0):
        try:
            domain = self._parse_dns_request(payload)
            if domain is None:
                raise Exception(
                    "[DnsSocketSimulator] Parse Failed: " + str(payload)
                )
            else:
                self.hostname = domain
            print(f"[DnsSocketSimulator] DNS Query {self.hostname}")
        except Exception as e:
            print("DNS_INVALID:", e)

        return len(payload)

    def recv(self, bufsize, flags=0):
        if self.dns_id is None:
            return b"0" * bufsize

        id = self.dns_id
        self.dns_id = None
        reply = self._create_dns_response(
            hostname=self.hostname, ip="127.0.0.1", id=id
        )
        return reply

    def sendto(self, payload, host_and_port, flags=0):
        self.host_and_port = host_and_port
        return self.send(payload)

    def recvfrom(self, bufsize, flags=0):
        host = self.host_and_port[0]
        port = self.host_and_port[1]
        result = (self.recv(bufsize), socket.AF_INET, host, port)
        return result

    def is_readable(self):
        return True

    def _parse_dns_request(self, payload):
        """
        Parses a DNS packet. Additionally handles some bugs in Mirai's
        DNS request packet generation.
        """
        dns_id = int.from_bytes(payload[:2], byteorder="big")
        self.dns_id = dns_id
        domain = None
        original_payload = payload
        chop_count = 0
        while True:
            parts = []
            if len(payload) <= chop_count:
                break
            payload = original_payload[chop_count:]
            self.dns_id = dns_id
            payload = payload[12:]
            chop_count += 1
            while True:
                cnt = payload[0]
                if cnt == 0 or len(payload) < cnt:
                    break
                part = payload[1 : cnt + 1]

                try:
                    decoded = str(part.decode("utf8"))
                    if not self._is_valid_domain(decoded):
                        break
                    parts.append(decoded)
                except Exception:
                    break

                payload = payload[cnt + 1 :]
                if len(payload) <= 6:
                    break
            if len(parts) >= 2:
                domain = ".".join(parts)
                break
        return domain

    def _is_valid_domain(self, domain):
        valid = True
        for c in domain:
            if c.isalnum() or c == "-" or c == ".":
                continue
            valid = False
        return valid

    def _create_dns_response(self, hostname="google.com", ip=None, id=1):
        """
        Create a DNS response packet for the specified hostname. If `ip`
        is specified (as a string, e.g., '127.0.0.1'), it will be used
        for the response. Otherwise, a not found (NXDOMAIN) response is
        returned.
        """
        try:
            if ip is None:
                d = dnslib.DNSRecord(
                    dnslib.DNSHeader(qr=1, aa=1, ra=1, rcode=3, id=id),
                    q=dnslib.DNSQuestion(hostname),
                )
            else:
                d = dnslib.DNSRecord(
                    dnslib.DNSHeader(qr=1, aa=1, ra=1, id=id),
                    q=dnslib.DNSQuestion(hostname),
                    a=dnslib.RR(hostname, rdata=dnslib.A(ip)),
                )
            payload = bytes(d.pack())
            return payload
        except Exception as e:
            print("DNS_CREATE failed:", e)
        return None


class RawSocketSimulator:
    """
    Simulates scans that make use of raw sockets. For instance, raw
    SYN scan packets will be replied to with appropriate SYN+ACK
    packets.
    """

    def __init__(self, domain, host=None, port=None):
        self._raw_syn_queue = queue.Queue()
        self.domain = domain
        self.host_and_port = (host, port)

    def send(self, payload):
        packet = ip.IP(payload)
        if packet[ip.IP, tcp.TCP] is not None:
            print(
                "[RawSocketSimulator] RAW TCP %s:%s -> %s:%s"
                % (
                    packet[ip.IP].src_s,
                    packet[tcp.TCP].sport,
                    packet[ip.IP].dst_s,
                    packet[tcp.TCP].dport,
                )
            )
            self.host_and_port = (packet[ip.IP].dst_s, packet[tcp.TCP].dport)
            # Handle TCP SYN Scan
            if packet[tcp.TCP].flags == tcp.TH_SYN:
                if self._raw_syn_queue.qsize() < 16:
                    self._raw_syn_queue.put(
                        (
                            packet[ip.IP].src_s,
                            packet[ip.IP].dst_s,
                            packet[tcp.TCP].sport,
                            packet[tcp.TCP].dport,
                            packet[tcp.TCP].seq,
                        )
                    )
        else:
            print("[RawSocketSimulator] Unsupported RAW scan packet:", packet)

    def recv(self, bufsize):
        if not self._raw_syn_queue.empty():
            req = self._raw_syn_queue.get()
            response = self._make_syn_ack_packet(
                req[1], req[0], req[3], req[2], req[4]
            )
            response = response[: min(len(response), bufsize)]
            return response

        # TODO: handle other raw queue types here, e.g.
        #   xmas, fin, null, etc.

        raise Exception("[RawSocketSimulator] No handler for this raw socket.")

    def sendto(self, payload, host_and_port, flags=0):
        return self.send(payload)

    def recvfrom(self, bufsize, flags=0):
        host = self.host_and_port[0]
        port = self.host_and_port[1]
        return (self.recv(bufsize), socket.AF_INET, host, port)

    def is_readable(self):
        return True

    def _make_syn_ack_packet(self, saddr, daddr, sport, dport, seq):
        packet = ip.IP(src_s=saddr, dst_s=daddr) + tcp.TCP(
            dport=dport,
            sport=sport,
            seq=seq,
            ack=seq + 1,
            flags=tcp.TH_SYN | tcp.TH_ACK,
        )
        return packet.bin()


class BaseSelect:
    """
    Implements `select` and `poll` for zelos `SocketHandles` that make
    use of the BaseSocket.
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

    def __init__(self, network_manager):
        self.network = network_manager

    def select(self, in_handles, out_handles, ex_handles, timeout=0.1):
        """
        Select file descriptors.

        Given 3 File Descriptor lists, `select` the first one
        that is ready within the timeout window. For BaseSockets, always
        return `ready` for `write` events, and `not ready` for read
        events, as BaseSockets will never reply with data.

        Args:
            in_handles: fds to select for `read`.
            out_handles: fds to select for `write`.
            ex_handles: fds to select for `exceptional` events.

        Returns:
            3 lists that indicate which handles ids are ready.
        """

        # If the handle refers to a simulated socket (e.g. DNS or
        # RAW socket simulator), check if there is data to read.
        # Otherwise, nothing else is readable, and everything is
        # writable.
        readable_socks = []
        in_socks = self._handles_to_sockets(in_handles)
        for sock in in_socks:
            if sock is not None and sock.is_readable():
                readable_socks.append(sock)
        in_handles_ready = self._sockets_to_handles(in_handles, readable_socks)

        return (in_handles_ready, out_handles, [])

    def poll(self, fds, timeout=0.1):
        """
        Poll file descriptors.

        Args:
            fds: a list of tuples [(fd, events),..].
            timeout: maximum time to wait for the file descriptors.

        Returns:
            the list of tuples with fired events [(fd, revents),..].
        """

        return fds

    def _get_sockfd_from_handle(self, fd):
        handle = self.network.handles.get(fd)
        if (
            handle is None
            or not isinstance(handle, SocketHandle)
            or not isinstance(handle.socket, BaseSocket)
        ):
            return None
        return handle.socket

    def _handles_to_sockets(self, fds):
        socks = []
        for fd in fds:
            sockfd = self._get_sockfd_from_handle(fd)
            if sockfd is not None:
                socks.append(sockfd.sock)
        return socks

    def _sockets_to_handles(self, fds, socks_ready):
        ready = []
        for fd in fds:
            sockfd = self._get_sockfd_from_handle(fd)
            if sockfd is not None:
                if sockfd.sock in socks_ready:
                    ready.append(fd)
        return ready
