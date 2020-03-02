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
import enum


class SysError(enum.IntEnum):
    EPERM = -1  # Operation not permitted */
    ENOENT = -2  # No such file or directory */
    ESRCH = -3  # No such process */
    EINTR = -4  # Interrupted system call */
    EIO = -5  # I/O error */
    ENXIO = -6  # No such device or address */
    E2BIG = -7  # Arg list too long */
    ENOEXEC = -8  # Exec format error */
    EBADF = -9  # Bad file number */
    ECHILD = -10  # No child processes */
    EAGAIN = -11  # Try again */
    ENOMEM = -12  # Out of memory */
    EACCES = -13  # Permission denied */
    EFAULT = -14  # Bad address */
    ENOTBLK = -15  # Block device required */
    EBUSY = -16  # Device or resource busy */
    EEXIST = -17  # File exists */
    EXDEV = -18  # Cross-device link */
    ENODEV = -19  # No such device */
    ENOTDIR = -20  # Not a directory */
    EISDIR = -21  # Is a directory */
    EINVAL = -22  # Invalid argument */
    ENFILE = -23  # File table overflow */
    EMFILE = -24  # Too many open files */
    ENOTTY = -25  # Not a typewriter */
    ETXTBSY = -26  # Text file busy */
    EFBIG = -27  # File too large */
    ENOSPC = -28  # No space left on device */
    ESPIPE = -29  # Illegal seek */
    EROFS = -30  # Read-only file system */
    EMLINK = -31  # Too many links */
    EPIPE = -32  # Broken pipe */
    EDOM = -33  # Math argument out of domain of func */
    ERANGE = -34  # Math result not representable */
    EDEADLK = -35  # Resource deadlock would occur */
    ENAMETOOLONG = -36  # File name too long */
    ENOLCK = -37  # No record locks available */
    ENOSYS = -38  # Function not implemented */
    ENOTEMPTY = -39  # Directory not empty */
    ELOOP = -40  # Too many symbolic links encountered */
    EWOULDBLOCK = EAGAIN  # Operation would block */
    ENOMSG = -42  # No message of desired type */
    EIDRM = -43  # Identifier removed */
    ECHRNG = -44  # Channel number out of range */
    EL2NSYNC = -45  # Level 2 not synchronized */
    EL3HLT = -46  # Level 3 halted */
    EL3RST = -47  # Level 3 reset */
    ELNRNG = -48  # Link number out of range */
    EUNATCH = -49  # Protocol driver not attached */
    ENOCSI = -50  # No CSI structure available */
    EL2HLT = -51  # Level 2 halted */
    EBADE = -52  # Invalid exchange */
    EBADR = -53  # Invalid request descriptor */
    EXFULL = -54  # Exchange full */
    ENOANO = -55  # No anode */
    EBADRQC = -56  # Invalid request code */
    EBADSLT = -57  # Invalid slot */

    EDEADLOCK = EDEADLK
    EBFONT = -59  # Bad font file format */
    ENOSTR = -60  # Device not a stream */
    ENODATA = -61  # No data available */
    ETIME = -62  # Timer expired */
    ENOSR = -63  # Out of streams resources */
    ENONET = -64  # Machine is not on the network */
    ENOPKG = -65  # Package not installed */
    EREMOTE = -66  # Object is remote */
    ENOLINK = -67  # Link has been severed */
    EADV = -68  # Advertise error */
    ESRMNT = -69  # Srmount error */
    ECOMM = -70  # Communication error on send */
    EPROTO = -71  # Protocol error */
    EMULTIHOP = -72  # Multihop attempted */
    EDOTDOT = -73  # RFS specific error */
    EBADMSG = -74  # Not a data message */
    EOVERFLOW = -75  # Value too large for defined data type */
    ENOTUNIQ = -76  # Name not unique on network */
    EBADFD = -77  # File descriptor in bad state */
    EREMCHG = -78  # Remote address changed */
    ELIBACC = -79  # Can not access a needed shared library */
    ELIBBAD = -80  # Accessing a corrupted shared library */
    ELIBSCN = -81  # .lib section in a.out corrupted */
    ELIBMAX = -82  # Attempting to link in too many shared libraries */
    ELIBEXEC = -83  # Cannot exec a shared library directly */
    EILSEQ = -84  # Illegal byte sequence */
    ERESTART = -85  # Interrupted system call should be restarted */
    ESTRPIPE = -86  # Streams pipe error */
    EUSERS = -87  # Too many users */
    ENOTSOCK = -88  # Socket operation on non-socket */
    EDESTADDRREQ = -89  # Destination address required */
    EMSGSIZE = -90  # Message too long */
    EPROTOTYPE = -91  # Protocol wrong type for socket */
    ENOPROTOOPT = -92  # Protocol not available */
    EPROTONOSUPPORT = -93  # Protocol not supported */
    ESOCKTNOSUPPORT = -94  # Socket type not supported */
    EOPNOTSUPP = -95  # Operation not supported on transport endpoint */
    EPFNOSUPPORT = -96  # Protocol family not supported */
    EAFNOSUPPORT = -97  # Address family not supported by protocol */
    EADDRINUSE = -98  # Address already in use */
    EADDRNOTAVAIL = -99  # Cannot assign requested address */
    ENETDOWN = -100  # Network is down */
    ENETUNREACH = -101  # Network is unreachable */
    ENETRESET = -102  # Network dropped connection because of reset */
    ECONNABORTED = -103  # Software caused connection abort */
    ECONNRESET = -104  # Connection reset by peer */
    ENOBUFS = -105  # No buffer space available */
    EISCONN = -106  # Transport endpoint is already connected */
    ENOTCONN = -107  # Transport endpoint is not connected */
    ESHUTDOWN = -108  # Cannot send after transport endpoint shutdown */
    ETOOMANYREFS = -109  # Too many references =  splice */
    ETIMEDOUT = -110  # Connection timed out */
    ECONNREFUSED = -111  # Connection refused */
    EHOSTDOWN = -112  # Host is down */
    EHOSTUNREACH = -113  # No route to host */
    EALREADY = -114  # Operation already in progress */
    EINPROGRESS = -115  # Operation now in progress */
    ESTALE = -116  # Stale NFS file handle */
    EUCLEAN = -117  # Structure needs cleaning */
    ENOTNAM = -118  # Not a XENIX named type file */
    ENAVAIL = -119  # No XENIX semaphores available */
    EISNAM = -120  # Is a named type file */
    EREMOTEIO = -121  # Remote I/O error */
    EDQUOT = -122  # Quota exceeded */

    ENOMEDIUM = -123  # No medium found */
    EMEDIUMTYPE = -124  # Wrong medium type */


ARCH_PRCTL_OPTIONS = {
    0x1001: "ARCH_SET_GS",
    0x1002: "ARCH_SET_FS",
    0x1003: "ARCH_GET_FS",
    0x1004: "ARCH_GET_GS",
}


FCNTL_COMMANDS = {
    0: "F_DUPFD",  # dup
    1: "F_GETFD",  # get close_on_exec
    2: "F_SETFD",  # set/clear close_on_exec
    3: "F_GETFL",  # get file->f_flags
    4: "F_SETFL",  # set file->f_flags
    5: "F_GETLK",
    6: "F_SETLK",
    7: "F_SETLKW",
    8: "F_SETOWN",  # for sockets.
    9: "F_GETOWN",  # for sockets.
    10: "F_SETSIG",  # for sockets.
    11: "F_GETSIG",  # for sockets.
    12: "F_GETLK64",  # using 'struct flock64'
    13: "F_SETLK64",
    14: "F_SETLKW64",
    15: "F_SETOWN_EX",
    16: "F_GETOWN_EX",
    17: "F_GETOWNER_UIDS",
}


# Used to determine what kind of socket is being used.
protocol_families = {
    1: "UNIX",  # /* Unix domain sockets 		*/
    2: "INET",  # /* Internet IP Protocol 	*/
    3: "AX25",  # /* Amateur Radio AX.25 		*/
    4: "IPX",  # /* Novell IPX 			*/
    5: "APPLETALK",  # /* AppleTalk DDP 		*/
    6: "NETROM",  # /* Amateur Radio NET/ROM 	*/
    7: "BRIDGE",  # /* Multiprotocol bridge 	*/
    8: "ATMPVC",  # /* ATM PVCs			*/
    9: "X25",  # /* Reserved for X.25 project 	*/
    10: "INET6",  # /* IP version 6			*/
    11: "ROSE",  # /* Amateur Radio X.25 PLP	*/
    12: "DECnet",  # /* Reserved for DECnet project	*/
    13: "NETBEUI",  # /* Reserved for 802.2LLC project*/
    14: "SECURITY",  # /* Security callback pseudo AF */
    15: "KEY",  # /* PF_KEY key management API */
    16: "NETLINK",  # /* Alias to emulate 4.4BSD */
    17: "PACKET",  # /* Packet family		*/
    18: "ASH",  # * Ash				*/
    19: "ECONET",  # /* Acorn Econet			*/
    20: "ATMSVC",  # /* ATM SVCs			*/
    21: "RDS",  # /* RDS sockets 			*/
    22: "SNA",  # /* Linux SNA Project (nutters!) */
    23: "IRDA",  # /* IRDA sockets			*/
    24: "PPPOX",  # /* PPPoX sockets		*/
    25: "WANPIPE",  # /* Wanpipe API Sockets */
    26: "LLC",  # /* Linux LLC			*/
    27: "IB",  # /* Native InfiniBand address	*/
    28: "MPLS",  # * MPLS */
    29: "CAN",  # /* Controller Area Network      */
    30: "TIPC",  # /* TIPC sockets			*/
    31: "BLUETOOTH",  # /* Bluetooth sockets 		*/
    32: "IUCV",  # /* IUCV sockets			*/
    33: "RXRPC",  # /* RxRPC sockets 		*/
    34: "ISDN",  # /* mISDN sockets 		*/
    35: "PHONET",  # /* Phonet sockets		*/
    36: "IEEE802154",  # /* IEEE802154 sockets		*/
    37: "CAIF",  # /* CAIF sockets			*/
    38: "ALG",  # /* Algorithm sockets		*/
    39: "NFC",  # /* NFC sockets			*/
    40: "VSOCK",  # * vSockets			*/
    41: "KCM",  # /* Kernel Connection Multiplexor*/
    42: "QIPCRTR",  # /* Qualcomm IPC Router          */
    43: "SMC",  # /* smc sockets: reserve number for
    44: "XDP",  # /* XDP sockets			*/
    45: "MAX",  # /* For now.. */
}


class SOCKADDR(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sa_data", ctypes.c_char * 8),
    ]


class SOCKADDR_UN(ctypes.Structure):
    _fields_ = [
        ("sun_family", ctypes.c_ushort),
        ("sun_path", ctypes.c_char * 108),
    ]


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_char * 8),
    ]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", ctypes.c_ushort),
        ("sin6_port", ctypes.c_ushort),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint64),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


class SocketFamily(enum.IntEnum):
    """
    Socket Family:
    https://github.com/torvalds/linux/blob/master/include/linux/socket.h
    """

    AF_UNSPEC = 0
    AF_UNIX = 1  # /* Unix domain sockets */
    AF_LOCAL = 1  # /* POSIX name for AF_UNIX */
    AF_INET = 2  # /* Internet IP Protocol */
    AF_AX25 = 3  # /* Amateur Radio AX.25 */
    AF_IPX = 4  # /* Novell IPX */
    AF_APPLETALK = 5  # /* AppleTalk DDP */
    AF_NETROM = 6  # /* Amateur Radio NET/ROM */
    AF_BRIDGE = 7  # /* Multiprotocol bridge */
    AF_ATMPVC = 8  # /* ATM PVCs */
    AF_X25 = 9  # /* Reserved for X.25 project */
    AF_INET6 = 10  # /* IP version 6 */
    AF_ROSE = 11  # /* Amateur Radio X.25 PLP */
    AF_DECnet = 12  # /* Reserved for DECnet project */
    AF_NETBEUI = 13  # /* Reserved for 802.2LLC project*/
    AF_SECURITY = 14  # /* Security callback pseudo AF */
    AF_KEY = 15  # /* PF_KEY key management API */
    AF_NETLINK = 16
    AF_ROUTE = 16  # /* AF_NETLINK: Alias to emulate 4.4BSD */
    AF_PACKET = 17  # /* Packet family */
    AF_ASH = 18  # /* Ash */
    AF_ECONET = 19  # /* Acorn Econet */
    AF_ATMSVC = 20  # /* ATM SVCs */
    AF_RDS = 21  # /* RDS sockets */
    AF_SNA = 22  # /* Linux SNA Project (nutters!) */
    AF_IRDA = 23  # /* IRDA sockets */
    AF_PPPOX = 24  # /* PPPoX sockets */
    AF_WANPIPE = 25  # /* Wanpipe API Sockets */
    AF_LLC = 26  # /* Linux LLC */
    AF_IB = 27  # /* Native InfiniBand address */
    AF_MPLS = 28  # /* MPLS */
    AF_CAN = 29  # /* Controller Area Network */
    AF_TIPC = 30  # /* TIPC sockets */
    AF_BLUETOOTH = 31  # /* Bluetooth sockets */
    AF_IUCV = 32  # /* IUCV sockets */
    AF_RXRPC = 33  # /* RxRPC sockets */
    AF_ISDN = 34  # /* mISDN sockets */
    AF_PHONET = 35  # /* Phonet sockets */
    AF_IEEE802154 = 36  # /* IEEE802154 sockets */
    AF_CAIF = 37  # /* CAIF sockets */
    AF_ALG = 38  # /* Algorithm sockets */
    AF_NFC = 39  # /* NFC sockets */
    AF_VSOCK = 40  # /* vSockets */
    AF_KCM = 41  # /* Kernel Connection Multiplexor*/
    AF_QIPCRTR = 42  # /* Qualcomm IPC Router */
    AF_SMC = 43  # /* smc sockets: reserve for PF_SMC protocol family */
    AF_XDP = 44  # /* XDP sockets */
    AF_MAX = 45  # /* For now.. */


class SocketType(enum.IntEnum):
    """
    Socket Types:
    https://github.com/torvalds/linux/blob/master/include/linux/net.h
    """

    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_RAW = 3
    SOCK_RDM = 4
    SOCK_SEQPACKET = 5
    SOCK_DCCP = 6
    SOCK_PACKET = 10
    SOCK_MAX = 11

    SOCK_CLOEXEC = 0o2000000
    SOCK_NONBLOCK = 0o4000


class SocketProtocol(enum.IntEnum):
    IPPROTO_IP = 0  # Dummy protocol for TCP.
    IPPROTO_ICMP = 1  # Internet Control Message Protocol.
    IPPROTO_IGMP = 2  # Internet Group Management Protocol.
    IPPROTO_IPIP = 4  # IPIP tunnels (older KA9Q tunnels use 94).
    IPPROTO_TCP = 6  # Transmission Control Protocol.
    IPPROTO_EGP = 8  # Exterior Gateway Protocol.
    IPPROTO_PUP = 12  # PUP protocol.
    IPPROTO_UDP = 17  # User Datagram Protocol.
    IPPROTO_IDP = 22  # XNS IDP protocol.
    IPPROTO_TP = 29  # SO Transport Protocol Class 4.
    IPPROTO_DCCP = 33  # Datagram Congestion Control Protocol.
    IPPROTO_IPV6 = 41  # IPv6 header.
    IPPROTO_RSVP = 46  # Reservation Protocol.
    IPPROTO_GRE = 47  # General Routing Encapsulation.
    IPPROTO_ESP = 50  # encapsulating security payload.
    IPPROTO_AH = 51  # authentication header.
    IPPROTO_MTP = 92  # Multicast Transport Protocol.
    IPPROTO_BEETPH = 94  # IP option pseudo header for BEET.
    IPPROTO_ENCAP = 98  # Encapsulation Header.
    IPPROTO_PIM = 103  # Protocol Independent Multicast.
    IPPROTO_COMP = 108  # Compression Header Protocol.
    IPPROTO_SCTP = 132  # Stream Control Transmission Protocol.
    IPPROTO_UDPLITE = 136  # UDP-Lite protocol.
    IPPROTO_MPLS = 137  # MPLS in IP.
    IPPROTO_RAW = 255  # Raw IP packets.


class SocketOptionsLevels(enum.IntEnum):
    IPPROTO_IP = 0
    SOL_SOCKET = 1
    IPPROTO_TCP = 6
    IPPROTO_IPV6 = 41


class SocketOptionsSocket(enum.IntEnum):
    SO_DEBUG = 1
    SO_REUSEADDR = 2
    SO_TYPE = 3
    SO_ERROR = 4
    SO_DONTROUTE = 5
    SO_BROADCAST = 6
    SO_SNDBUF = 7
    SO_RCVBUF = 8
    SO_SNDBUFFORCE = 32
    SO_RCVBUFFORCE = 33
    SO_KEEPALIVE = 9
    SO_OOBINLINE = 10
    SO_NO_CHECK = 11
    SO_PRIORITY = 12
    SO_LINGER = 13
    SO_BSDCOMPAT = 14
    SO_REUSEPORT = 15
    SO_PASSCRED = 16
    SO_PEERCRED = 17
    SO_RCVLOWAT = 18
    SO_SNDLOWAT = 19
    SO_RCVTIMEO = 20
    SO_SNDTIMEO = 21

    # Security levels - as per NRL IPv6 - don't actually do anything
    SO_SECURITY_AUTHENTICATION = 22
    SO_SECURITY_ENCRYPTION_TRANSPORT = 23
    SO_SECURITY_ENCRYPTION_NETWORK = 24
    SO_BINDTODEVICE = 25

    # Socket filtering
    SO_ATTACH_FILTER = 26
    SO_DETACH_FILTER = 27
    SO_PEERNAME = 28
    SO_TIMESTAMP = 29
    SO_ACCEPTCONN = 30
    SO_PEERSEC = 31
    SO_PASSSEC = 34
    SO_TIMESTAMPNS = 35
    SO_MARK = 36
    SO_TIMESTAMPING = 37
    SO_PROTOCOL = 38
    SO_DOMAIN = 39
    SO_RXQ_OVFL = 40
    SO_WIFI_STATUS = 41
    SO_PEEK_OFF = 42

    # Instruct lower device to use last 4-bytes of skb data as FCS
    SO_NOFCS = 43
    SO_LOCK_FILTER = 44
    SO_SELECT_ERR_QUEUE = 45
    SO_BUSY_POLL = 46
    SO_MAX_PACING_RATE = 47
    SO_BPF_EXTENSIONS = 48
    SO_INCOMING_CPU = 49
    SO_ATTACH_BPF = 50
    SO_ATTACH_REUSEPORT_CBPF = 51
    SO_ATTACH_REUSEPORT_EBPF = 52
    SO_CNX_ADVICE = 53
    SCM_TIMESTAMPING_OPT_STATS = 54
    SO_MEMINFO = 55
    SO_INCOMING_NAPI_ID = 56
    SO_COOKIE = 57
    SCM_TIMESTAMPING_PKTINFO = 58
    SO_PEERGROUPS = 59
    SO_ZEROCOPY = 60


class SocketOptionsIp(enum.IntEnum):
    IP_TOS = 1
    IP_TTL = 2
    IP_HDRINCL = 3
    IP_OPTIONS = 4
    IP_ROUTER_ALERT = 5
    IP_RECVOPTS = 6
    IP_RETOPTS = 7
    IP_PKTINFO = 8
    IP_PKTOPTIONS = 9
    IP_MTU_DISCOVER = 10
    IP_RECVERR = 11
    IP_RECVTTL = 12
    IP_RECVTOS = 13
    IP_MTU = 14
    IP_FREEBIND = 15
    IP_IPSEC_POLICY = 16
    IP_XFRM_POLICY = 17
    IP_PASSSEC = 18
    IP_TRANSPARENT = 19

    # TProxy original addresses
    IP_ORIGDSTADDR = 20

    IP_MINTTL = 21
    IP_NODEFRAG = 22
    IP_CHECKSUM = 23
    IP_BIND_ADDRESS_NO_PORT = 24
    IP_RECVFRAGSIZE = 25

    IP_MULTICAST_IF = 32
    IP_MULTICAST_TTL = 33
    IP_MULTICAST_LOOP = 34
    IP_ADD_MEMBERSHIP = 35
    IP_DROP_MEMBERSHIP = 36
    IP_UNBLOCK_SOURCE = 37
    IP_BLOCK_SOURCE = 38
    IP_ADD_SOURCE_MEMBERSHIP = 39
    IP_DROP_SOURCE_MEMBERSHIP = 40
    IP_MSFILTER = 41
    MCAST_JOIN_GROUP = 42
    MCAST_BLOCK_SOURCE = 43
    MCAST_UNBLOCK_SOURCE = 44
    MCAST_LEAVE_GROUP = 45
    MCAST_JOIN_SOURCE_GROUP = 46
    MCAST_LEAVE_SOURCE_GROUP = 47
    MCAST_MSFILTER = 48
    IP_MULTICAST_ALL = 49
    IP_UNICAST_IF = 50


class SocketOptionsTcp(enum.IntEnum):
    TCP_NODELAY = 1  # Turn off Nagle's algorithm.
    TCP_MAXSEG = 2  # Limit MSS
    TCP_CORK = 3  # Never send partially complete segments
    TCP_KEEPIDLE = 4  # Start keeplives after this period
    TCP_KEEPINTVL = 5  # Interval between keepalives
    TCP_KEEPCNT = 6  # Number of keepalives before death
    TCP_SYNCNT = 7  # Number of SYN retransmits
    TCP_LINGER2 = 8  # Life time of orphaned FIN-WAIT-2 state
    TCP_DEFER_ACCEPT = 9  # Wake up listener only when data arrive
    TCP_WINDOW_CLAMP = 10  # Bound advertised window
    TCP_INFO = 11  # Information about this connection.
    TCP_QUICKACK = 12  # Block/reenable quick acks
    TCP_CONGESTION = 13  # Congestion control algorithm
    TCP_MD5SIG = 14  # TCP MD5 Signature (RFC2385)
    TCP_THIN_LINEAR_TIMEOUTS = 16  # Use linear timeouts for thin streams*/
    TCP_THIN_DUPACK = 17  # Fast retrans. after = 1 dupack
    TCP_USER_TIMEOUT = 18  # How long for loss retry before timeout
    TCP_REPAIR = 19  # TCP sock is under repair right now
    TCP_REPAIR_QUEUE = 20
    TCP_QUEUE_SEQ = 21
    TCP_REPAIR_OPTIONS = 22
    TCP_FASTOPEN = 23  # Enable FastOpen on listeners
    TCP_TIMESTAMP = 24
    TCP_NOTSENT_LOWAT = 25  # limit number of unsent bytes in write queue
    TCP_CC_INFO = 26  # Get Congestion Control (optional) info
    TCP_SAVE_SYN = 27  # Record SYN headers for new connections
    TCP_SAVED_SYN = 28  # Get SYN headers recorded for connection
    TCP_REPAIR_WINDOW = 29  # Get/set window parameters
    TCP_FASTOPEN_CONNECT = 30  # Attempt FastOpen with connect
    TCP_ULP = 31  # Attach a ULP to a TCP connection
    TCP_MD5SIG_EXT = 32  # TCP MD5 Signature with extensions
    TCP_FASTOPEN_KEY = 33  # Set the key for Fast Open (cookie)
    TCP_FASTOPEN_NO_COOKIE = 34  # Enable TFO without a TFO cookie


class SocketOptionsIPV6(enum.IntEnum):
    IPV6_ADDRFORM = 1
    IPV6_2292PKTINFO = 2
    IPV6_2292HOPOPTS = 3
    IPV6_2292DSTOPTS = 4
    IPV6_2292RTHDR = 5
    IPV6_2292PKTOPTIONS = 6
    IPV6_CHECKSUM = 7
    IPV6_2292HOPLIMIT = 8
    IPV6_NEXTHOP = 9
    IPV6_AUTHHDR = 10
    IPV6_FLOWINFO = 11

    IPV6_UNICAST_HOPS = 16
    IPV6_MULTICAST_IF = 17
    IPV6_MULTICAST_HOPS = 18
    IPV6_MULTICAST_LOOP = 19
    IPV6_ADD_MEMBERSHIP = 20
    IPV6_DROP_MEMBERSHIP = 21
    IPV6_ROUTER_ALERT = 22
    IPV6_MTU_DISCOVER = 23
    IPV6_MTU = 24
    IPV6_RECVERR = 25
    IPV6_V6ONLY = 26
    IPV6_JOIN_ANYCAST = 27
    IPV6_LEAVE_ANYCAST = 28

    # Flowlabel
    IPV6_FLOWLABEL_MGR = 32
    IPV6_FLOWINFO_SEND = 33

    IPV6_IPSEC_POLICY = 34
    IPV6_XFRM_POLICY = 35
    IPV6_HDRINCL = 36

    IPV6_RECVPKTINFO = 49
    IPV6_PKTINFO = 50
    IPV6_RECVHOPLIMIT = 51
    IPV6_HOPLIMIT = 52
    IPV6_RECVHOPOPTS = 53
    IPV6_HOPOPTS = 54
    IPV6_RTHDRDSTOPTS = 55
    IPV6_RECVRTHDR = 56
    IPV6_RTHDR = 57
    IPV6_RECVDSTOPTS = 58
    IPV6_DSTOPTS = 59
    IPV6_RECVPATHMTU = 60
    IPV6_PATHMTU = 61
    IPV6_DONTFRAG = 62

    IPV6_RECVTCLASS = 66
    IPV6_TCLASS = 67

    IPV6_AUTOFLOWLABEL = 70
    # RFC5014: Source address selection
    IPV6_ADDR_PREFERENCES = 72

    # RFC5082: Generalized Ttl Security Mechanism
    IPV6_MINHOPCOUNT = 73

    IPV6_ORIGDSTADDR = 74
    IPV6_TRANSPARENT = 75
    IPV6_UNICAST_IF = 76
    IPV6_RECVFRAGSIZE = 77
    IPV6_FREEBIND = 78


class PRCTL(enum.IntEnum):
    """
    Process Control Types:
    https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h
    """

    PR_SET_PDEATHSIG = 1
    PR_GET_PDEATHSIG = 2
    PR_GET_DUMPABLE = 3
    PR_SET_DUMPABLE = 4
    PR_GET_UNALIGN = 5
    PR_SET_UNALIGN = 6
    PR_UNALIGN_NOPRINT = 1
    PR_UNALIGN_SIGBUS = 2
    PR_GET_KEEPCAPS = 7
    PR_SET_KEEPCAPS = 8
    PR_GET_FPEMU = 9
    PR_SET_FPEMU = 10
    PR_FPEMU_NOPRINT = 1
    PR_FPEMU_SIGFPE = 2
    PR_GET_FPEXC = 11
    PR_SET_FPEXC = 12
    PR_FP_EXC_SW_ENABLE = 0x80
    PR_FP_EXC_DIV = 0x010000
    PR_FP_EXC_OVF = 0x020000
    PR_FP_EXC_UND = 0x040000
    PR_FP_EXC_RES = 0x080000
    PR_FP_EXC_INV = 0x100000
    PR_FP_EXC_DISABLED = 0
    PR_FP_EXC_NONRECOV = 1
    PR_FP_EXC_ASYNC = 2
    PR_FP_EXC_PRECISE = 3
    PR_GET_TIMING = 13
    PR_SET_TIMING = 14
    PR_TIMING_STATISTICAL = 0
    PR_TIMING_TIMESTAMP = 1
    PR_SET_NAME = 15
    PR_GET_NAME = 16
    PR_GET_ENDIAN = 19
    PR_SET_ENDIAN = 20
    PR_ENDIAN_BIG = 0
    PR_ENDIAN_LITTLE = 1
    PR_ENDIAN_PPC_LITTLE = 2
    PR_GET_SECCOMP = 21
    PR_SET_SECCOMP = 22
    PR_CAPBSET_READ = 23
    PR_CAPBSET_DROP = 24
    PR_GET_TSC = 25
    PR_SET_TSC = 26
    PR_TSC_ENABLE = 1
    PR_TSC_SIGSEGV = 2
    PR_GET_SECUREBITS = 27
    PR_SET_SECUREBITS = 28
    PR_SET_TIMERSLACK = 29
    PR_GET_TIMERSLACK = 30
    PR_TASK_PERF_EVENTS_DISABLE = 31
    PR_TASK_PERF_EVENTS_ENABLE = 32
    PR_MCE_KILL = 33
    PR_MCE_KILL_CLEAR = 0
    PR_MCE_KILL_SET = 1
    PR_MCE_KILL_LATE = 0
    PR_MCE_KILL_EARLY = 1
    PR_MCE_KILL_DEFAULT = 2
    PR_MCE_KILL_GET = 34
    PR_SET_MM = 35
    PR_SET_MM_START_CODE = 1
    PR_SET_MM_END_CODE = 2
    PR_SET_MM_START_DATA = 3
    PR_SET_MM_END_DATA = 4
    PR_SET_MM_START_STACK = 5
    PR_SET_MM_START_BRK = 6
    PR_SET_MM_BRK = 7
    PR_SET_MM_ARG_START = 8
    PR_SET_MM_ARG_END = 9
    PR_SET_MM_ENV_START = 10
    PR_SET_MM_ENV_END = 11
    PR_SET_MM_AUXV = 12
    PR_SET_MM_EXE_FILE = 13
    PR_SET_MM_MAP = 14
    PR_SET_MM_MAP_SIZE = 15
    PR_SET_PTRACER = 0x59616D61
    # PR_SET_PTRACER_ANY          = ((unsigned long)-1)
    PR_SET_CHILD_SUBREAPER = 36
    PR_GET_CHILD_SUBREAPER = 37
    PR_SET_NO_NEW_PRIVS = 38
    PR_GET_NO_NEW_PRIVS = 39
    PR_GET_TID_ADDRESS = 40
    PR_SET_THP_DISABLE = 41
    PR_GET_THP_DISABLE = 42
    PR_MPX_ENABLE_MANAGEMENT = 43
    PR_MPX_DISABLE_MANAGEMENT = 44
    PR_SET_FP_MODE = 45
    PR_GET_FP_MODE = 46
    PR_FP_MODE_FR = 1
    PR_FP_MODE_FRE = 2
    PR_CAP_AMBIENT = 47
    PR_CAP_AMBIENT_IS_SET = 1
    PR_CAP_AMBIENT_RAISE = 2
    PR_CAP_AMBIENT_LOWER = 3
    PR_CAP_AMBIENT_CLEAR_ALL = 4
    PR_SVE_SET_VL = 50
    PR_SVE_SET_VL_ONEXEC = 0x40000
    PR_SVE_GET_VL = 51
    PR_SVE_VL_LEN_MASK = 0xFFFF
    PR_SVE_VL_INHERIT = 0x20000
    PR_GET_SPECULATION_CTRL = 52
    PR_SET_SPECULATION_CTRL = 53
    PR_SPEC_STORE_BYPASS = 0
    PR_SPEC_INDIRECT_BRANCH = 1
    PR_SPEC_NOT_AFFECTED = 0
    PR_SPEC_PRCTL = 0x00000001
    PR_SPEC_ENABLE = 0x00000002
    PR_SPEC_DISABLE = 0x00000004
    PR_SPEC_FORCE_DISABLE = 0x00000008
    PR_SPEC_DISABLE_NOEXEC = 0x00000010
    PR_PAC_RESET_KEYS = 54
    PR_PAC_APIAKEY = 0x00000001
    PR_PAC_APIBKEY = 0x00000002
    PR_PAC_APDAKEY = 0x00000004
    PR_PAC_APDBKEY = 0x00000008
    PR_PAC_APGAKEY = 0x00000010


class SIGINFO(ctypes.Structure):
    _fields_ = [
        ("si_signo", ctypes.c_int32),
        ("si_errno", ctypes.c_int32),
        ("si_code", ctypes.c_int32),
        ("si_trapno", ctypes.c_int32),
        ("si_pid", ctypes.c_int32),  # pid_t
    ]


"""
('sin6_family', ctypes.c_ushort),
('sin6_port', ctypes.c_ushort),
('sin6_flowinfo', ctypes.c_uint32),
('sin6_addr', ctypes.c_uint64),
('sin6_scope_id', ctypes.c_uint32),
"""


class SIGAction(enum.IntEnum):
    SI_USER = 0
    SI_KERNEL = 0x80
    SI_QUEUE = -1
    SI_TIMER = -2
    SI_MESGQ = -3
    SI_ASYNCIO = -4
    SI_SIGIO = -5
    SI_TKILL = -6
    SI_DETHREAD = -7
    SI_ASYNCNL = -60
    ILL_ILLOPC = 1
    ILL_ILLOPN = 2
    ILL_ILLADR = 3
    ILL_ILLTRP = 4
    ILL_PRVOPC = 5
    ILL_PRVREG = 6
    ILL_COPROC = 7
    ILL_BADSTK = 8
    ILL_BADIADDR = 9
    __ILL_BREAK = 10
    __ILL_BNDMOD = 11
    NSIGILL = 11
    FPE_INTDIV = 1
    FPE_INTOVF = 2
    FPE_FLTDIV = 3
    FPE_FLTOVF = 4
    FPE_FLTUND = 5
    FPE_FLTRES = 6
    FPE_FLTINV = 7
    FPE_FLTSUB = 8
    __FPE_DECOVF = 9
    __FPE_DECDIV = 10
    __FPE_DECERR = 11
    __FPE_INVASC = 12
    __FPE_INVDEC = 13
    FPE_FLTUNK = 14
    FPE_CONDTRAP = 15
    NSIGFPE = 15
    SEGV_MAPERR = 1
    SEGV_ACCERR = 2
    SEGV_BNDERR = 3
    SEGV_PKUERR = 4
    SEGV_ACCADI = 5
    SEGV_ADIDERR = 6
    SEGV_ADIPERR = 7
    NSIGSEGV = 7
    BUS_ADRALN = 1
    BUS_ADRERR = 2
    BUS_OBJERR = 3
    BUS_MCEERR_AR = 4
    BUS_MCEERR_AO = 5
    NSIGBUS = 5
    TRAP_BRKPT = 1
    TRAP_TRACE = 2
    TRAP_BRANCH = 3
    TRAP_HWBKPT = 4
    TRAP_UNK = 5
    NSIGTRAP = 5
    CLD_EXITED = 1
    CLD_KILLED = 2
    CLD_DUMPED = 3
    CLD_TRAPPED = 4
    CLD_STOPPED = 5
    CLD_CONTINUED = 6
    NSIGCHLD = 6
    POLL_IN = 1
    POLL_OUT = 2
    POLL_MSG = 3
    POLL_ERR = 4
    POLL_PRI = 5
    POLL_HUP = 6
    NSIGPOLL = 6
    SYS_SECCOMP = 1
    NSIGSYS = 1
    EMT_TAGOVF = 1
    NSIGEMT = 1
    SIGEV_SIGNAL = 0
    SIGEV_NONE = 1
    SIGEV_THREAD = 2
    SIGEV_THREAD_ID = 4
