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
import dnslib


# Code that is used to aid dns parsing.


def parse_dns_request(raw_packet_data):
    try:
        d = str(
            dnslib.DNSRecord.parse(raw_packet_data).get_q().get_qname()
        ).rstrip(".")
        return str(d)
    except Exception as e:
        print("DNS_INVALID:", e)
    return None


def parse_dns_response(raw_packet_data):
    try:
        d = str(
            dnslib.DNSRecord.parse(raw_packet_data).get_a().get_rname()
        ).rstrip(".")
        print("DNS_RESPONSE:", str(d))
        return str(d)
    except Exception as e:
        print("DNS_INVALID:", e)
    if len(str(d)) == 0:
        return None
    return None


def create_dns_response(hostname="google.com", ip=None):
    """
    Create a DNS response packet for the specified hostname. If `ip` is
    specified (as a string, e.g., '127.0.0.1'), it will be used for the
    response. Otherwise, a not found (NXDOMAIN) response is returned.
    """
    try:
        if ip is None:
            d = dnslib.DNSRecord(
                dnslib.DNSHeader(qr=1, aa=1, ra=1, rcode=3),
                q=dnslib.DNSQuestion(hostname),
            )
        else:
            d = dnslib.DNSRecord(
                dnslib.DNSHeader(qr=1, aa=1, ra=1),
                q=dnslib.DNSQuestion(hostname),
                a=dnslib.RR(hostname, rdata=dnslib.A(ip)),
            )
        return d.pack()
    except Exception as e:
        print("DNS_CREATE failed:", e)
    return None
