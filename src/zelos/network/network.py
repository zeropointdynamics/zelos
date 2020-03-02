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
import logging

from zelos.handles import SocketHandle
from zelos.manager import IManager

from .base_socket import BaseSelect, BaseSocket


class Network(IManager):
    def __init__(self, helpers, file_manager, tracer):
        super().__init__(helpers)
        self.file_manager = file_manager
        self.trace = tracer
        self.logger = logging.getLogger(__name__)
        self.attempted_connections = set()
        self.num_sockets = 0

        self.ignore_whitelist = False
        self.whitelist = {
            "127.0.0.53": [53]
            # '8.8.8.8': [53]
        }

        # Entries in the DNS whitelist will always result in a
        # successful DNS response. If real networking is used, and the
        # domain is non-existant, the response will be replaced with a
        # default IP. This is useful for ensuring network checks for
        # common domains succeed.
        self.dns_whitelist = {"google.com", "pastebin.com", "virustotal.com"}
        # Entries in the DNS blacklist will always result in an NXDOMAIN
        # result, whether using real networking or Base sockets. This
        # is useful making it appear as if hardcoded C2 hosts are
        # unavailable, which often invokes DGA functionality.
        self.dns_blacklist = {}

        # When returning a fake DNS response, use this IP address in the
        # answer. This could be pointed to a network simulator.
        self.dns_default_ip = "45.45.45.45"

        # By default, return non-existant (NX) responses for all
        # domains, except those listed in the whitelist.
        self.dns_default_to_nx = True

        self.socket_class = BaseSocket
        self.select = BaseSelect(self)

    @property
    def sockets(self):
        return self.handles.get_by_type(SocketHandle)

    def set_socket_class(self, socket_class):
        """
        Allows network activity to be handled by a different socket
        class.
        """
        self.socket_class = socket_class

    def set_select_class(self, select_class):
        """
        Allows select/poll to be handled by a different class.
        """
        self.select = select_class(self)

    def add_attempted_connection(self, string, method):
        self.attempted_connections.add(string)
        self.triggers.tr_contacts_domain(string, method)

        if len(self.attempted_connections) > 10:
            self.triggers.tr_contacts_many_domains(self.attempted_connections)

    def create_socket(self, domain, type, protocol=0):
        sock = self.socket_class(self, domain, type, protocol)

        sock_handle_num = self.handles.new_socket(
            "sock#{0:03d}".format(self.num_sockets), sock
        )
        self.num_sockets += 1

        return sock_handle_num

    def enable_whitelist(self):
        self.ignore_whitelist = False

    def disable_whitelist(self):
        self.ignore_whitelist = True

    def is_whitelisted(self, host, port):
        """
        Returns if the host and port to connect is whitelisted
        """
        if host in self.whitelist:
            if self.whitelist[host] == -1:
                return True
            if port in self.whitelist[host]:
                return True
        return self.ignore_whitelist
