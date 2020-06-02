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

from __future__ import absolute_import

import unittest

from os import path

from zelos import Zelos
from zelos.feeds import FeedLevel


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class TraceTest(unittest.TestCase):
    def test_feed_level(self):
        z = Zelos(None)

        feeds = z.internal_engine.feeds
        self.assertEqual(feeds.get_feed_level(), FeedLevel.SYSCALL)
        self.assertFalse(feeds.inst_feed_on)
        self.assertFalse(feeds.api_feed_on)
        self.assertTrue(feeds.syscall_feed_on)

        feeds.set_feed_level(FeedLevel.API)
        self.assertFalse(feeds.inst_feed_on)
        self.assertTrue(feeds.api_feed_on)
        self.assertTrue(feeds.syscall_feed_on)

        feeds.set_feed_level(FeedLevel.INST)
        self.assertTrue(feeds.inst_feed_on)
        self.assertTrue(feeds.api_feed_on)
        self.assertTrue(feeds.syscall_feed_on)

        feeds.set_feed_level(FeedLevel.NONE)
        self.assertFalse(feeds.inst_feed_on)
        self.assertFalse(feeds.api_feed_on)
        self.assertFalse(feeds.syscall_feed_on)

    def test_syscall_subscribe(self):
        z = Zelos(
            path.join(DATA_DIR, "static_elf_helloworld"),
            syscall_feed="syscall=set_thread_area",
            stop_feed="syscall=readlink",
            inst_feed="syscall=fstat64",
            api_feed="syscall=write",
        )

        feeds = z.internal_engine.feeds

        syscalls = []

        def syscall_feed_subscriber(zelos, sysname, args, retval):
            syscalls.append(sysname)

        feeds.subscribe_to_syscall_feed(syscall_feed_subscriber)

        syscalls2 = []

        def syscall_feed_subscriber2(zelos, sysname, args, retval):
            syscalls2.append(sysname)

        handle = feeds.subscribe_to_syscall_feed(syscall_feed_subscriber2)
        feeds.unsubscribe_from_feed(handle)

        insts = []

        def inst_feed_subscriber(zelos, addr, size):
            insts.append(addr)

        feeds.subscribe_to_inst_feed(inst_feed_subscriber)

        apis = []

        def api_feed_subscriber(zelos, apiname, args, retval):
            apis.append(apiname)

        feeds.subscribe_to_api_feed(api_feed_subscriber)

        z.start()

        self.assertEqual(syscalls2, [])
        self.assertEqual(
            syscalls,
            [
                "set_thread_area",
                "uname",
                "fstat64",
                "ioctl",
                "write",
                "exit_group",
            ],
        )
        self.assertEqual(insts[0], 0x81356E2)
        self.assertEqual(insts[-1], 0x81356E0)
        # TODO: Update 'apis' check once we support api feeds.
        self.assertEqual(apis, [])
