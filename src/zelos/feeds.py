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


import functools
import logging

from enum import IntEnum
from typing import Callable, Dict

from zelos.hooks import HookManager, HookType
from zelos.zml import ZmlParser


class FeedLevel(IntEnum):
    NONE = 0
    SYSCALL = 1
    API = 2
    INST = 3


class FeedHandle:
    def __init__(self, feed_level, num):
        self._feed_level = feed_level
        self._num = num


class FeedManager:
    def __init__(
        self, config, zml_parser: ZmlParser, hook_manager: HookManager
    ):
        self._hook_manager = hook_manager
        self.logger = logging.getLogger(__name__)

        # _inst_hook_info is only present when the inst feed is active.
        self._inst_hook_info = None
        # The syscall hook must be registered later
        self._syscall_hook_info = None

        self._feed_level = FeedLevel.NONE

        self._handle_num = 0
        self._subscribers: Dict[FeedLevel, Dict[int, Callable]] = {
            FeedLevel.SYSCALL: {},
            FeedLevel.API: {},
            FeedLevel.INST: {},
        }

        # Default to feed level SYSCALL, unless plans for the syscall
        # level feed were already specified.
        if len(config.syscall_feed) == 0:
            self.set_feed_level(FeedLevel.SYSCALL)

        # For initial setup, we want to respect the highest level set if
        # multiple are set to trigger immediately. We run them from
        # lowest to highest to achieve this goal
        for zml_string in config.stop_feed:
            zml_parser.trigger_on_zml(
                functools.partial(self.set_feed_level, FeedLevel.NONE),
                zml_string,
            )

        for zml_string in config.api_feed:
            zml_parser.trigger_on_zml(
                functools.partial(self.set_feed_level, FeedLevel.API),
                zml_string,
            )

        for zml_string in config.syscall_feed:
            zml_parser.trigger_on_zml(
                functools.partial(self.set_feed_level, FeedLevel.SYSCALL),
                zml_string,
            )

        for zml_string in config.inst_feed:
            zml_parser.trigger_on_zml(
                functools.partial(self.set_feed_level, FeedLevel.INST),
                zml_string,
            )

        # TODO: Turning on the syscall feed from a syscall hook skips
        # the printing of the syscall it triggered on depening on the
        # order of registration of the syscall hooks. (Of course,
        # this could be fixed with a before hook)
        self._syscall_hook_info = hook_manager.register_syscall_hook(
            HookType.SYSCALL.AFTER,
            self._syscall_feed_hook,
            name="syscall_hook",
        )

    @property
    def inst_feed_on(self) -> bool:
        return self._feed_level >= FeedLevel.INST

    @property
    def api_feed_on(self) -> bool:
        return self._feed_level >= FeedLevel.API

    @property
    def syscall_feed_on(self) -> bool:
        return self._feed_level >= FeedLevel.SYSCALL

    def get_feed_level(self) -> FeedLevel:
        return self._feed_level

    def set_feed_level(self, feed_level: FeedLevel):
        self._feed_level = feed_level
        self._refresh_inst_feed()
        self._refresh_api_feed()
        self._refresh_syscall_feed()

    def subscribe_to_inst_feed(self, callback) -> FeedHandle:
        return self._subscribe(FeedLevel.INST, callback)

    def subscribe_to_api_feed(self, callback) -> FeedHandle:
        return self._subscribe(FeedLevel.API, callback)

    def subscribe_to_syscall_feed(self, callback) -> FeedHandle:
        return self._subscribe(FeedLevel.SYSCALL, callback)

    def _subscribe(self, feed_level: FeedLevel, callback):
        handle = self._gen_handle(feed_level)
        self._subscribers[feed_level][handle._num] = callback
        return handle

    def unsubscribe_from_feed(self, handle: FeedHandle):
        del self._subscribers[handle._feed_level][handle._num]

    def _gen_handle(self, feed_level: FeedLevel) -> int:
        self._handle_num += 1
        return FeedHandle(feed_level, self._handle_num)

    def _inst_feed_hook(self, zelos, address, size):
        for s in self._subscribers[FeedLevel.INST].values():
            s(zelos, address, size)

    def _refresh_inst_feed(self):
        should_be_on = self._feed_level >= FeedLevel.INST
        currently_on = self._inst_hook_info is not None

        if should_be_on and not currently_on:
            self._inst_hook_info = self._hook_manager.register_exec_hook(
                HookType.EXEC.INST, self._inst_feed_hook, name="inst_feed"
            )
        elif not should_be_on and currently_on:
            self._hook_manager.delete_hook(self._inst_hook_info)
            self._inst_hook_info = None

    def _refresh_api_feed(self):
        pass

    def _syscall_feed_hook(self, zelos, sysname, args, retval):
        if self._feed_level >= FeedLevel.SYSCALL:
            for s in self._subscribers[FeedLevel.SYSCALL].values():
                s(zelos, sysname, args, retval)

    def _refresh_syscall_feed(self):
        # Handled in _syscall_feed_hook
        pass
