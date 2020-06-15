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

"""Implementation of feeds.

Feeds are a way to subscribe to information that is retrieved from a
dynamic execution of a binary, while respecting the performance
optimizations that have been requested by the user. This way, a user can
specify what kinds of information should be collected (each with their
own performance cost) in a global way, without having to configure
multiple plugins separately.

To start with, there are different levels of feeds, each increasing in
amount of verbosity as well as performance cost::

                     -> Verbosity ->
            None -> Syscalls -> Functions -> Instructions
                    <- Performance <-

The feed level determines what feeds are supplied with information. All
feeds that are more verbose than the feed level are not provided data,
and will not run subscribed callbacks.

Example:
    When the feed level is FeedLevel.FUNC, subscribers to the syscall and
    func feeds will be run, but no calls to inst feed subscribers will be
    made.

Feeds are made more powerful by command line arguments that provide ways
to modify the feed level based on events and conditions. This allows the
user to specify that only instructions between certain regions should be
collected. The conditions are specified through the
--(stop|syscall|func|inst)_feed command line flags.

Example:
    To trigger instructions to be printed only after the 'recv' syscall
    has been called, specify '--inst_feed=syscall=recv' on the command
    line. For a script, add 'inst_feed="syscall=recv"' as a keyword
    argument in the Zelos constructor.

For more information on what options are available for configuring feeds
look at the zelos.zml module.
"""


import functools

from enum import IntEnum
from typing import Any, Callable, Dict

from zelos.hooks import HookManager, HookType
from zelos.zml import ZmlParser


class FeedLevel(IntEnum):
    NONE = 0
    SYSCALL = 1
    FUNC = 2
    INST = 3


class FeedHandle:
    """
    Returned when subscribing to a feed. Used for unsubscribing to a
    feed.
    """

    def __init__(self, feed_level, num):
        self._feed_level = feed_level
        self._num = num


class FeedManager:
    """
    Handles feed subscribers as well as the feed level.

    Subscription is handled by passing a callback to the subscribe_to_*
    functions.
    """

    def __init__(
        self, config, zml_parser: ZmlParser, hook_manager: HookManager
    ):
        self._hook_manager = hook_manager

        # _inst_hook_info is only present when the inst feed is active.
        self._inst_hook_info = None

        self._feed_level = None

        self._handle_num = 0
        self._subscribers: Dict[FeedLevel, Dict[int, Callable]] = {
            FeedLevel.SYSCALL: {},
            FeedLevel.FUNC: {},
            FeedLevel.INST: {},
        }

        # For initial setup, we want to respect the highest level set if
        # multiple are set to trigger immediately. We run them from
        # lowest to highest to achieve this goal
        for zml_string in config.no_feeds:
            zml_parser.trigger_on_zml(
                functools.partial(self.set_feed_level, FeedLevel.NONE),
                zml_string,
            )

        for zml_string in config.func_feed:
            zml_parser.trigger_on_zml(
                functools.partial(self.set_feed_level, FeedLevel.FUNC),
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

        # Default to feed level SYSCALL, unless another feed level was
        # specified
        if self._feed_level is None:
            if config.inst:
                self.set_feed_level(FeedLevel.INST)
            elif config.func:
                self.set_feed_level(FeedLevel.FUNC)
            else:
                self.set_feed_level(FeedLevel.SYSCALL)

    @property
    def inst_feed_on(self) -> bool:
        return self._feed_level >= FeedLevel.INST

    @property
    def func_feed_on(self) -> bool:
        return self._feed_level >= FeedLevel.FUNC

    @property
    def syscall_feed_on(self) -> bool:
        return self._feed_level >= FeedLevel.SYSCALL

    def get_feed_level(self) -> FeedLevel:
        return self._feed_level

    def set_feed_level(self, feed_level: FeedLevel):
        if feed_level == self._feed_level:
            return
        self._feed_level = feed_level
        self._refresh_inst_feed()
        # Syscall feed and func feed do not require refresh upon
        # changing feed level.

    def subscribe_to_inst_feed(
        self, callback: Callable[["Zelos", int, int], Any]
    ) -> FeedHandle:
        return self._subscribe(FeedLevel.INST, callback)

    # TODO: Support func feeds.
    def subscribe_to_func_feed(self, callback) -> FeedHandle:
        return self._subscribe(FeedLevel.FUNC, callback)

    def subscribe_to_syscall_feed(
        self, callback: Callable[["Zelos", str, "Args", int], Any]
    ) -> FeedHandle:
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

    def _handle_syscall_feed(self, zelos, sysname, args, retval):
        if self._feed_level >= FeedLevel.SYSCALL:
            for s in self._subscribers[FeedLevel.SYSCALL].values():
                s(zelos, sysname, args, retval)
