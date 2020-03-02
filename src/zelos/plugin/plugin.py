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

import inspect
import logging
import pkgutil

from collections import defaultdict
from os.path import isabs
from typing import Callable

import zelos.ext.platforms
import zelos.ext.plugins

from zelos.exceptions import UnsupportedBinaryError
from zelos.manager import IManager


class IPlugin(IManager):
    """
    Base class for Plugins that provides an api for interacting with
    zelos objects.
    """

    def __init__(self, zelos):
        super().__init__(zelos.internal_engine.helpers)
        self.zelos = zelos

    def __init_subclass__(cls, **kwargs):
        Plugins.loaded_plugins.append(cls)
        super().__init_subclass__(**kwargs)


plugins_loaded = set()


def load(paths):
    """Loads the plugins that are located in the plugins directory."""
    global plugins_loaded

    # Load plugins that come with zelos
    paths += zelos.ext.plugins.__path__._path
    paths += zelos.ext.platforms.__path__._path

    paths = {p for p in paths if isabs(p) and p not in plugins_loaded}
    if len(paths) == 0:
        return

    for finder, name, _ in pkgutil.iter_modules(paths):
        try:
            _ = finder.find_module(name).load_module(name)
        except Exception as e:
            logging.getLogger(__name__).exception(
                f"Could not load plugin at '{name}': {e}"
            )
    plugins_loaded.update(paths)


class Plugins:
    """
    Plugins are set as attributes of this class for convenience.
    """

    loaded_plugins = []

    def __init__(self, zelos, paths):
        self.registered_plugins = {}
        self.logger = logging.getLogger(__name__)
        load(paths)
        self._zelos = zelos

        for p in self.loaded_plugins:
            self.register_plugin(p)
        print(f"Plugins: {', '.join(self.registered_plugins.keys())}")

    def register_plugin(
        self, plugin_class: Callable[["Zelos"], IPlugin]
    ) -> None:
        name = getattr(plugin_class, "NAME", plugin_class.__name__.lower())
        plugin = plugin_class(self._zelos)
        self.registered_plugins[name] = plugin
        setattr(self, name, plugin)
        self.logger.debug(f"Successfully registered plugin '{name}'")

    def get(self, plugin_name):
        return self.registered_plugins.get(plugin_name, None)

    def has(self, plugin_name):
        return hasattr(self, plugin_name)


class OSPlugin:
    def __init__(self, z):
        self.z = z
        self.logger = self.z.logger

    def __init_subclass__(cls, **kwargs):
        OSPlugins.unregistered_os_plugins.append(cls)

    def parse(self, *args, **kwargs):
        raise NotImplementedError

    def load(self, *args, **kwargs):
        raise NotImplementedError


class OSPlugins:
    unregistered_os_plugins = []

    def __init__(self, z):
        self.logger = z.logger
        self._registered_os_plugins = []
        self._register_plugins(z)
        self.chosen_os = None

    def _register_plugins(self, z):
        for p in self.unregistered_os_plugins:
            self._registered_os_plugins.append(p(z))
            name = p.__name__.lower()
            if hasattr(p, "NAME"):
                name = p.NAME
            self.logger.debug(
                f"Successfully registered platform plugin '{name}'"
            )

    def parse(self, path, binary):
        if self.chosen_os is not None:
            return self.chosen_os.parse(path, binary)

        for os_plugin in self._registered_os_plugins:
            parsed_file = os_plugin.parse(path, binary)
            if parsed_file is not None:
                self.chosen_os = os_plugin
                return parsed_file
        raise UnsupportedBinaryError(
            f"File {path} does not have a supported parser"
        )

    def load(self, file, process, entrypoint_override=None):
        if self.chosen_os is None:
            raise UnsupportedBinaryError(
                f"No supported parser was identified during parsing"
            )
        self.chosen_os.load(
            file, process, entrypoint_override=entrypoint_override
        )


class ISubcommand:
    # TODO: Subcommands need to be moved to scripts, then the ISubcommand
    # class can be deleted

    def __init__(self, argparser):
        self.logger = logging.getLogger(__name__)


class PluginCommands:
    registered_flags = defaultdict(dict)

    flags_to_resolve = []

    def __init__(self, paths, argparser):
        self.logger = logging.getLogger(__name__)
        load(paths)

        self._added_flags = {}
        for source_file, flags in self.registered_flags.items():
            arg_group = argparser.add_argument_group(source_file)
            self.add_flags(source_file, flags, arg_group)

    def add_flags(self, source_file_name, flags_dict, argparser):
        for name, args in flags_dict.items():
            if name in self._added_flags:
                self.logger.warning(
                    (
                        f"Skipped flag {name} from {source_file_name}, "
                        f"already defined in {self._added_flags[name]}"
                    )
                )
                continue
            argparser.add_argument(f"--{name}", **args)
            self._added_flags[name] = source_file_name


class CommandLineOption:
    """
    Registers a command line option for Zelos. The kwargs are those
    recognized by the argparse library
    """

    def __init__(self, name, **kwargs):
        stack = inspect.stack()
        frame = stack[1]

        PluginCommands.registered_flags[frame.filename][name] = kwargs
