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

import os

from typing import Optional

import configargparse

from zelos.plugin import PluginCommands


def generate_config(
    binary_path: Optional[str], *cmdline_args: str, **kwargs: str
):
    """
    Generates a config used to modify the analysis run by Zelos. The
    config uses the same options present in the command line flags.

    Args:
        binary_path: Relative or absolute filepath to binary
        cmdline_args: Command line arguments that will be passed to the
            binary.
        kwargs: Additional options to specify corresponding to command
            line flags

    Returns:
        Config that can be used to initialize Zelos.
    """

    if binary_path is None:
        return _generate_without_binary(**kwargs)
    flags = []
    for k, v in kwargs.items():
        if v in [False, True]:
            flags.append(f"--{k}")
        else:
            flags.append(f"--{k}={v}")
    flag_string = " ".join(flags)

    cmdline_arg_string = " ".join(cmdline_args)
    return generate_config_from_cmdline(
        f"{flag_string} {binary_path} {cmdline_arg_string}"
    )


def _generate_without_binary(**kwargs):
    # Generating a config without a binary should only be done when
    # testing zelos. A file is required when using zelos, pass in a fake
    # file and then overwrite that field immediately after. We can
    # consider removing this requirement and doing manual checking after
    # getting the config
    config = generate_config("NOFILE", **kwargs)
    config.filename = ""
    return config


def generate_parser():
    parser = configargparse.ArgumentParser()
    group_logging = parser.add_argument_group("logging")
    group_reporting = parser.add_argument_group("reporting")
    group_limits = parser.add_argument_group("limits")
    group_networking = parser.add_argument_group("networking")
    group_fs = parser.add_argument_group("filesystem")
    group_clock = parser.add_argument_group("clock")
    parser.add("-c", "--config", is_config_file=True, help="config file path")
    group_fs.add_argument(
        "--virtual-filename",
        type=str,
        default=None,
        help="Emulated filename (if different from real filename).",
    )
    group_fs.add_argument(
        "--virtual-path",
        type=str,
        default=None,
        help="Emulated file path (optional). "
        "(default: '/home/admin/zelos_dir/').",
    )
    group_logging.add_argument(
        "-v",
        "--verbosity",
        action="count",
        default=0,
        help="Increase output verbosity. Enables instruction-level tracing.",
    )
    group_logging.add_argument(
        "--log",
        type=str,
        default="info",
        help="Decide what level of logging should be used. LOG is "
        "'info', 'verbose', 'debug', 'spam', 'notice', 'warning', 'success', "
        "'error', or 'fatal'. Note that this does not affect "
        "verbosity. (default: 'info')",
    )
    group_networking.add_argument(
        "--dns",
        action="count",
        default=0,
        help="Simulate DNS response for all domains (resolve to 127.0.0.1)",
    )
    group_logging.add_argument(
        "--fasttrace",
        action="count",
        default=0,
        help="Enable instruction-level tracing only the first time a memory "
        "address is reached.",
    )
    group_limits.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=0,
        help="If specified, execution will end after TIMEOUT seconds have "
        "passed.",
    )
    group_limits.add_argument(
        "-m",
        "--memlimit",
        type=int,
        default=0,
        help="Limits memory allocation to MEMLIMIT total mb.",
    )
    group_logging.add_argument(
        "--traceon",
        type=str,
        default="",
        help="[Experimental] Enable verbose tracing after specified address "
        "or API name.",
    )
    group_logging.add_argument(
        "--traceoff",
        type=str,
        default="",
        help="[Experimental] Disable verbose tracing after "
        "specified address or API name.",
    )
    group_logging.add_argument(
        "--tracethread",
        type=str,
        default="",
        help="[Experimental] Enable verbose tracing on a single thread.",
    )
    group_logging.add_argument(
        "--writetrace",
        type=str,
        default="",
        help="Print a message every time a value at the given memory "
        "location is written.",
    )
    group_clock.add_argument(
        "--date",
        type=str,
        default="2019-02-02",
        help="Emulated system date. Format: YYYY-MM-DD. "
        "(default: '2019-02-02')",
    )
    parser.add_argument(
        "--startat",
        type=str,
        default=None,
        help="[Experimental] Start execution at the given hex address.",
    )
    parser.add_argument(
        "--disableNX",
        action="store_true",
        help="Disable the no-execute bit. All memory becomes executable.",
    )
    group_reporting.add_argument(
        "--strace",
        type=str,
        default=None,
        help="Writes the system call trace to the specified output file.",
    )
    group_logging.add_argument(
        "--log_exports",
        action="store_true",
        help="Enable logging of calls to exported functions. (default: off)",
    )
    group_fs.add_argument(
        "--mount",
        action="append",
        default=[],
        help="[Experimental] Mount the specified file or path into the "
        "emulated root filesystem. Format: '--mount ARCH,DEST,"
        "SRC'. ARCH is 'x86', 'x86-64', 'arm', or 'mips'. "
        "DEST is the emulated path to mount. SRC is the absolute host path to "
        "the file or directory to mount. Can be specified multiple times to "
        "mount multiple files.",
    )
    group_fs.add_argument(
        "--env_vars",
        action="append",
        default=[],
        help="Emulated environment variables. ENV_VARS is a comma separated "
        "key value pair. Can be specified multiple times to set multiple "
        "environment variables. Format: '--env_vars FOO:bar --env_vars "
        "ZERO:point'.",
    )

    path = os.environ.get("ZELOS_PLUGIN_DIR", None)
    paths = path.split(",") if path is not None else []
    _ = PluginCommands(paths, parser)

    parser.add_argument("filename", type=str, help="Executable to emulate")
    parser.add_argument(
        "cmdline_args", type=str, nargs="*", help="Arguments to the executable"
    )
    return parser


def generate_config_from_cmdline(cmdline_string):
    parser = generate_parser()
    config = parser.parse_args(cmdline_string)

    return config
