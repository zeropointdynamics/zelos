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
import threading
import xmlrpc

from xmlrpc.server import SimpleXMLRPCServer

import zelos


DEFAULT_INTERFACE = "localhost"
DEFAULT_PORT = 62433

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("zdbserver")


class ZdbServer:
    """
    Zelos Remote Debug Server.

    Provides remote access to a target running in `zelos` over `xmlrpc`.
    Numbers are represented as strings for arguments and return values,
    e.g. '0x1234' or '4660' to support 64-bit numbers, which are
    otherwise not serialized by `xmlrpc`.

    The `zdbserver` can be run from the command-line via
    `python -m zelos.tools.zdbserver ZELOS_ARGUMENTS`.
    """

    def __init__(self, z: zelos.Zelos):
        self.z = z

    def read_memory(self, address: str, nbytes: int) -> xmlrpc.client.Binary:
        """
        Reads specified region of memory.

        Args:
            address: Address to start reading from.
            nbytes: Number of bytes to read.

        Returns:
            Binary data corresponding to data held in memory.
        """
        address = int(address, 0)
        logger.debug(f"[debug] read_memory(0x{address:x}, 0x{nbytes:x})")
        data = self.z.memory.read(address, nbytes)
        return xmlrpc.client.Binary(data)

    def write_memory(self, address: str, value: xmlrpc.client.Binary) -> int:
        """
        Writes specified bytes to memory.

        Args:
            address: Address to start writing data to.
            value: Binary data to write in memory.

        Returns:
            The number of bytes written.
        """
        address = int(address, 0)
        logger.debug(f"[debug] write_memory(0x{address:x}, {value.data})")
        return self.z.memory.write(address, value.data)

    def read_register(self, register: str) -> str:
        """
        Reads specified register from of the current thread.

        Args:
            register: String representation of the register name.

        Returns:
            Value of the specified register.
        """
        logger.debug(f"[debug] read_register('{register}')")
        register = register.lower()
        if register == "pc":
            return f"0x{self.z.regs.getIP():x}"
        return f"0x{self.z.regs[register]:x}"

    def write_register(self, register: str, value: str) -> str:
        """
        Writes specified register of the current thread.

        Args:
            register: String representation of the register name.
            value: register value to set.

        Returns:
            The value written to the register.
        """
        logger.debug(f"[debug] write_register('{register}', {value})")
        int_value = int(value, 0)
        register = register.lower()
        if register == "pc":
            self.z.regs.setIP(int_value)
        else:
            self.z.regs[register] = int_value
        return value

    def set_breakpoint(self, address: str, temporary: bool) -> bool:
        """
        Set a breakpoint at a particular address.

        Args:
            address: Target address of breakpoint.
            temporary: Determines whether or not the breakpoint is
                temporary. A temporary breakpoint will be automatically
                removed after use.

        Returns:
            True if no exception occurred.
        """
        address = int(address, 0)
        logger.debug(f"[debug] set_breakpoint(0x{address:x}, {temporary})")
        self.z.set_breakpoint(address, temporary)
        return True

    def remove_breakpoint(self, address: str) -> bool:
        """
        Remove a previously set breakpoint.

        Args:
            address: Target address of breakpoint to remove.

        Returns:
            True if no exception occurred.
        """
        address = int(address, 0)
        logger.debug(f"[debug] remove_breakpoint(0x{address:x})")
        self.z.remove_breakpoint(address)
        return True

    def set_watchpoint(
        self, address: str, read: bool, write: bool, temporary: bool
    ) -> bool:
        """
        Set a watchpoint on a particular memory address.

        Args:
            address: Target address of watchpoint.
            read: Determines whether to watch for reads to the target
                memory address.
            write: Determines whether to watch for writes to the target
                memory address.
            temporary: Determines whether or not the watchpoint is
                temporary. A temporary watchpoint will be automatically
                removed after use.

        Returns:
            True if no exception occurred.
        """
        address = int(address, 0)
        logger.debug(f"[debug] set_watchpoint(0x{address:x}, {read}, {write})")
        self.z.set_watchpoint(address, read, write, temporary)
        return True

    def remove_watchpoint(self, address: str) -> bool:
        """
        Remove a previously set watchpoint.

        Args:
            address: Target address of watchpoint to remove.

        Returns:
            True if no exception occurred.
        """
        address = int(address, 0)
        logger.debug(f"[debug] remove_watchpoint(0x{address:x})")
        self.z.remove_watchpoint(address)
        return True

    def get_mappings(self) -> list:
        """
        Gets the memory region mappings.

        Returns:
            A list of the current memory regions.
        """
        logger.debug(f"[debug] get_mappings()")
        vmmap = []
        regions = self.z.memory.get_regions()
        for region in regions:
            entry = {
                "start_address": f"0x{region.start:x}",
                "end_address": f"0x{region.end:x}",
            }
            vmmap.append(entry)
        return vmmap

    def run(self) -> dict:
        """
        Run until a break condition is encountered.

        Returns:
            Information about the break condition in the format:

            .. code-block:: python

                break_state = {
                    'pc': INT,
                    'syscall': {
                        'name': STR,
                        'args': [
                            { 'type': STR, 'name': STR, 'value': INT },
                            ...
                        ],
                        'retval': INT,
                        'retval_register': STR,
                    },
                    'bits': INT,
                }

        """
        logger.debug(f"[debug] run()")
        break_state = self.z.start()
        # Format break_state for RPC by converting `None` and Numbers to
        # RPC-serializable values.
        if break_state is None:
            return {}
        break_state["pc"] = f"0x{break_state['pc']:x}"
        if break_state.get("syscall", None) is None:
            break_state["syscall"] = {}
        else:
            break_state["syscall"][
                "retval"
            ] = f"0x{break_state['syscall']['retval']:x}"
            for arg in break_state["syscall"]["args"]:
                arg["value"] = f"0x{arg['value']:x}"
        return break_state

    def stop(self) -> bool:
        """
        Stop running.

        Returns:
            True if no exception occurred.
        """
        logger.debug(f"[debug] stop()")
        self.z.stop("debug stop")
        return True

    def set_syscall_breakpoint(self, name: str) -> bool:
        """
        Set a breakpoint at all syscalls of a specified name. Breaks
        will occur *after* the syscall has completed and PC has
        advanced to the next instruction.

        Args:
            name: Target syscall to set breakpoint at.

        Returns:
            True if no exception occurred.
        """
        logger.debug(f"[debug] set_syscall_breakpoint({name})")
        self.z.set_syscall_breakpoint(name)
        return True

    def remove_syscall_breakpoint(self, name: str) -> bool:
        """
        Remove a previously set syscall breakpoint specified by name.

        Args:
            name: Target syscall to remove breakpoints from.

        Returns:
            True if no exception occurred.
        """
        logger.debug(f"[debug] remove_syscall_breakpoint({name})")
        self.z.remove_syscall_breakpoint(name)
        return True

    def get_filepath(self) -> str:
        """
        Get the file path of the emulated binary.

        Returns:
            The full path to the emulated binary.
        """
        return self.z.target_binary_path


def create_server(cmdline_options: str) -> SimpleXMLRPCServer:
    """
    Starts the `zdbserver`.

    Args:
        cmdline_options: Zelos command-line options used to initialize
            zelos.

    Returns:
        A `SimpleXMLRPCServer` that will handle requests once
        `serve_forever` is called on it.
    """
    zelos.CommandLineOption(
        "debug_interface",
        type=str,
        default=DEFAULT_INTERFACE,
        help="debug network interface",
    )
    zelos.CommandLineOption(
        "debug_port", type=int, default=DEFAULT_PORT, help="debug network port"
    )
    z = zelos.ZelosCmdline(cmdline_options)
    dbg = ZdbServer(z)
    rpc = SimpleXMLRPCServer(
        (z.config.debug_interface, z.config.debug_port), logRequests=False
    )

    def server_shutdown():
        threading.Thread(target=rpc.shutdown).start()
        return True

    rpc.register_introspection_functions()
    rpc.register_instance(dbg)
    rpc.register_function(server_shutdown)
    uri = f"http://{z.config.debug_interface}:{z.config.debug_port}"
    logger.info(f"zelos debug server @ {uri}")
    return rpc
