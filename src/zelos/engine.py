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
import ntpath
import os

from collections import namedtuple
from typing import Optional

import verboselogs
import zebracorn

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_MIPS,
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
    Cs,
)
from zebracorn import UcError

from zelos import util
from zelos.breakpoints import BreakpointManager, BreakState
from zelos.config_gen import _generate_without_binary, generate_config
from zelos.exceptions import UnsupportedBinaryError, ZelosLoadException
from zelos.feeds import FeedManager
from zelos.file_system import FileSystem
from zelos.hooks import ExceptionHooks, HookManager, HookType, InterruptHooks
from zelos.network import Network
from zelos.plugin import OSPlugins
from zelos.processes import Processes
from zelos.state import State
from zelos.triggers import Triggers
from zelos.zml import ZmlParser


class Engine:
    # Stack size
    # we need at least 0x80000 for some malware:
    # (ff07b93686aca11c9b3484f43b8b910306f30b52cc1c01638bfc16960038dd75)
    STACK_SIZE = 0x90000

    def __init__(self, config=None, api=None):
        self.api = api
        self.api.internal_engine = self
        if config is None:
            config = _generate_without_binary()
        if isinstance(config, str):
            config = generate_config(config)
        self.config = config

        binary = config.filename

        # Set provided arguments
        self.original_binary = binary
        self.cmdline_args = (
            [] if config.cmdline_args is None else config.cmdline_args
        )

        self.log_level = getattr(logging, config.log.upper(), None)
        if not isinstance(self.log_level, int):
            raise ValueError("Invalid log level: %s" % config.log)

        # To get different logs based on the level, read this:
        # https://stackoverflow.com/questions/14844970
        #   /modifying-logging-message-format-based-on-message-
        #   logging-level-in-python3
        self._init_logging(self.log_level)

        # If verbose is true, print lots of info, including every
        # instruction
        self.original_file_name = ""
        self.target_binary_path = ""
        self.main_module_name = ""
        self.main_module = None

        self.date = "2019-02-02"

        self.timer = util.Timer()

        self.zml_parser = ZmlParser(self.api)
        self.hook_manager = HookManager(self, self.api)
        self.feeds = FeedManager(
            self.config, self.zml_parser, self.hook_manager
        )
        self.breakpoints = BreakpointManager(self.hook_manager)
        self.interrupt_handler = InterruptHooks(self.hook_manager, self)
        self.exception_handler = ExceptionHooks(self)
        self.files = FileSystem(self, self.hook_manager, config.sandbox)
        self.processes = Processes(
            self.hook_manager,
            self.interrupt_handler,
            self.files,
            self.original_binary,
            self.STACK_SIZE,
            disableNX=self.config.disableNX,
        )

        self.os_plugins = OSPlugins(self)

        if binary is not None and binary != "":
            self.load_executable(binary, entrypoint_override=config.startat)
            self.hook_manager.on_entrypoint(self.hook_manager.setup_func_hooks)
        else:
            self._initialize_zelos()  # For testing purposes.
            # If no binary is passed, default to UNIX-style paths.
            self.files.setup("/")

        head, tail = ntpath.split(config.filename)
        original_filename = tail or ntpath.basename(head)
        self.original_file_name = original_filename
        self.date = config.date

        if config.dns > 0:
            self.flags_dns = True

        if config.writetrace != "":
            target_addr = int(config.writetrace, 16)
            self.set_writetrace(target_addr)
        if config.memlimit > 0:
            self.set_mem_limit(config.memlimit)
        for m in config.mount:
            try:
                arch, dest, src = m.split(",")
                # TODO: Use arch to determine when to mount
                if os.path.isdir(src):
                    self.files.mount_folder(src, emulated_path=dest)
                else:
                    self.files.add_file(src, emulated_path=dest)
            except ValueError:
                self.logger.error(
                    f"Incorrectly formatted input to '--mount': {m}"
                )
                continue

    def __del__(self):
        try:
            self.processes.handles.close_all()
        except Exception as e:
            print("Engine: could not close handles:", e)

    def _init_logging(self, initial_log_level):
        if initial_log_level is None:
            initial_log_level = verboselogs.logging.INFO
        verboselogs.install()
        # This will be the parent to all loggers in this project.
        logger = verboselogs.logging.getLogger("zelos")
        fmt = "{asctime}:{module:_<10.10s}:{levelname:_<6.6s}:{message}"
        datefmt = "%H:%M:%S"
        try:
            import coloredlogs

            coloredlogs.install(
                logger=logger,
                level=initial_log_level,
                fmt=fmt,
                datefmt=datefmt,
                style="{",
            )
        except ModuleNotFoundError:
            logger.error("You do not have the required coloredlogs dependency")
            console = verboselogs.logging.StreamHandler()
            # set a format which is simpler for console use
            formatter = verboselogs.logging.Formatter(fmt, datefmt, style="{")
            console.setFormatter(formatter)
            logger.addHandler(console)

        self.logger = logger

    def set_log_level(self, log_level):
        fmt = "{asctime}:{module:_<10.10s}:{levelname:_<6.6s}:{message}"
        datefmt = "%H:%M:%S"
        try:
            import coloredlogs

            coloredlogs.install(
                logger=self.logger,
                reconfigure=True,
                level=log_level,
                fmt=fmt,
                datefmt=datefmt,
                style="{",
            )
        except ModuleNotFoundError:
            self.logger.setLevel(log_level)

    def hexdump(self, address: int, size: int) -> None:
        import hexdump

        try:
            data = self.memory.read(address, size)
            hexdump.hexdump(data)
        except Exception:
            self.logger.exception("Invalid address range.")

    @property
    def current_process(self):
        return self.processes.current_process

    @property
    def emu(self):
        return self.current_process.emu

    @property
    def memory(self):
        return self.current_process.memory

    @property
    def scheduler(self):
        return self.current_process.scheduler

    @property
    def thread_manager(self):
        return self.current_process.threads

    @property
    def current_thread(self):
        return self.current_process.current_thread

    @property
    def loader(self):
        return self.current_process.loader

    @loader.setter
    def loader(self, loader):
        self.current_process.loader = loader

    @property
    def modules(self):
        return self.current_process.modules

    @property
    def handles(self):
        return self.processes.handles

    def set_mem_limit(self, limit_in_mb: int) -> None:
        limit = limit_in_mb * 1024 * 1024
        """ Sets the memory limit for the python process"""
        try:
            import resource

            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
        except ModuleNotFoundError:
            self.logger.error("Unable to set memory limit in Windows")

    def set_writetrace(self, target):
        def hook(zelos, access, address, size, value):
            if address == target:
                self.logger.error(
                    "[WRITE 0x%x] EIP: 0x%x: value 0x%x"
                    % (address, self.current_thread.getIP(), value)
                )

        self.hook_manager.register_mem_hook(
            HookType.MEMORY.WRITE, hook, name="write_trace"
        )

    def _first_parse(self, module_path):
        """ Function to parse an executable """
        self.logger.verbose("Parse Main Module")

        with open(module_path, "rb") as f:
            file_data = bytearray(f.read())
        if file_data.startswith(b"ZENC"):
            file_data = util.in_mem_decrypt(file_data)

        return self._parse_file_data(module_path, file_data)

    def parse_file(self, filename):
        with open(filename, "rb") as f:
            file_data = bytearray(f.read())
        return self._parse_file_data(filename, file_data)

    def _parse_file_data(self, filename, filedata):
        parsed_file = self.os_plugins.parse(filename, filedata)

        if parsed_file is not None:
            assert len(parsed_file.Data) > 0, "File has no data"
            return parsed_file
        raise UnsupportedBinaryError(f"{filename} is unsupported file format")

    def load_executable(self, module_path, entrypoint_override=None):
        """
        This method simply loads the executable, without starting the
        emulation
        """

        self.target_binary_path = module_path

        original_file_name = os.path.basename(module_path)
        self.original_file_name = original_file_name

        file = self._first_parse(module_path)

        module_path = file.Filepath
        self.main_module = file
        self._initialize_zelos(file)

        self.os_plugins.load(
            file, self.current_process, entrypoint_override=entrypoint_override
        )

        # TODO: don't let this be in loader and zelos
        self.main_module_name = self.loader.main_module_name

        # We need to create this file in the file system, so that other
        # files can access it.
        self.files.create_file(
            self.files.emulated_path_module.join(
                self.files.zelos_file_prefix, module_path
            )
        )

    def _initialize_zelos(self, binary=None):
        self.state = State(self, binary, self.date)

        cs_arch_mode_sm_dict = {
            "x86": (CS_ARCH_X86, CS_MODE_32),
            "x86_64": (CS_ARCH_X86, CS_MODE_64),
            "arm": (CS_ARCH_ARM, CS_MODE_ARM),
            "mips": (CS_ARCH_MIPS, CS_MODE_MIPS32),
        }

        arch = self.state.arch
        (cs_arch, cs_mode) = cs_arch_mode_sm_dict[arch]

        endianness = self.state.endianness
        if endianness == "little":
            cs_mode |= CS_MODE_LITTLE_ENDIAN
        elif endianness == "big":
            cs_mode |= CS_MODE_BIG_ENDIAN
        else:
            raise ZelosLoadException(f"Unsupported endianness {endianness}")
        self.cs = Cs(cs_arch, cs_mode)
        self.cs.detail = True

        self.logger.debug(
            f"Initialized {arch} {self.state.bits} emulator/disassembler"
        )

        self.triggers = Triggers(self)
        self.processes.set_architecture(self.state)

        self.network = Network(self.helpers, self.files, None)

        self.processes._create_first_process(self.main_module_name)
        p = self.current_process
        p.cmdline_args = self.cmdline_args
        p.environment_variables = self.config.env_vars
        p.virtual_filename = self.config.virtual_filename
        p.virtual_path = self.config.virtual_path

        if hasattr(zebracorn.unicorn, "WITH_ZEROPOINT_PATCH"):

            def process_switch_wrapper(*args, **kwargs):
                # Block count interrupt. Fires every 2^N blocks executed
                # Use this as an opportunity to swap threads.
                self.logger.info(">>> Tracing Thread Swap Opportunity")
                self.processes.schedule_next()

            self.interrupt_handler.register_interrupt_handler(
                0xF8F8F8F8, process_switch_wrapper
            )

        if self.config.filename is not None and self.config.filename != "":
            if (
                self.config.virtual_filename is not None
                and self.config.virtual_filename != ""
            ):
                self.files.add_file(
                    self.config.filename, self.config.virtual_filename
                )
            else:
                self.files.add_file(self.config.filename)

        # TODO: SharedSection needs to be removed
        self.processes.handles.new("section", "\\Windows\\SharedSection")

    @property
    def helpers(self):
        """
        Helpers are the first layer in the components hierarchy, which
        mainly deal with providing help to developers.
        """
        helpers_class = namedtuple(
            "Helpers", ["handles", "triggers", "state", "processes"]
        )
        return helpers_class(
            self.handles, self.triggers, self.state, self.processes
        )

    def load_library(self, module_name):
        binary, _ = self.loader._load_module(module_name, depth=1)
        return binary

    def disas(self, address: int, size: int):
        """
        Disassemble code at the given address, for up to size bytes
        """
        code = self.memory.read(address, size)
        return [insn for insn in self.cs.disasm(bytes(code), address)]

    def step(self, count: int = 1) -> None:
        """ Steps one assembly level instruction """
        # You might be tempted to use zebracorn's "count" argument to
        # step. However, printing instruction comments relies on an
        # ad-hoc "post instruction" method.
        #
        # Using zebracorn's emu_start count argument
        #   run INST hook
        #   run instruction
        #   zebracorn stops
        #
        # Current method:
        #   run INST hook (don't print)
        #   run instruction
        #   run INST hook (do print) then stop before next instruction
        #   zebracorn stops
        #
        # Of course, we can simplify when we get a post instruction
        # hook working properly.

        inst_count = 0

        def step_n(zelos, addr, size):
            nonlocal inst_count
            inst_count += 1
            if inst_count > count:
                self.scheduler.stop("step")

        def quit_step_n():
            nonlocal inst_count
            return inst_count > count

        self.hook_manager.register_exec_hook(
            HookType.EXEC.INST, step_n, end_condition=quit_step_n
        )
        return self.start(swap_threads=False)

    def step_over(self, count: int = 1) -> None:
        """
        Steps on assembly level instruction up to count instructions
        """
        for i in range(count):
            if not self._step_over():
                return

    def _step_over(self):
        """Returns True if it successfully stepped."""
        max_inst_size = 15
        insts = self.disas(self.emu.getIP(), max_inst_size)
        if len(insts) == 0:
            self.logger.notice(f"Unable to disassemble 0x{self.emu.getIP():x}")
            return False
        i = insts[0]
        if insts[0].group(CS_GRP_CALL):
            self.plugins.runner.run_to_addr(i.address + i.size)
        else:
            self.step()
        return True

    def start(self, timeout=0, swap_threads=True) -> Optional[BreakState]:
        """
        Starts execution of the program at the given offset or entry
        point.
        """
        if timeout > 0:
            self.timer.begin(timeout)

            def timeout_hook(zelos, addr, size):
                self._check_timeout()

            # TODO: Delete timeout hook after timeout is triggered.
            self.hook_manager.register_exec_hook(
                HookType.EXEC.BLOCK, timeout_hook, name="timeout_hook"
            )

        if self.processes.num_active_processes() == 0:
            self.processes.logger.info(
                "No more processes or threads to execute."
            )
            return None

        self.ehCount = 0

        # Main emulated execution loop
        while self._should_continue():
            if self.current_thread is None:
                self.processes.swap_with_next_thread()

            self.plugins.trace.should_print_last_instruction = False
            self.plugins.trace.last_instruction = self.emu.getIP()
            self.plugins.trace.last_instruction_size = 1

            try:
                if self.processes.num_active_processes() == 0:
                    self.processes.logger.info(
                        "No more processes or threads to execute."
                    )
                else:
                    # Execute until emulator exception
                    self._run(self.current_process)
            except UcError as e:
                # TODO: This is a special case for forcing a stop.
                # Sometimes setting a stop reason doesn't stop
                # execution (especially when changingEIP).
                # This is a hack. Fix me plz
                if self.current_thread is not None and not (
                    self.emu.getIP() == 0x30
                    and "kill thread" in self.scheduler.end_reasons
                ):
                    self.exception_handler.handle_exception(e)

            # If we get here and there are no end_reasons this is
            # because emu ended early. If we have swap thread set, this
            # is because this is a signal to zelos to swap threads.
            # Otherwise, this is a signal that execution is over
            # (for example, stepping)
            if not self.scheduler._has_end_reasons():
                if not swap_threads:
                    break
                self.processes.swap_with_next_thread()

        return self.kernel.generate_break_state()

    def _run(self, p):
        t = p.current_thread
        assert (
            t is not None
        ), "Current thread is None. Something has gone horribly wrong."

        self.breakpoints._disable_breakpoints_on_start(t.getIP())
        if t.emu.is_running:
            self.logger.critical(
                "Trying to run zebracorn while zebracorn is already running. "
                "You are entering untested waters"
            )

        try:
            t.emu.emu_start(t.getIP(), 0)
        finally:
            stop_addr = p.threads.scheduler._pop_stop_addr(t.id)
            self.hook_manager._clear_deleted_hooks()

        # Only set the stop addr if you stopped benignly
        if stop_addr is not None:
            t.setIP(stop_addr)

    def _should_continue(self):
        """
        Takes the reasons for ending zebracorn execution, and decides
        whether to continue or end execution
        """

        if self.current_thread is None:
            self.processes.swap_with_next_thread()

        if self.scheduler._resolve_end_reasons() is False:
            return False

        if self.processes.num_active_processes() == 0:
            return False

        # Keep running unless told otherwise.
        return True

    def close(self) -> None:
        """ Handles the end of the run command """
        for closure in self.hook_manager._get_hooks(HookType._OTHER.CLOSE):
            try:
                closure()
            except Exception:
                self.logger.exception("Exception while trying to close Zelos")

    def _dbgprint(self, address):
        service = self.emu.get_reg("eax")
        if service == 1:  # DbgPrint functionality
            length = self.emu.get_reg("edx")
            buffer = self.emu.get_reg("ecx")
            buffer_s = self.memory.read_string(buffer, length)
            print("[DBGPRINT SYSCALL] {0}".format(buffer_s))
        else:
            self.logger.info(
                ">>> Tracing DebugService at 0x%x Routine 0x%x"
                % (address, service)
            )

    def _check_timeout(self):
        if self.timer.is_timed_out():
            self.scheduler.stop("timeout")

    # Estimates the number of function arguments with the assumption
    # that the callee is responsible for cleaning up the stack.
    # Disassembles insts linearly until a RETN instruction is
    # encountered. The RETN operand indicates the number of stack bytes
    # the caller had pushed as arguments.

    def _estimate_function_stack_adjustment(self, function_start_address):
        address = function_start_address
        while True:
            code = self.emu.mem_read(address, 1000)
            for insn in self.cs.disasm(str(code), address):
                if insn.mnemonic != "ret":
                    address += insn.size
                    continue
                if len(insn.operands) == 0:
                    return 0  # no stack adjustment
                # imm bytes popped by this function
                return insn.operands[0].imm
