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
import ntpath
import os

from collections import namedtuple
from shutil import copyfile
from tempfile import mkstemp

import unicorn
import verboselogs

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
from unicorn import UcError

from zelos import util
from zelos.config_gen import _generate_without_binary, generate_config
from zelos.exceptions import UnsupportedBinaryError, ZelosLoadException
from zelos.file_system import FileSystem
from zelos.hooks import ExceptionHooks, HookManager, HookType, InterruptHooks
from zelos.network import Network
from zelos.plugin import OSPlugins
from zelos.processes import Processes
from zelos.state import State
from zelos.tracer import Tracer
from zelos.triggers import Triggers


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
        # OS plugins place OS-specific, system-wide, functionality
        # in engine.zos

        class ZOS(object):
            def __init__(self):
                pass

        self.zos = ZOS()

        binary = config.filename

        # Set provided arguments
        self.original_binary = binary
        self.cmdline_args = (
            [] if config.cmdline_args is None else config.cmdline_args
        )

        self.random_file_name = getattr(config, "random_file_name", False)

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
        self.main_module_name = ""
        self.main_module = None

        self.date = "2019-02-02"
        self.traceon = ""
        self.traceoff = ""

        # Handling of the logging
        self.verbose = False
        self.verbosity = 0
        self.fasttrace_on = False
        self.timer = util.Timer()

        self.hook_manager = HookManager(self, self.api)
        self.interrupt_handler = InterruptHooks(self.hook_manager, self)
        self.exception_handler = ExceptionHooks(self)
        self.processes = Processes(
            self.hook_manager,
            self.interrupt_handler,
            self.original_binary,
            self.STACK_SIZE,
            disableNX=self.config.disableNX,
        )

        self.files = FileSystem(self, self.processes, self.hook_manager)

        self.os_plugins = OSPlugins(self)

        if binary is not None and binary != "":
            self.load_executable(binary, entrypoint_override=config.startat)
        else:
            self._initialize_zelos()  # For testing purposes.

        head, tail = ntpath.split(config.filename)
        original_filename = tail or ntpath.basename(head)
        self.original_file_name = original_filename
        self.date = config.date

        if config.fasttrace > 0:
            self.fasttrace_on = True
        if config.dns > 0:
            self.flags_dns = True

        self.set_trace_on(config.traceon)
        self.traceoff = config.traceoff
        if config.tracethread != "":
            self.trace.threads_to_print.add(config.tracethread)
        if config.writetrace != "":
            target_addr = int(config.writetrace, 16)
            self.set_writetrace(target_addr)
        if config.memlimit > 0:
            self.set_mem_limit(config.memlimit)
        for m in config.mount:
            try:
                arch, dest, src = m.split(",")
                # TODO: Use arch, dest to determine where to mount
                # For now, always mounts src at default location
                if os.path.isdir(src):
                    self.files.mount_folder(src)
                else:
                    self.files.add_file(src)
            except ValueError:
                self.logger.error(
                    f"Incorrectly formatted input to '--mount': {m}"
                )
                continue
        if config.strace is not None:
            self.zos.syscall_manager.set_strace_file(config.strace)

        self.verbosity = config.verbosity
        self.set_verbose(config.verbosity > 0)

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

    def log_api(self, args, isNative=False):
        self.trace.api(args, isNative)

    def log_api_dbg(self, args):
        self.trace.api_dbg(args)

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

    def _first_parse(self, module_path, random_file_name=False):
        """ Function to parse an executable """

        if random_file_name:
            self.original_file_name = module_path
            original_file_name = module_path
            # To ensure we don't get any issues with the size of the
            # file name, we copy the file and rename it 'target'
            fd, temp_path = mkstemp(dir=".", suffix=".xex")
            os.close(fd)
            temp_filename = os.path.basename(temp_path)
            copyfile(module_path, temp_filename)
            module_path = temp_filename
            self.hook_manager.register_close_hook(
                functools.partial(os.remove, temp_filename)
            )
            self.logger.debug(
                f"Setting random file name for "
                f"{original_file_name} : {module_path}"
            )

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

        original_file_name = os.path.basename(module_path)
        self.original_file_name = original_file_name

        file = self._first_parse(
            module_path, random_file_name=self.random_file_name
        )

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
        self.files.create_file(self.files.zelos_file_prefix + module_path)

        # If you remove one of the hooks on _hook_code, be careful that
        # you don't break the ability to stop a running emulation
        if self.verbose:
            self.set_hook_granularity(HookType.EXEC.INST)

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

        self.last_instruction = None
        self.last_instruction_size = None
        self.should_print_last_instruction = True

        self.triggers = Triggers(self)
        self.processes.set_architecture(self.state)

        self.network = Network(self.helpers, self.files, None)

        self.processes._create_first_process(self.main_module_name)
        p = self.current_process
        p.cmdline_args = self.cmdline_args
        p.environment_variables = self.config.env_vars
        p.virtual_filename = self.config.virtual_filename
        p.virtual_path = self.config.virtual_path

        if hasattr(unicorn.unicorn, "WITH_ZEROPOINT_PATCH"):

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
        self.trace = Tracer(self.helpers, self, self.cs, self.modules)

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
        self.start(count=count, swap_threads=False)
        if self.last_instruction is not None:
            self.trace.bb(self.last_instruction, self.last_instruction_size)
        else:
            self.trace.bb()

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

    def start(self, count=0, timeout=0, swap_threads=True) -> None:
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
            return

        self.ehCount = 0

        # Main emulated execution loop
        while self._should_continue():
            if self.current_thread is None:
                self.processes.swap_with_next_thread()

            self.last_instruction = self.emu.getIP()
            self.last_instruction_size = 1
            try:
                if self.processes.num_active_processes() == 0:
                    self.processes.logger.info(
                        "No more processes or threads to execute."
                    )
                else:
                    # Execute until emulator exception
                    self._run(self.current_process, count)
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

        return

    def _run(self, p, count):
        t = p.current_thread
        assert (
            t is not None
        ), "Current thread is None. Something has gone horribly wrong."

        t.emu.is_running = True
        try:
            t.emu.emu_start(t.getIP(), 0, count=count)
        finally:
            stop_addr = p.threads.scheduler._pop_stop_addr(t.id)
            t.emu.is_running = False

        # Only set the stop addr if you stopped benignly
        if stop_addr is not None:
            t.setIP(stop_addr)

    def _should_continue(self):
        """
        Takes the reasons for ending unicorn execution, and decides
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

    def set_trace_on(self, val):
        try:
            i = int(val, 0)

            def f(zelos, address, size):
                self.verbosity = 2  # Allow logging inside modules
                self.set_verbose(True)

            self.hook_manager.register_exec_hook(
                HookType.EXEC.INST, f, name="traceon", ip_low=i, ip_high=i
            )
        except ValueError:
            pass
        self.traceon = val

    def _check_timeout(self):
        if self.timer.is_timed_out():
            self.scheduler.stop("timeout")

    # Hook invoked for each instruction or block.
    def _hook_code(self, zelos, address, size):
        try:
            self._hook_code_impl(zelos, address, size)
            self._check_timeout()
        except Exception:
            if self.current_thread is not None:
                self.current_process.threads.kill_thread(
                    self.current_thread.id
                )
            self.logger.exception("Stopping execution due to exception")

    def _hook_code_impl(self, zelos, address, size):
        current_process = self.current_process
        current_thread = self.current_thread
        # TCG Dump example usage:
        # self.emu.get_tcg(0, 0)
        if current_thread is None:
            self.emu.emu_stop()
            return

        # Log the total number of blocks executed per thread. Swap
        # threads if the specified number of blocks is exceeded and
        # other threads exist
        current_thread.total_blocks_executed += 1
        if (
            current_thread.total_blocks_executed % 1000 == 0
            and address not in self.modules.reverse_module_functions
        ):
            self.current_process.scheduler.stop_and_exec(
                "process swap", self.processes.schedule_next
            )
            return

        if self.verbose:
            if self.should_print_last_instruction:  # Print block
                # Turn on full trace to do trace comparison
                self.trace.bb(
                    self.last_instruction,
                    self.last_instruction_size,
                    full_trace=False,
                )
            self.should_print_last_instruction = True
            if (
                self.fasttrace_on
                and current_process.threads.block_seen_before(address)
            ):
                self.should_print_last_instruction = False

        current_process.threads.record_block(address)

        self.last_instruction = address
        self.last_instruction_size = size

    def set_verbose(self, should_set_verbose: bool) -> None:
        """
        Used to set the verbosity level, and change the hooks.
        This prevents two types of issues:

        1) Running block hooks when printing individual instructions
               This will cause the annotations that are printed to be
               the values at the end of the block's execution
        2) Running instruction hooks when not printing instructions
               This will slow down the emulation (sometimes
               considerably)
        """
        if self.verbose == should_set_verbose:
            return
        self.verbose = should_set_verbose

        if should_set_verbose:
            self.set_hook_granularity(HookType.EXEC.INST)
        else:
            self.set_hook_granularity(HookType.EXEC.BLOCK)

    def set_hook_granularity(self, granularity: HookType.EXEC):
        try:
            self.hook_manager.delete_hook(self._code_hook_info)
        except AttributeError:
            pass  # first time setting _code_hook_info

        self._code_hook_info = self.hook_manager.register_exec_hook(
            granularity, self._hook_code, name="code_hook"
        )

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
