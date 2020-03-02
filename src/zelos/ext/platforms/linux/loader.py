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

from os.path import basename

from unicorn import UC_ERR_EXCEPTION

from zelos.exceptions import ZelosLoadException
from zelos.hooks import HookType
from zelos.plugin import Loader
from zelos.util import align


class LinuxMode:
    def __init__(self, arch, z):
        self.z = z
        self.logger = z.logger
        self.z.hook_manager.register_exception_hook(self.handle_exception)

        # TODO: removing this fails
        #       test.test_linux_arm.ZelosTest.test_dynamic_elf
        #       due to the stack being allocated at the same address as
        #       the binary. Stacks in linux should be allocated from the
        #       top-down to avoid this collision.
        # Set the stack address range
        if arch != "mips":

            def set_stack_region(current_process):
                current_process.threads.stack_min = 0xFF000000
                current_process.threads.stack_max = 0xFFFF0000

            self.z.hook_manager.register_process_hook(
                HookType.PROCESS.CREATE, set_stack_region
            )

        self.z = z

    def handle_exception(self, p, e):
        # TODO(kzsnow): This goes in core?
        try:
            self.z.trace.bb(
                self.z.last_instruction, self.z.last_instruction_size
            )
        except Exception:
            self.z.logger.exception("Couldn't print basic block")

        if p.current_thread.getIP() == p.current_thread.end_address:
            # TODO: this only removes the mapping, but does not change
            # where the next allocation will occur.
            # p.current_thread.cleanup(self)
            p.threads.complete_current_thread()
            return

        if self.z.state.arch == "arm":
            arm_private_syscall = {
                0xFFFF0F60: self.z.zos.syscall_manager._kuser_cmpxchg64,
                0xFFFF0FA0: self.z.zos.syscall_manager._kuser_memory_barrier,
                0xFFFF0FC0: self.z.zos.syscall_manager._kuser_cmpxchg,
                0xFFFF0FE0: self.z.zos.syscall_manager._kuser_get_tls,
            }.get(p.current_thread.getIP(), None)
            if arm_private_syscall is not None:
                arm_private_syscall()
                return
        if e.errno == UC_ERR_EXCEPTION:
            if self._attempt_to_handle_syscall():
                return  # linear execution after syscall (interrupt style)

        self.z.trace.bb()
        p.threads.fail_current_thread(fail_reason=f"Exception {e}")
        self.z.processes.handles.close_all(self.z.current_process.pid)

    def _attempt_to_handle_syscall(self):
        if self.z.verbose:
            self.z.trace.bb(
                self.z.last_instruction,
                self.z.last_instruction_size,
                full_trace=False,
            )
        syscall_action = self.z.zos.syscall_manager.handle_syscall(
            self.z.current_process
        )
        was_handled = syscall_action is not None
        return was_handled

    def create_tls(self, thread):
        if thread.local_data_address is not None:
            flags = thread.memory.gdt.gdt_entry_flags(
                gr=0, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1
            )
            thread.memory.gdt.set_entry(
                10, thread.thread_local_data, 0xFFF, flags
            )


class ElfLoader(Loader):

    TLS_ADDR = 0x7FFDF000

    def load(
        self, module_path, file, thread_name="main", entrypoint_override=None
    ):
        self.main_module_name = module_path
        self.main_module = file
        if self.main_module.ExtraCmdlineArg is not None:
            filename = self.process.cmdline_args[0]
            self.process.cmdline_args[0] = f"./{basename(filename)}"
            self.process.cmdline_args.insert(
                0, self.main_module.ExtraCmdlineArg
            )

        self._create_process_address_space(file)

        self.base = self._load_module(file, module_path)

        # Need to load the thread local storage before the gs register:
        #   https://wiki.osdev.org/Thread_Local_Storage#i386
        # tdata section is the initial state of this data:
        #   https://stackoverflow.com/questions/4126184/elf-file-tls-and-load-program-sections
        tdata = self._z.main_module.Tls
        self.process.memory.write(self.TLS_ADDR - len(tdata), bytes(tdata))

        self.EntryPoint = self._get_entrypoint(file, entrypoint_override)
        self._create_thread(self.EntryPoint, module_path, thread_name)

        self.logger.verbose(
            f'Map Module "{module_path}" | '
            f"ImageBase: 0x{file.ImageBase:08x} "
            f"MapBase: 0x{self.base:08x}"
        )

        return self.base, None

    def _create_thread(
        self,
        entry_point,
        module_path,
        thread_name=None,
        priority=0,
        benign_code=False,
    ):
        self.process.new_thread(
            entry_point,
            name=thread_name,
            priority=priority,
            stack_setup=self._stack_setup,
            module_path=module_path,
            benign_code=benign_code,
        )

    def _load_module(self, elf, module_name):
        module_path, normalized_module_name = self._get_module_name(
            module_name
        )
        data = bytearray(elf.Data)
        base = self.memory._alloc_at(
            "",
            "main",
            basename(normalized_module_name),
            elf.ImageBase,
            elf.VirtualSize,
        )
        self.memory.write(base, bytes(data))
        # Set proper permissions for each section of the module
        for s in elf.Sections:
            try:
                self.memory.protect(
                    s.Address,
                    align(s.VirtualSize, s.Alignment),
                    s.Permissions,
                    # s.Name,
                    # "main",
                    # module_name=basename(module_path),
                )
            except Exception:
                raise ZelosLoadException(
                    f"Bad section {hex(s.Address)}  {hex(s.VirtualSize)}"
                )
        return base

    def _create_process_address_space(self, binary):
        self.ADDRESS = binary.ImageBase
        self._z.STACK_SIZE = max(binary.StackSize + 0x1000, self._z.STACK_SIZE)
        self.size = binary.VirtualSize
        self.entry = binary.EntryPoint

        # Discusses the setup of TLS https://akkadia.org/drepper/tls.pdf
        # I have seen an access behind the start address in linux x86
        # hello world
        self.memory.map(self.TLS_ADDR - 0x1000, 0x2000, "TLS", "system")
        # Linux puts the syscall function at gs 10
        self.memory.write_int(self.TLS_ADDR + 0x10, 0xB0BABABE)

    def _stack_setup(self, thread):
        # A good overview of the stack format:
        #   http://articles.manugarg.com/aboutelfauxiliaryvectors.html

        # This needs to be changed for dynamically linked binaries a la
        #   http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html
        # regs = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'ebp', 'esi']
        # for r in regs:
        #     thread.set_reg(r, 0)

        # aux vector codes:
        #   https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/auxvec.h

        module_path_ptr, str_len = self.memory.heap.allocstr(
            f"/home/admin/{self.main_module_name}", alloc_name="Module Path"
        )
        cpu_string_ptr, _ = self.memory.heap.allocstr(
            "some computer", alloc_name="cpu_string"
        )

        # Begin by mapping strings that exist at stack bottom.

        env_vars = {"SHELL": "bin/bash"}

        env_strings = [f"{k}={v}\x00" for k, v in env_vars.items()]
        env_strings.extend(
            [x + "\x00" for x in self.process.environment_variables]
        )
        arg_strings = [s + "\x00" for s in self.process.cmdline_args]

        self.logger.debug(f"Command line args are {arg_strings}")
        self.logger.debug(f"Env vars are {env_strings}")

        # Setup the stack bottom
        thread.pushstack(0)

        def push_data(data):
            sp = thread.getSP()
            string_addr = sp - len(data)
            self.memory.write(string_addr, data)
            thread.setSP(string_addr)
            return string_addr

        env_string_ptrs = [push_data(s.encode()) for s in env_strings]
        # ptrs must be in the same order as the arg strings
        arg_string_ptrs = [push_data(s.encode()) for s in arg_strings]

        # Padding would come next. To figure out how much padding is
        # needed to align the stack pointer, we collect the data that
        # comes after the padding
        stack_top = self._get_stack_top_bytes(
            thread, arg_string_ptrs, env_string_ptrs
        )

        padding = self._get_padding_bytes(thread, stack_top)
        push_data(stack_top + padding)
        self.logger.debug(f"SP is set to {thread.getSP():x}")

    # Functions used in the setup of the stack #

    def _get_stack_top_bytes(self, thread, arg_string_ptrs, env_string_ptrs):
        def get_ptr_bytes(thread, ptrs):
            return b"".join([thread.pack(p) for p in ptrs])

        argc = thread.pack(len(arg_string_ptrs))
        argv = get_ptr_bytes(thread, arg_string_ptrs)
        args_bytes = argc + argv + thread.pack(0)

        env_bytes = get_ptr_bytes(thread, env_string_ptrs) + thread.pack(0)

        aux_vector_bytes = self._get_aux_vector_bytes()

        return args_bytes + env_bytes + aux_vector_bytes

    def _get_padding_bytes(self, thread, stack_top):
        # The padding needs to make sure that
        #   (current_sp - (padding_len + initial_stack_data_len))
        #     % alignment == 0
        # restricting padding_len < alignment,using basic maths implies
        #   (current_sp - initial_stack_data_len)
        #     % alignment == padding_len
        ALIGNMENT = 16
        padding_size = (thread.getSP() - len(stack_top)) % ALIGNMENT
        self.logger.debug(
            f"stack_top: {len(stack_top):x}, sp: {thread.getSP():x}"
            f" padding: {padding_size:x}"
        )
        return b"\x00" * padding_size

    def _get_aux_vector_bytes(self):
        random_bytes_ptr, str_len = self.memory.heap.allocstr(
            "RANDOMBYTESRAND", alloc_name="random bytes"
        )

        aux_vector = [
            # legal values
            # (0x01, 0), #AT_IGNORE: entry should be ignored
            # (0x02, val), #AT_EXECFD: file descriptor of program
            # AT_PHDR: program headers for program
            (0x03, self.main_module.HeaderAddress),
            # AT_PHENT: size of program header entry
            (0x04, self.main_module.HeaderSize),
            # AT_PHNUM: number of program headers
            (0x05, self.main_module.NumberOfProgramHeaders),
            (0x06, 0x1000),  # AT_PAGESZ: system page size
            # AT_BASE: base address of interpreter
            (0x07, self.main_module.ImageBase),
            (0x08, 0),  # AT_FLAGS: flags
            # AT_ENTRY: program entry point
            (0x09, self.main_module.EntryPoint),
            # (0x0a, 0), #AT_NOTELF: program is not ELF
            (0x0B, 0x3E8),  # AT_UID: real uid
            (0x0C, 0x3E8),  # AT_EUID: effective uid
            (0x0D, 0x3E8),  # AT_GID: real gid
            (0x0E, 0x3E8),  # AT_EGID: effective gid
            (0x11, 0x64),  # AT_CLKTCK: frequency of times()
            # hardware related
            # (0x0f, 'x86_64'), #AT_PLATFORM: string ident platform
            (
                0x10,
                0x001FB897,
            ),  # AT_HWCAP: machine dependent processor capabilities
            # (0x18, 0) #AT_BASE_PLATFORM: string for real platforms
            (0x1A, 0),  # AT_HWCAP2: extension of processor capabilities
            # FPU related (kernel use)
            # (0x12, 0), #AT_FPUCW: used FPU control word
            # cache block sizes
            # (0x13, 0), #AT_DCACHEBSIZE: data cache block size
            # (0x14, 0), #AT_ICACHEBSIZE: instruction cache block size
            # (0x15, 0), #AT_UCACHEBSIZE: unified cache block size
            # PPC related (kernel use)
            # (0x16, 0), #AT_IGNOREPPC: entry should be ignored
            # (0x17, 0), #AT_SECURE: exec is setuid-like
            (0x19, random_bytes_ptr),  # AT_RANDOM: addr of 16 rand byte
            # global system pages
            # (0x20, 0), #AT_SYSINFO: entry point to syscall in vDSO
            # (0x21, 0), #AT_SYSINFO_EHDR: page address of vDSO
            (0x00, 0),  # AT_NULL: end of vector
        ]

        data = b""
        for (key, val) in aux_vector:
            data += self.emu.pack(key)
            data += self.emu.pack(val)
        return data
