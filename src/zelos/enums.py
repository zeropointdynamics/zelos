from enum import Enum, IntEnum, auto

from unicorn import (
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
)


class ProtType(IntEnum):
    NONE = UC_PROT_NONE
    READ = UC_PROT_READ
    WRITE = UC_PROT_WRITE
    EXEC = UC_PROT_EXEC
    RWX = UC_PROT_ALL
    RX = UC_PROT_READ | UC_PROT_EXEC
    RW = UC_PROT_READ | UC_PROT_WRITE


class HookType:
    class MEMORY(Enum):
        """
        Used by :py:meth:`zelos.Zelos.hook_memory` to specify the
        memory event to hook on. View the registration function for more
        details.
        """

        READ = auto()
        WRITE = auto()
        READ_UNMAPPED = auto()
        WRITE_UNMAPPED = auto()
        READ_PROT = auto()
        WRITE_PROT = auto()
        READ_AFTER = auto()
        UNMAPPED = auto()
        PROT = auto()
        READ_INVALID = auto()
        WRITE_INVALID = auto()
        INVALID = auto()
        VALID = auto()

    class EXEC(Enum):
        """
        Used by :py:meth:`zelos.Zelos.hook_execution`.
        If INST is chosen, the registered hook will be executed every
        time a single instruction is executed.

        If BLOCK is chosen, the registered hook will be executed after
        every block of instructions is executed. A block is interpreted
        as a contiguous sequence of code where only the last instruction
        can modify control flow, typically a branch or return
        instruction.

        View the registration function for more details.
        """

        INST = auto()
        BLOCK = auto()

    class THREAD(Enum):
        """
        Not usable yet through Zelos API
        """

        CREATE = auto()
        SWAP = auto()
        DESTROY = auto()

    class PROCESS(Enum):
        """
        Not usable yet through Zelos API
        """

        CREATE = auto()
        SWAP = auto()
        DESTROY = auto()

    class SYSCALL(Enum):
        """
        Used by :py:meth:`zelos.Zelos.hook_syscalls`.

        If AFTER is chosen, the hook will be triggered after the syscall
        hass been executed.

        View the registration function for more details.
        """

        AFTER = auto()
        # TODO: support BEFORE to allow conditionally executing syscall.
        # BEFORE = auto()

    class _INST(Enum):
        """
        HookTypes used for triggering on specific instructions. These
        are intended for internal use only.
        """

        X86_SYSCALL = auto()

    class _OTHER(Enum):
        """
        HookTypes that do not need to be specified since they have no
        options. Only used internally.
        """

        CLOSE = auto()
        INTERRUPT = auto()
        EXCEPTION = auto()
