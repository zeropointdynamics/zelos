# 05 - Syscall Limiter Plugin

This tutorial explains how the syscall-limiter plugin was written and how it works.

The source code for this plugin can be fond in [src/zelos/ext/plugins/syscall_limiter.py](https://github.com/zeropointdynamics/zelos/blob/master/src/zelos/ext/plugins/syscall_limiter.py).

## Overview

The Syscall Limiter Plugin provides the following additional functionalities for Zelos:
  * Stop Zelos emulation after a specified number of syscalls have been executed across all threads.
  * Stop a thread after specified number of syscalls have been executed on a thread.
  * Swap threads after a specified number of syscalls have been executed on a thread.

## Create the Command Line Options

```eval_rst
As mentioned in the previous tutorial, we create three :py:class:`zelos.CommandLineOption` to be able to specify the number of syscalls we want to limit overall, the number of syscalls per thread we want to limit, and the number of syscalls before swapping at run time.
```

```python
from zelos import CommandLineOption

CommandLineOption(
    "syscall_limit",
    type=int,
    default=0,
)

CommandLineOption(
    "syscall_thread_limit",
    type=int,
    default=0,
)

CommandLineOption(
    "syscall_thread_swap",
    type=int,
    default=100,
)
```

## Initializing the Plugin

```eval_rst
We create the plugin by creating a class that subclasses :py:class:`zelos.IPlugin`. We initialize by invoking the superclass init function through :code:`super()__init__(z)` in the SyscallLimiter's :code:`__init__` function.
```

```python
from zelos import CommandLineOption, IPlugin

CommandLineOption(
    "syscall_limit",
    type=int,
    default=0,
)

CommandLineOption(
    "syscall_thread_limit",
    type=int,
    default=0,
)

CommandLineOption(
    "syscall_thread_swap",
    type=int,
    default=100,
)

class SyscallLimiter(IPlugin):

    def __init__(self, z):
        super().__init__(z)
        pass

```

## Implementing the Syscall Hook

```eval_rst
In order to implement the desired behavior of SyscallLimiter, we create a syscall hook using the :py:meth:`~zelos.Zelos.hook_syscalls` function. As noted in the previous tutorial, we can access our command line options through :py:class:`zelos.Zelos`'s :code:`config` field. Additionally, we create a callback function that keeps track of the number of syscalls executed overall and per thread.
```

```python
from collections import defaultdict
from zelos import CommandLineOption, IPlugin, HookType

CommandLineOption(
    "syscall_limit",
    type=int,
    default=0,
)

CommandLineOption(
    "syscall_thread_limit",
    type=int,
    default=0,
)

CommandLineOption(
    "syscall_thread_swap",
    type=int,
    default=100,
)

class SyscallLimiter(IPlugin):

    def __init__(self, z):
        super().__init__(z)
        # If we specify any of the above commandline options,
        # then create a syscall hook
        if (
            z.config.syscall_limit > 0
            or z.config.syscall_thread_limit > 0
            or z.config.syscall_thread_swap > 0
        ):
            self.zelos.hook_syscalls(
                HookType.SYSCALL.AFTER, self._syscall_callback
            )
        # Fields to keep track of syscalls executed
        self.syscall_cnt = 0
        self.syscall_thread_cnt = defaultdict(int)

    def _syscall_callback(self, p, sysname, args, retval):
        if self.zelos.thread is None:
            return
        # Get the name of the current thread
        thread_name = self.zelos.thread.name

        self.syscall_cnt += 1
        self.syscall_thread_cnt[thread_name] += 1

```

## Limiting Syscalls Overall

```eval_rst
To stop after a specified number of syscalls have been executed, we use the :py:meth:`~zelos.Zelos.hook_syscalls` function.
```

```python
    def _syscall_callback(self, p, sysname, args, retval):
        if self.zelos.thread is None:
            return
        # Get the name of the current thread
        thread_name = self.zelos.thread.name

        self.syscall_cnt += 1
        self.syscall_thread_cnt[thread_name] += 1

        # End execution if syscall limit reached
        if (
            self.zelos.config.syscall_limit > 0
            and self.syscall_cnt >= self.zelos.config.syscall_limit
        ):
            self.zelos.stop("syscall limit")
            return

```

## Limiting Syscalls Per Thread

```eval_rst
To stop & complete a thread after specified number of syscalls have been executed on it, we use the :py:meth:`~zelos.Zelos.end_thread` function.
```

```python
    def _syscall_callback(self, p, sysname, args, retval):
        if self.zelos.thread is None:
            return
        # Get the name of the current thread
        thread_name = self.zelos.thread.name

        self.syscall_cnt += 1
        self.syscall_thread_cnt[thread_name] += 1

        # End execution if syscall limit reached
        if (
            self.zelos.config.syscall_limit > 0
            and self.syscall_cnt >= self.zelos.config.syscall_limit
        ):
            self.zelos.stop("syscall limit")
            return

        # End thread if syscall thread limit reached
        if (
            self.zelos.config.syscall_thread_limit != 0
            and self.syscall_thread_cnt[thread_name]
            % self.zelos.config.syscall_thread_limit
            == 0
        ):
            self.zelos.end_thread()
            return
```

## Swapping Threads

```eval_rst
To force a thread swap to occur after specified number of syscalls have been executed on it, we use the :py:meth:`~zelos.Zelos.swap_thread` function.
```

```python
    def _syscall_callback(self, p, sysname, args, retval):
        if self.zelos.thread is None:
            return
        # Get the name of the current thread
        thread_name = self.zelos.thread.name

        self.syscall_cnt += 1
        self.syscall_thread_cnt[thread_name] += 1

        # End execution if syscall limit reached
        if (
            self.zelos.config.syscall_limit > 0
            and self.syscall_cnt >= self.zelos.config.syscall_limit
        ):
            self.zelos.stop("syscall limit")
            return

        # End thread if syscall thread limit reached
        if (
            self.zelos.config.syscall_thread_limit != 0
            and self.syscall_thread_cnt[thread_name]
            % self.zelos.config.syscall_thread_limit
            == 0
        ):
            self.zelos.end_thread()
            return

        # Swap threads if syscall thread swap limit reached
        if (
            self.zelos.config.syscall_thread_swap > 0
            and self.syscall_cnt % self.zelos.config.syscall_thread_swap == 0
        ):
            self.zelos.swap_thread("syscall limit thread swap")
        return
```
