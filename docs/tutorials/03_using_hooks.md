# 03 - Using Hooks

This tutorial demonstrates how hooks in the Zelos API can be used to identify strings that are copied during runtime without symbol information.

Files and scripts from this tutorial are available in the [examples/inmemory_strings](https://github.com/zeropointdynamics/zelos/blob/master/examples/inmemory_strings) directory.

## Hook Overview

Hooks are a way to invoke your code whenever certain events occur during execution. To hook on:
```eval_rst
*  Memory reads and writes use :py:meth:`~zelos.Zelos.hook_memory`
*  Invocations of syscalls use :py:meth:`~zelos.Zelos.hook_syscalls`
*  Execution of an instruction :py:meth:`~zelos.Zelos.hook_execution`

Each hook offers different configuration options and requires a different type of callback. For more details, as well as examples, for each type of hook, take a look at :py:class:`~zelos.Zelos`.
```

## Pwnable.kr Challenge

The [flag challenge on pwnable.kr](http://pwnable.kr/play.php) provides a binary that we need to extract a flag from. We can start off by just running the binary in zelos using `zelos pwnablekr_flag_binary`.
This will produce the output
```
[main] [SYSCALL] mmap ( addr=0x800000, length=0x2d295e, prot=0x7, flags=0x32, fd=0x0 (stdin), offset=0x0 ) -> 800000
[main] [SYSCALL] readlink ( pathname=0x84a78d ("/proc/self/exe"), buf=0xff08deb4, bufsiz=0x1000 ) -> 12
[main] [SYSCALL] mmap ( addr=0x400000, length=0x2c7000, prot=0x0, flags=0x32, fd=0xffffffff (unknown), offset=0x0 ) -> 400000
[main] [SYSCALL] mmap ( addr=0x400000, length=0xc115e, prot=0x7, flags=0x32, fd=0xffffffff (unknown), offset=0x0 ) -> 400000
[main] [SYSCALL] mprotect ( addr=0x400000, len=0xc115e, prot=0x5 ) -> 0
[main] [SYSCALL] mmap ( addr=0x6c1000, length=0x26f0, prot=0x3, flags=0x32, fd=0xffffffff (unknown), offset=0xc1000 ) -> 6c1000
[main] [SYSCALL] mprotect ( addr=0x6c1000, len=0x26f0, prot=0x3 ) -> 0
[main] [SYSCALL] mmap ( addr=0x6c4000, length=0x22d8, prot=0x3, flags=0x32, fd=0xffffffff (unknown), offset=0x0 ) -> 6c4000
[main] [SYSCALL] munmap ( addr=0x801000, length=0x2d195e ) -> 0
[main] [SYSCALL] uname ( buf=0xff08dab0 ) -> 0
[main] [SYSCALL] brk ( addr=0x0 ) -> 90000048
[main] [SYSCALL] brk ( addr=0x90001208 ) -> 90001208
[main] [SYSCALL] arch_prctl ( option=0x1002 (ARCH_SET_FS), addr=0x90000900 ) -> 0
[main] [SYSCALL] brk ( addr=0x90022208 ) -> 90022208
[main] [SYSCALL] brk ( addr=0x90023000 ) -> 90023000
[main] [SYSCALL] fstat ( fd=0x1 (stdout), statbuf=0xff08db40 ) -> 0
[main] [SYSCALL] ioctl ( fd=0x1 (stdout), request=0x5401, data=0xff08dab8 ) -> -1
[main] [SYSCALL] mmap ( addr=0x0, length=0x1000, prot=0x3, flags=0x22, fd=0xffffffff (unknown), offset=0x0 ) -> 10000
[StdOut]: 'bytearray(b'I will malloc() and strcpy the flag there. take it.\n')'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x10000 ("I will malloc() and strcpy the flag there. take it.\n"), count=0x34 ) -> 34
00:45:32:threads___:SUCCES:Done executing thread main
[main] [SYSCALL] exit_group ( status=0x0 ) -> void
```

Immediately, we see the line:

```
[StdOut]: 'bytearray(b'I will malloc() and strcpy the flag there. take it.\n')'
```

An initial approach may be to dump all of the strings that are present in the binary using the `strings` utility, unfortunately the is packed with [UPX](https://en.wikipedia.org/wiki/UPX). Seems like we'll have to run the binary and find strings while the binary is running...

## Script to Print In-Memory String Writes
To identify the flag, we will create a script that will print all the times strings are written.

To begin with, let's create a script that will run the target binary similar to how we ran it using the Zelos command line tool.

```python
from zelos import Zelos

z = Zelos("pwnablekr_flag_binary")
z.start()
```

```eval_rst
Next, let's print out every write to memory that occurs. Use the :py:meth:`~zelos.Zelos.hook_memory` to register the hook and specify the :py:const:`zelos.HookType.MEMORY.WRITE` hook type.
```

``` python
from zelos import Zelos, HookType

z = Zelos("pwnablekr_flag_binary")

def mem_hook_callback(zelos: Zelos, access: int, address: int, size: int, value: int):
  "Prints the destination and contents of every memory write."
  print(f"Address: {address:x}, Value: {value:x}")

z.hook_memory(HookType.MEMORY.WRITE, mem_hook_callback)

z.start()
```
```eval_rst
The function signature used by :code:`mem_hook_callback` is required by :py:meth:`~zelos.Zelos.hook_memory`. You can find the required callback function signature in the documentation for the hook registration functions in :py:class:`~zelos.Zelos`.
Unfortunately this script will print out a lot of garbage. What we want is a very specific subset of these writes, and to print them in a way that we can easily understand. We'll make some basic assumptions on how strings are written to memory via strcpy.
```

  1. A single string is written from beginning to end with no memory writes to other locations inbetween.
  2. The bytes that are written make up a valid utf-8 string.

Let's write a class that can keep track of subsequent writes and decodes strings as they are written.

```python
class StringCollector:
    def __init__(self):
        self._current_string = ""
        self._next_addr = 0

    def collect_writes(self, zelos: zelos, access: int, address: int, size: int, value: int):
        # Pack converts the value into its representation in bytes.
        data = zelos.memory.pack(value)
        try:
            decoded_data = data.decode("utf-8")
        except UnicodeDecodeError:
            self._next_addr = 0
            self._end_current_string()
            return
        decoded_data = decoded_data[:size]

        if address != self._next_addr:
            self._end_current_string()

        self._next_addr = address + size
        self._current_string += decoded_data
        return

    def _end_current_string(self):
        print(f'Found string: "{self._current_string}"')
        self._current_string = ""
```
```eval_rst
Let's put this class to use. Note that we kept the method signature for :code:`collect_writes` similar to :code:`mem_hook_callback` from before. This allows us to use it as the callback for :py:meth:`~zelos.Zelos.hook_memory`
```

```python
from zelos import Zelos, HookType

class StringCollector:
  ...

z = Zelos("example_binary")

sc = StringCollector()
z.hook_memory(HookType.MEMORY.WRITE, sc.collect_writes)

z.start()
```
Running this script, we see the following input
```
Found string: "4"
Found string: ""
Found string: ""
Found string: "4"
Found string: ""
Found string: ""
Found string: ""
[StdOut]: 'bytearray(b'I will malloc() and strcpy the flag there. take it.\n')'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x10000 ("I will malloc() and strcpy the flag there. take it.\n"), count=0x34 ) -> 34
Found string: ""
Found string: ""
Found string: ""
Found string: ""
Found string: ""
Found string: ""

```

There is still a lot of random looking data being printed. Let's clean up the results a bit by making two more assumptions.

1. A string can only contain a null byte at the end.
2. We're only interested in strings with 4 or more characters (similar to the `strings` utility)

Our new and improved `StringCollector` looks like this now

```python
class StringCollector:
    def __init__(self):
        self._min_len = 4
        self._current_string = ""
        self._next_addr = 0

    def collect_writes(self, zelos, access, address, size, value):
        data = zelos.memory.pack(value)
        try:
            decoded_data = data.decode("utf-8")
        except UnicodeDecodeError:
            self._next_addr = 0
            self._end_current_string()
            return
        decoded_data = decoded_data[:size]

        first_null_byte = decoded_data.find("\x00")
        if first_null_byte != -1:
            decoded_data = decoded_data[:first_null_byte]
            self._current_string += decoded_data
            self._next_addr = 0
            self._end_current_string()
            return

        if address != self._next_addr:
            self._end_current_string()

        self._next_addr = address + size
        self._current_string += decoded_data
        return

    def _end_current_string(self) -> None:
        if len(self._current_string) >= self._min_len:
            print(f'Found string: "{self._current_string}"')
        self._current_string = ""

```

Running this script still prints out quite a bit due to the aforementioned obfuscation, however near the end you should see the target string printed out!

```
[main] [SYSCALL] ioctl ( fd=0x1 (stdout), request=0x5401, data=0xff08dab8 ) -> -1
[main] [SYSCALL] mmap ( addr=0x0, length=0x1000, prot=0x3, flags=0x22, fd=0xffffffff (unknown), offset=0x0 ) -> 10000
Found string: "I will malloc() and strcpy the flag there. take it.3"
Found string: "UPX...? sounds like a delivery service :)"
[StdOut]: 'bytearray(b'I will malloc() and strcpy the flag there. take it.\n')'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x10000 ("I will malloc() and strcpy the flag there. take it.\n"), count=0x34 ) -> 34
01:36:32:threads___:SUCCES:Done executing thread main
[main] [SYSCALL] exit_group ( status=0x0 ) -> void
```

Our script still needs some work, since there are many nonsensical characters printed out and we accidentally added a byte onto the string that got printed to stdout. However, we didn't have to worry about UPX! (We'll deal with it in a later tutorial.)

The following example script showing how to collect in-memory strings can be found at [examples/inmemory_strings/strings_script.py](https://github.com/zeropointdynamics/zelos/blob/master/examples/inmemory_strings/strings_script.py).

```python
import argparse

from zelos import Zelos, HookType

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--len",
        type=int,
        default=4,
        help="The minimum size of string to identify",
    )
    parser.add_argument("filename", type=str, help="The file to analyze")

    args = parser.parse_args()

    z = Zelos(args.filename)
    sc = StringCollector(args.len)

    z.hook_memory(
        HookType.MEMORY.WRITE, sc.collect_writes, name="strings_syscall_hook"
    )
    z.start()


class StringCollector:
    """
    Identifies strings that are written in-memory. We identify strings by the
    observation that when they are written to memory
      * The string is written in sequential chunks.
      * They are comprised of valid utf-8 bytes

    This runs into some false positives with data that happens to be
    valid utf-8. To reduce false positives we observe that
      * Strings often end at the first null byte.
      * False positives are often short strings. There is a higher
        chance that 2 consecutive characters are valid utf-8 than
        4 consecutive characters.

    """

    def __init__(self, min_len):
        self._min_len = min_len
        self._current_string = ""
        self._next_addr = 0

    def collect_writes(self, zelos, access, address, size, value):
        """
        Collects strings that are written to memory. Intended to be used
        as a callback in a Zelos HookType.MEMORY hook.
        """
        data = zelos.memory.pack(value)
        try:
            decoded_data = data.decode()
        except UnicodeDecodeError:
            self._next_addr = 0
            self._end_current_string()
            return
        decoded_data = decoded_data[:size]

        first_null_byte = decoded_data.find("\x00")
        if first_null_byte != -1:
            decoded_data = decoded_data[:first_null_byte]
            self._current_string += decoded_data
            self._next_addr = 0
            self._end_current_string()
            return

        if address != self._next_addr:
            self._end_current_string()

        self._next_addr = address + size
        self._current_string += decoded_data
        return

    def _end_current_string(self) -> None:
        """
        Ends the currently identified string. May save the string if it
        looks legit enough.
        """
        if len(self._current_string) >= self._min_len:
            print(f'Found string: "{self._current_string}"')
        self._current_string = ""

if __name__ == "__main__":
    main()

```
