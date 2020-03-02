import argparse

from typing import List

from zelos import HookType, Zelos


"""
# tl;dr
# http://pwnable.kr has a binary that contains a hidden string that is
# only written in memory. To identify the flag, run
# `python inmemory_strings.py <path to flag binary>`

This example is intended as a potential solution for the
pwnable.kr challenge "flag". This challenge contains a binary that
"strcpy"s the flag into "malloc"ed memory, and our goal is to find that
flag.

The original binary is packed using UPX (which can be identified through
the "strings" utility), but the unpacked binary contains symbols which
indicate the location of the flag. This script identifies the target
string without requiring the use of symbols. In addition, this script
can be used to identify in-memory strings of other binaries as well.

When this script is run on the packed binary, you will notice a lot of
strings being printed during unpacking. These could be filtered out,
however, we know the valid string by when the string in "strcpy"ed.
"""


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
    Identifies strings that are written in-memory. We identify strings
    by the observation that when they are written to memory
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
        self.strings_found: List[str] = []

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
            self.strings_found.append(self._current_string)
        self._current_string = ""


if __name__ == "__main__":
    main()
