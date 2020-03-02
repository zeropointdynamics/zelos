from zelos import CommandLineOption, HookType, IPlugin, Zelos


"""
# tl;dr

This is a copy of the strings_script.py file, except written as a Zelos
plugin. In order to include this plugin, you must either

  * copy this file into the zelos/ext/plugins folder
  * specify the containing folder in the ZELOS_PLUGIN_DIR environment
    variable


"""

CommandLineOption(
    "print_strings",
    type=int,
    default=None,
    help="The minimum size of string to identify",
)


class StringCollectorPlugin(IPlugin):
    NAME = "strings"
    """
    Identifies strings that are written in-memory. We identify strings by the
    observation that when they are written to memory
      * They are comprised of valid utf-8 bytes
      * The string is written in sequential chunks.

    This runs into some false positives with data that happens to be
    valid utf-8. To reduce false positives we observe that
      * Strings often end at the first null byte.
      * False positives are often short strings. There is a higher
        chance that 2 consecutive characters are valid utf-8 than
        4 consecutive characters.

    """

    def __init__(self, z: Zelos):
        super().__init__(z)
        if z.config.print_strings:
            z.hook_memory(
                HookType.MEMORY.WRITE,
                self.collect_writes,
                name="strings_syscall_hook",
            )
            self._min_len = z.config.print_strings
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
