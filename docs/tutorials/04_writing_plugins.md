# 04 - Creating Plugins

This tutorial demonstrates how the in-memory string finding script from the previous tutorial can be adapted to a plugin.

Files and scripts from this tutorial are available in the [examples/inmemory_strings](https://github.com/zeropointdynamics/zelos/blob/master/examples/inmemory_strings) directory.

## Plugin Overview

Plugins are ways that make sharing additional functionalities for Zelos even easier. Plugins can be used to
  * Modify how Zelos executes
  * Provide additional output from zelos
  * Extend Zelos's capabilities

In order for Zelos to find plugins, the python module containing the plugin must be located in a path specified by the `ZELOS_PLUGIN_DIR` environment variable.

## Building a Minimal Plugin
```eval_rst
Zelos identifies plugins as objects that subclass the :py:class:`zelos.IPlugin` class.
```
```python
from zelos import IPlugin

class MinimalPlugin(IPlugin):
    pass
```

If we include this in a file `/home/kevin/zelos_plugins/MinimalPlugin.py`, let's just set our environment up appropriately before running zelos with our plugin!

```
$ ZELOS_PLUGIN_DIR=$ZELOS_PLUGIN_DIR,`/home/kevin/zelos_plugins`
$ zelos target_binary
Plugins: runner, minimalplugin
...
```
```eval_rst
Unfortunately, our plugin doesn't do much at the moment. We can add some functionality, but first we should have a way to turn our plugin on and off from the command line. This prevents plugins from running costly operations or printing extraneous output when they aren't being used.  The easiest way to do this is by specifying a :py:class:`zelos.CommandLineOption` to add flags to the zelos command line tool. The arguments for creating a :py:class:`zelos.CommandLineOption` are identical to the python :code:`argparse` library's `add_argument() <https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser.add_argument>`_ function.

The ideal time to activate the plugin is when the plugin is initialized by Zelos through the  :code:`__init__` function. You can add your own initialization code by creating an :code:`__init__` which takes :py:class:`zelos.Zelos` as an input. Remember to begin with a call to the parent :code:`__init__` function.
```

```python
from zelos import IPlugin, Zelos

class MinimalPlugin(IPlugin):
    def __init__(self, z:Zelos):
        super.__init__(z)
        print("Minimal plugin is created.")
```
```eval_rst
Now, we add the :py:class:`zelos.CommandLineOption` to change behavior at run time. The option can then be accessed using :py:class:`zelos.Zelos`'s :code:`config` field.
```

```python
from zelos import IPlugin, CommandLineOption

CommandLineOption('activate_minimal_plugin', action='store_true')

class MinimalPlugin(IPlugin):
    def __init__(self, z):
        super.__init__(z)
        print("Minimal plugin is created.")
        if z.config.activate_minimal_plugin:
            print("Minimal plugin has been activated!")
```

Now we can change the behavior of zelos using our `MinimalPlugin`!

```
$ zelos target_binary
Minimal plugin is created.
...
$ zelos --activate_minimal_plugin target_binary
Minimal plugin is created.
Minimal plugin has been activated!
...
```
Now to do something a bit more complicated.

## Creating the In-Memory Strings Plugin.
The script from [the previous tutorial](03_using_hooks.md) can be converted into a plugin so that we can easily use it in the future.

The following plugin showing how to collect in-memory strings can be found at [examples/inmemory_strings/strings_plugin.py](https://github.com/zeropointdynamics/zelos/blob/master/examples/inmemory_strings/strings_plugin.py). To invoke the plugin, run `zelos --print_strings 4 target_binary`.

```python
from zelos import CommandLineOption, Zelos, HookType, IPlugin

CommandLineOption(
    "print_strings",
    type=int,
    default=None,
    help="The minimum size of string to identify",
)

class StringCollectorPlugin(IPlugin):
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

```
