# 01 - Command Line Use

To emulate a binary with default options:

```console
$ zelos my_binary
```

To emulate a binary and view the instructions being executed, add the `-v` flag:
```console
$ zelos -v my_binary
```

To print only the *first* time an instruction is executed, rather than *every* instruction, using the `--fasttrace` flag:
```console
$ zelos -v --fasttrace my_binary
```

To write output to a file use the `--trace_file` flag:
```console
$ zelos --trace_file /path/to/file my_binary
```

To provide command line arguments to the emulated binary, specify them after the binary name:
```console
$ zelos my_binary arg1 arg2
```

To log various Zelos-related debug information, you can specify log level with flag `--log` and specify one of the options from 'info', 'verbose', 'debug', 'spam', 'notice', 'warning', 'success', 'error', or 'fatal'. The default options is 'info'.
```console
$ zelos --log debug my_binary
```

To specify a timeout in seconds, after which emulation will stop, use the flag `-t`:
```console
$ zelos -t 10 my_binary
```

To specify a memory limit in mb, after which an exception is thrown an emulation will stop, use the flag `m`:
```console
$ zelos -m 1024 my_binary
```

To specify a virtual filename, the name that will be used for the binary during emulation, use the `--virtual_filename` flag:
```console
$ zelos --virtual_filename virtualname my_binary
```

To specify a virtual file path, the path that will be used for the binary during emulation, use the `--virtual_path` flag:
```console
$ zelos --virtual_path /home/admin/ my_binary
```

To specify environment variables to use during emulation, use the `--env_vars` (`-ev`) flag. This can be specified multiple times to set multiple environment variables:
```console
$ zelos --env_vars FOO=bar --env_vars LOREM=ipsum my_binary
```

To specify the date in YYYY-MM-DD format, use the `--date` flag. This is primarily used when emulating date-related system calls such as __time__ and __gettimeofday__.
```console
$ zelos --date 2020-03-04 my_binary
```

To see an example of the above, you can use zelos to emulate the `date` GNU coreutil. This is included on most linux systems at `/bin/date`. The source code for `date` is available [here](https://github.com/coreutils/coreutils/blob/master/src/date.c).
```
$ zelos --date 2020-03-04 /bin/date
```

To mount a specified file or path into the emulated filesystem, use the `--mount` flag. The format is `--mount ARCH,DEST,SRC`. `ARCH` is one of `x86`, `x86-64`, `arm`, or `mips`. `DEST` is the emulated path to mount the specified `SRC`. `SRC` is the absolute host path to the file or path to mount.
```
$ zelos --mount x86,/path/to/dest,/path/to/src my_binary
```

To specify a directory to use as the rootfs directory during emulation of a linux system, use `--linux_rootfs` flag. The format is `--linux_rootfs ARCH,PATH`. `ARCH` is one of `x86`, `x86-64`, `arm`, or `mips`. `PATH` is the absolute host path to the directory to be used as rootfs. For example, if you were running Zelos on a linux host machine, and you wanted to use your own root filesystem as the emulated rootfs, you would do the following:
```console
$ zelos --linux_rootfs x86,/ my_binary
```
