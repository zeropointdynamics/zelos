## Hello Zelos

The sources for this example can be found at
https://github.com/zeropointdynamics/zelos/tree/master/examples/hello

To emulate a binary with Zelos:

```python
from zelos import Zelos

z = Zelos("hello.bin")
z.start()
```

Which produces the following output

```
[main] [SYSCALL] brk ( addr=0x0 ) -> 90000038
[main] [SYSCALL] brk ( addr=0x90001238 ) -> 90001238
[main] [SYSCALL] arch_prctl ( option=0x1002 (ARCH_SET_FS), addr=0x90000900 ) -> 0
[main] [SYSCALL] uname ( buf=0xff08eae0 ) -> 0
[main] [SYSCALL] readlink ( pathname=0x57ee83 ("/proc/self/exe"), buf=0xff08dc10, bufsiz=0x1000 ) -> 31
[main] [SYSCALL] brk ( addr=0x90022238 ) -> 90022238
[main] [SYSCALL] brk ( addr=0x90023000 ) -> 90023000
[main] [SYSCALL] access ( pathname=0x57ea5a ("/etc/ld.so.nohwcap"), mode=0x0 ) -> -1
[main] [SYSCALL] fstat ( fd=0x1 (stdout), statbuf=0xff08ea50 ) -> 0
IOCTL: 0
[main] [SYSCALL] ioctl ( fd=0x1 (stdout), request=0x5401, data=0xff08e9b0 ) -> -1
[StdOut]: 'bytearray(b'Hello, Zelos!\n')'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x900132d0 ("Hello, Zelos!\n"), count=0xe ) -> e
16:36:17:threads___:SUCCES:Done executing thread main
[main] [SYSCALL] exit_group ( status=0x0 ) -> void
```
