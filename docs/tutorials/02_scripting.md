# 02 - Scripting with Zelos

This tutorial demonstrates how Zelos can be used as a library in scripts to
dynamically change behavior at runtime.


## Hello Zelos

Files and scripts from this example are available in the [examples/hello](https://github.com/zeropointdynamics/zelos/tree/master/examples/hello) directory.


Consider the following example binary:

```
$ ./hello.bin
Hello, Zelos!
```

To emulate this binary with Zelos:

```python
from zelos import Zelos

z = Zelos("hello.bin")
z.start()
```

Which will produce the following output:

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

## Scripting Tutorial - Bypass

The source code and test program for this tutorial can be found in the [examples/script_bypass](https://github.com/zeropointdynamics/zelos/tree/master/examples/script_bypass) directory.

Consider the following example binary:

```sh
$ ./password_check.bin
What's the password?
password
Incorrect

$ ./password_check.bin
What's the password
0point
Correct!
```

The above binary prompts the user for a password from stdin. Upon
entry of the correct password, the program will output "Correct!" to
stdout and exit. Upon entry of an incorrect password, however, the
program will output "Incorrect" to stdout.

Our objective is to bypass the password check, such that
any password can be entered and the program will always print "Correct!"
to stdout. For this tutorial we will accomplish this in three different ways,
by dynamically writing directly to memory, setting registers, and patching code.

For each of these, we start with a boilerplate script that loads the binary
and emulates normal behavior:

```python
from zelos import Zelos

def main():
    z = Zelos("password_check.bin", verbosity=1)
    z.start()

if __name__ == "__main__":
    main()
```

We can examine the output of the above script to locate where the string
comparison and subsequent check for equality actually occurs:


```
...
[main] [INS] [004017c0] <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_S_compareEmm>
[main] [INS] [004017c0] push	rbp                                                      ; push(0xff08ebf0) -> ff08ec70
[main] [INS] [004017c1] mov	rbp, rsp                                                  ; rbp = 0xff08eb80 -> ff08ebf0
[main] [INS] [004017c4] mov	qword ptr [rbp - 0x10], rdi                               ; store(0xff08eb70,0x0)
[main] [INS] [004017c8] mov	qword ptr [rbp - 0x18], rsi                               ; store(0xff08eb68,0x6)
[main] [INS] [004017cc] mov	rsi, qword ptr [rbp - 0x10]                               ; rsi = 0x0
[main] [INS] [004017d0] sub	rsi, qword ptr [rbp - 0x18]                               ; rsi = 0xfffffffffffffffa
[main] [INS] [004017d4] mov	qword ptr [rbp - 0x20], rsi                               ; store(0xff08eb60,0xfffffffffffffffa)
[main] [INS] [004017d8] cmp	qword ptr [rbp - 0x20], 0x7fffffff                        ; 0xfffffffffffffffa vs 0x7fffffff
[main] [INS] [004017e0] jle	0x4017f2
[main] [INS] [004017f2] cmp	qword ptr [rbp - 0x20], -0x80000000                       ; 0xfffffffffffffffa vs 0x-80000000
[main] [INS] [004017fa] jge	0x40180c
[main] [INS] [0040180c] mov	rax, qword ptr [rbp - 0x20]                               ; rax = 0xfffffffffffffffa
[main] [INS] [00401810] mov	ecx, eax                                                  ; ecx = 0xfffffffa
[main] [INS] [00401812] mov	dword ptr [rbp - 4], ecx                                  ; store(0xff08eb7c,0xfffffffa)
[main] [INS] [00401815] mov	eax, dword ptr [rbp - 4]                                  ; eax = 0xfffffffa
[main] [INS] [00401818] pop	rbp                                                       ; rbp = 0xff08ebf0 -> ff08ec70
[main] [INS] [00401819] ret
[main] [INS] [004012a7] mov	dword ptr [rbp - 0x2c], eax                               ; store(0xff08ebc4,0xfffffffa)
[main] [INS] [004012aa] mov	eax, dword ptr [rbp - 0x2c]                               ; eax = 0xfffffffa
[main] [INS] [004012ad] add	rsp, 0x60                                                 ; rsp = 0xff08ebf0 -> ff08ec70
[main] [INS] [004012b1] pop	rbp                                                       ; rbp = 0xff08ec70 -> 49cfa0
[main] [INS] [004012b2] ret
[main] [INS] [00401079] mov	dword ptr [rbp - 0x38], eax                               ; store(0xff08ec38,0xfffffffa)
[main] [INS] [0040107c] cmp	dword ptr [rbp - 0x38], 0
[main] [INS] [00401080] jne	0x4010d7
...

```

### Method 1 - Writing Memory

We can see from the above output that the result of comparison is
initially contained in `eax` before being moved to the memory location
at `[rbp - 0x38]` after the last `ret`. This value in memory is then
used in the subequent `cmp` instruction to determine equality. In the
above output, the `jne` instruction is what determines whether the
program will execute code that prints "Correct!" vs "Incorrect". If the
jump is taken, the program will print "Incorrect".

To bypass this, we can ensure that this jump is never taken by writing
`0x0` to the memory location that is used ub the `cmp` instruction.

```python
def patch_mem():
    z = Zelos("password_check.bin", verbosity=1)
    # The address cmp instr observed above
    target_address = 0x0040107C
    # run to the address of cmp and break
    z.set_breakpoint(target_address, True)
    z.start()

    # Execution is now STOPPED at address 0x0040107C

    # Write 0x0 to address [rbp - 0x38]
    z.memory.write_int(z.regs.rbp - 0x38, 0x0)
    # resume execution
    z.start()

if __name__ == "__main__":
    patch_mem()
```

To check our script, we can see that the last four lines of the output are:

```
...
[StdOut]: 'bytearray(b'Correct!\n')'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x900132d0 ("Correct!\n"), count=0x9 ) -> 9
11:32:11:threads___:SUCCES:Done executing thread main
[main] [SYSCALL] exit_group ( status=0x0 ) -> void
```

### Method 2 - Setting Registers

We noted in method 1 that the result of comparison is initially contained in `eax` before being moved to the memory location at `[rbp - 0x38]` after the last `ret`. Therefore,
we can accomplish the same behavior as method 1 by setting `eax` to `0x0` before
it is used.

```python
def patch_reg():
    z = Zelos("password_check.bin", verbosity=1)
    # The address of the first time eax is used above
    target_address = 0x00401810
    # run to the address of cmp and break
    z.set_breakpoint(target_address, True)
    z.start()

    # Execution is now STOPPED at address 0x00401810

    # Set eax to 0x0
    z.eax = 0x0
    # Resume execution
    z.start()

if __name__ == "__main__":
    patch_reg()
```

Again, to check our script, we can see that the last four lines of the output are:

```
...
[StdOut]: 'bytearray(b'Correct!\n')'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x900132d0 ("Correct!\n"), count=0x9 ) -> 9
12:08:38:threads___:SUCCES:Done executing thread main
[main] [SYSCALL] exit_group ( status=0x0 ) -> void
```

### Method 3 - Patching Code

An alternative approach to methods 1 & 2 is to ensure that the final
jump is never taken by replacing the `cmp` that immediately precedes the
final `jne`. In the following script, this is accomplished by replacing
`cmp dword ptr [rbp - 0x38], 0` with `cmp eax, eax`, which ensures that
the compared values never differ and the jump is never taken.

We make use of the keystone assembler to encode our replacement code, which
also includes two NOP instructions since we are replacing a 4 byte instruction.

```python
def patch_code():
    z = Zelos("password_check.bin", verbosity=1)
    # The address of the cmp instr
    target_address = 0x0040107C
    # run to the address of cmp and break
    z.set_breakpoint(target_address, True)
    z.start()

    # Execution is now STOPPED at address 0x0040107C


    # Code we want to insert
    code = b"NOP; NOP; CMP eax, eax"
    # Assemble with keystone
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)

    # replace the four bytes at this location with our code
    for i in range(len(encoding)):
        z.memory.write_uint8(target_address + i, encoding[i])

    # resume execution
    z.start()

if __name__ == "__main__":
    patch_code()
```

Yet again, to check our script, we can see that the last four lines of the output are:

```
...
[StdOut]: 'bytearray(b'Correct!\n')'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x900132d0 ("Correct!\n"), count=0x9 ) -> 9
12:12:26:threads___:SUCCES:Done executing thread main
[main] [SYSCALL] exit_group ( status=0x0 ) -> void
```

## Scripting Tutorial - Brute

The source code and test program for this tutorial can be found at
[examples/script_brute](https://github.com/zeropointdynamics/zelos/tree/master/examples/script_brute)

This example demonstrates some more of the dynamic capabilities of zelos. Consider the following example binary:

```sh
$ ./password.bin
What's the password?
password
Incorrect

$ ./password.bin
What's the password
0point
Correct!
```

The above binary prompts the user for a password from stdin. Upon
entry of the correct password, the program will output "Correct!" to
stdout and exit. Upon entry of an incorrect password, however, the
program will output "Incorrect" to stdout and then sleep for 10 seconds
before exiting.

Let's say that our objective is to dynamically brute force this password,
but we don't have time to wait 10 seconds between every failure. Our
goal is to focus only on the part of the program that checks user input,
 namely the `strcmp` function.

We start with a script that loads the binary and emulates normal behavior:

```python
from zelos import Zelos

def brute():
    z = Zelos("password.bin", verbosity=1)
    # Start execution
    z.start()

if __name__ == "__main__":
    brute()
```

We can examine the output of the above to locate where the `strcmp`
function is invoked. Here we can see the `call` to `strcmp` is invoked at
address `0x00400bb6`. Additionally, the `rsi` and `rdi` registers appear to point to the strings being compared.


```
...
[main] [INS] [00400bac] lea     rsi, [rip + 0xab349]                                      ; rsi = 0x4abefc -> "0point"
[main] [INS] [00400bb3] mov     rdi, rax                                                  ; rdi = 0xff08ec00 -> 0
[main] [INS] [00400bb6] call    0x4004b0                                                 ; call(0x4004b0)
[main] [INS] [004004b0] jmp     qword ptr [rip + 0x2d3be2]                                ; jmp(0x425df0)
[main] [INS] [00425df0] <__strcmp_ssse3>
[main] [INS] [00425df0] mov     ecx, esi                                                  ; ecx = 0x4abefc -> "0point"
[main] [INS] [00425df2] mov     eax, edi                                                  ; eax = 0xff08ec00 -> 0
...

```

Ignoring for a moment the fact that Zelos annotates pointers with the data at their location, let's modify our script to stop at the address of the call to `strcmp` and save the contents of the `rsi` & `rdi` registers. Let's also take the opportunity
to guess the password by writing a string to the address in `rdi`.

```python
from zelos import Zelos


def brute():
    z = Zelos("password.bin", verbosity=1)
    # The address of strcmp observed above
    strcmp_address = 0x00400BB6
    # run to the address of cmp and break
    z.set_breakpoint(strcmp_address, True)
    z.start()

    # Execution is now STOPPED at address 0x00400BB6

    # get initial reg values of rdi & rsi before strcmp is called
    rdi = z.regs.rdi # user input
    rsi = z.regs.rsi # 'real' password

    # Write the string "our best guess" to address in rdi
    z.memory.write_string(rdi, "our best guess")

    # Resume execution
    z.start()

if __name__ == "__main__":
    brute()
```

At this point, we can inspect the output of the above modified script to
see that we successfully wrote the string "_our best guess_" to memory,
but unfortunately (and unsurprisingly) it was not correct.

We can see that zelos has annotated register `edi` with the first 8
characters ("our best") of the string at the address pointed to. We can
also see the stdout output indicating that our guess was incorrect.

```
...
[main] [INS] [00425df0] <__strcmp_ssse3>
[main] [INS] [00425df0] mov	ecx, esi                                                  ; ecx = 0x4abefc -> "0point"
[main] [INS] [00425df2] mov	eax, edi                                                  ; eax = 0xff08ec00 -> "our best"
...

[StdOut]: 'bytearray(b"What\'s the password?\nIncorrect\n")'
[main] [SYSCALL] write ( fd=0x1 (stdout), buf=0x90001690 ("What's the password?\nIncorrect\n"), count=0x1f ) -> 1f
...
```

Now we are prepared to add the actual 'brute-force' to this script.
For this, we will need to know where the check occurs that causes
behavior to diverge when inputting a correct vs incorrect password.
This appears to occur in a `test` instruction immediately after the
`strcmp` function returns, at address `0x400bbb`.

```
...
[main] [INS] [0042702c] sub     eax, ecx
[main] [INS] [0042702e] ret
[main] [INS] [00400bbb] test    eax, eax
[main] [INS] [00400bbd] jne     0x400bcd
...
```

We will 'brute-force' by repeatedly writing our guess to memory, letting execution
run until we reach the above `test` instruction, inspect the flag `zf` set as a result
of the `test`, and reset `IP` & `rsi` & `rdi` back to the call to `strcmp` if `zf` indicates that strings differ.

```python
from zelos import Zelos


def brute():
    z = Zelos("password.bin", verbosity=1)
    # The address of strcmp observed above
    strcmp_address = 0x00400BB6
    # run to the address of cmp and break
    z.set_breakpoint(strcmp_address, True)
    z.start()

    # Execution is now STOPPED at address 0x00400BB6

    # get initial reg values of rdi & rsi before strcmp is called
    rdi = z.regs.rdi # user input
    rsi = z.regs.rsi # 'real' password

    # 'brute force' the correct string
    for i in range(9, -1, -1):

        # write our bruteforced guess to memory
        z.memory.write_string(rdi, str(i) + "point")

        # Address of the test instr
        test_address = 0x00400BBB
        # run to the address of cmp and break
        z.set_breakpoint(test_address, True)
        z.start()

        # execute one step, in this case the test instr
        z.step()

        # check the zf bit for result of test
        flags = z.regs.flags
        zf = (flags & 0x40) >> 6
        if zf == 1:
            # if correct, run to completion
            z.start()
            return

        # otherwise, reset ip to strcmp func & set regs
        z.regs.setIP(strcmp_address)
        z.regs.rdi = rdi
        z.regs.rsi = rsi


if __name__ == "__main__":
    brute()
```
