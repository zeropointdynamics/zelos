## Scripting Tutorial - Bypass

The source code and test program for this tutorial can be found in the
[examples/script_bypass](https://github.com/zeropointdynamics/zelos/tree/master/examples/script_bypass) directory.

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
    z = Zelos("password_check.bin", inst=True)
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
    z = Zelos("password_check.bin", inst=True)
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
    z = Zelos("password_check.bin", inst=True)
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
    z = Zelos("password_check.bin", inst=True)
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
