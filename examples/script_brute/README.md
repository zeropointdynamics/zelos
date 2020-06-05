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
    z = Zelos("password.bin", inst=True)
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
    z = Zelos("password.bin", inst=True)
    # The address of strcmp observed above
    strcmp_address = 0x00400BB6
    # run to the address of call to strcmp and break
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
    z = Zelos("password.bin", inst=True)
    # The address of strcmp observed above
    strcmp_address = 0x00400BB6
    # run to the address of call to strcmp and break
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
        # run to the address of test instr and break
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
