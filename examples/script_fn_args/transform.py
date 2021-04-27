from zelos import Zelos

z = Zelos("transform.bin", inst=True, fasttrace=True)
# z = Zelos("transform.bin")

z.set_breakpoint(0x08049795)

z.start()

# STOPPED at breakpoint
z.memory.write_string(0xff08ecbc, "NEWSTRING")
z.set_breakpoint(0x080497a4)

z.start()

# STOPPED at breakpoint
s = z.memory.read_string(0xff08ed3c, 128)

z.stop()

print(f"The string is: {s}")
