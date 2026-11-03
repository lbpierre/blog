+++
title = "Emulating CastleLoader with Flare-Emu 🏰"
author = ["pbo"]
description = "A quick reference for configuring Unicorn stack frames and emulating a CastleLoader xor loop with the flare-emu plugin."
publishDate = 2026-09-10T00:00:00+02:00
aliases = ["/notes/flare-emu-castle/"]
tags = ["python"]
categories = ["IDA"]
draft = false
+++

{{< figure src="/ox-hugo/flare-emu_header.jpg" >}}

While analyzing a sample of [CastleLoader](https://malpedia.caad.fkie.fraunhofer.de/details/win.castleloader) I decided to test out [flare-emu](https://github.com/mandiant/flare-emu) an
emulator based on [Unicorn](https://github.com/unicorn-engine/unicorn). Here are a few notes I want to keep for future reference.

For this experiment, the following sample was used: [sha256: 39addeb849aa7bd86dd08c260d5cb1d9e28bb5b194d7739341f99d816d8b61ca](https://bazaar.abuse.ch/sample/39addeb849aa7bd86dd08c260d5cb1d9e28bb5b194d7739341f99d816d8b61ca/).

The string obfuscation is fairly straightforward; the obfuscated data is constructed directly on the stack:

```nil
.text:00197730 33 C0                                   xor     eax, eax
.text:00197732 C7 45 88 68 00 71 00                    mov     [ebp+var_78], 710068h
.text:00197739 C7 45 8C 3D 00 32 00                    mov     [ebp+var_74], 32003Dh
.text:00197740 33 C9                                   xor     ecx, ecx
.text:00197742 C7 45 90 3A 00 2A 00                    mov     [ebp+var_70], 2A003Ah
.text:00197749 C7 45 94 66 00 7B 00                    mov     [ebp+var_6C], 7B0066h
.text:00197750 C7 45 98 34 00 2B 00                    mov     [ebp+var_68], 2B0034h
.text:00197757 C7 45 9C 78 00 77 00                    mov     [ebp+var_64], 770078h
.text:0019775E C7 45 A0 39 00 2B 00                    mov     [ebp+var_60], 2B0039h
.text:00197765 C7 45 A4 78 00 73 00                    mov     [ebp+var_5C], 730078h
.text:0019776C C7 45 A8 33 00 2B 00                    mov     [ebp+var_58], 2B0033h
.text:00197773 C7 45 AC 7A 00 70 00                    mov     [ebp+var_54], 70007Ah
.text:0019777A C7 45 B0 2F 00 76 00                    mov     [ebp+var_50], 76002Fh
.text:00197781 C7 45 B4 2C 00 30 00                    mov     [ebp+var_4C], 30002Ch
.text:00197788 C7 45 B8 76 00 6C 00                    mov     [ebp+var_48], 6C0076h
.text:0019778F C7 45 BC 2A 00 27 00                    mov     [ebp+var_44], 27002Ah
.text:00197796 66 89 45 C0                             mov     [ebp+var_40], ax
```

The deobfuscation routine then relies on a basic XOR loop:

```nil
.text:001977A0                         unxor_loop:                             ; CODE XREF: sub_197400+3BD↓j
.text:001977A0 8B C1                                   mov     eax, ecx
.text:001977A2 83 E0 03                                and     eax, 3
.text:001977A5 0F B6 80 18 0A 1C 00                    movzx   eax, ds:byte_1C0A18[eax]
.text:001977AC 66 33 44 4D 88                          xor     ax, word ptr [ebp+ecx*2+var_78]
.text:001977B1 66 89 84 4D 4C FF FF FF                 mov     [ebp+ecx*2+var_B4], ax
.text:001977B9 41                                      inc     ecx
.text:001977BA 83 F9 1D                                cmp     ecx, 1Dh
.text:001977BD 72 E1                                   jb      short unxor_loop
```

To emulate this using `flare-emu`, I wrote the Python snippet below.
Initially, the emulation failed because I didn't account for the required stack frame size.

To fix this, I had to manually allocate a larger stack frame by adjusting the `ebp` and `esp` registers.
Because the x86 stack grows downwards, establishing this safe workspace requires two steps:

1.  `ebp = sp + 0x400` establishes a safe starting line.
    By moving the Base Pointer higher in memory, it prevents the emulated code from accidentally overwriting existing stack data.
2.  `"esp": ebp - 0x600` defines the actual size of the frame.
    Subtracting 0x600 carves out extra bytes of usable stack space between the base pointer and the new top of the stack.

<!--listend-->

```python { linenos=true, linenostart=1 }
from flare_emu import EmuHelper

START = 0x197730
END   = 0x1977BF          # instruction AFTER the loop (the lea), NOT the jb at 0x1977BD

eh  = EmuHelper()
sp  = eh.getRegVal("esp") # need to retrieve the actual value set by Unicorn
ebp = sp + 0x400          # increase the stack base size here

eh.emulateRange(
	START,
	endAddr=END,
        registers={"ebp": ebp, "esp": ebp - 0x600})       # her

raw = eh.getEmuBytes(ebp - 0xB4, 29 * 2)                  # var_B4, 29 wide chars
print(raw.decode("utf-16-le", errors="replace").split("\x00")[0])
```

The output of the decoded strings is: `'http://94.159.113.32/service\x00'`

Here are a few other useful functions I noted down while experimenting with the plugin:

```python
sp = eh.getRegVal("esp")
print(f"Stack Pointer is at: {hex(sp)}")
```

To read data from the stack using the pointer
First option is to read a pointer-sized value (4 bytes on 32-bit, 8 bytes on 64-bit)
This is useful for grabbing variables, arguments, or return addresses

```python
top_of_stack = eh.getEmuPtr(sp)
print(f"Value at top of stack: {hex(top_of_stack)}")
```

Read a value at an offset (e.g., `[esp + 8]`)

```python
offset_val = eh.getEmuPtr(sp + 8)
print(f"Value at ESP+8: {hex(offset_val)}")
```

Read a chunk of raw bytes from the stack, for reading structs, strings,
or buffers pushed to the stack

```python
stack_buffer = eh.getEmuBytes(sp, 16) # Reads 16 bytes starting at ESP
print(f"Raw stack bytes: {stack_buffer.hex()}")
```

Read a null-terminated string from the stack, useful if a function decrypted
a string directly onto the stack

```python
stack_string = eh.getEmuString(sp)
print(f"String on stack: {stack_string}")
```
