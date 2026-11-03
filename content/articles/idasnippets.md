+++
title = "IDAPython Snippets 🔩"
author = ["pbo"]
description = "A collection of reusable IDAPython scripts for everyday reverse engineering tasks."
publishDate = 2024-03-17T00:00:00+01:00
aliases = ["/notes/idasnippets/"]
tags = ["python"]
categories = ["IDA"]
draft = false
+++

{{< figure src="/ox-hugo/idapython_snippets_header.jpg" >}}


## Type of instruction {#type-of-instruction}

Decompile an instruction at a given address `ea` (_below_) and print
the type of memory if the instruction is a `mov`.

```python
insn = idaapi.insn_t()
length = idaapi.decode_insn(insn, ea)
if insn.itype == ida_allins.NN_mov:
    if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_mem:
	  print(f"{insn.Op1.type} is reg and {insn.Op2.type} is mem")
```


## cdecl function parameters {#cdecl-function-parameters}

Get the value of a function argument that is moved into a register before
the function call (for instance for function with the `cdecl` convention).

In the example below it reads the value of the second argument (register `edx`)
of the function at address `0x1234` and saved its value in a list named `arguments`.

```python
import idc
import idautils

resolve_func_addr = 0x1234 # replace by the address of the function

arguments = []

#+begin_src python
for ref in idautils.XrefsTo(resolve_func_addr):
    for ea in idautils.Heads(ref.frm - 10, ref.frm):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        mnemonic = print_insn_mnem(ea)
        if mnemonic == "mov":
            operand_1 = print_operand(ea, 0)
            fn_hash = idc.get_operand_value(ea, 1)
            if operand_1 == "edx":
                print(f"0x{ea:<10x} | {mnemonic} {operand_1} 0x{fn_hash:x}")
                arguments.append(fn_hash)

for arg in arguments:
    print(f"0x{arg:x}", end=", ")
```
