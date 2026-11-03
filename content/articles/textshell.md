+++
title = "TextShell Automatic Unpacking : Give your F7 key a vacation 🐚"
author = ["pbo"]
description = """
  TextShell is packer used to deliver various cybercrime malware including OysterLoader,
  SUPER backdoor. The malware is developped in C and is composed of two stages. The
  first one attempts to mimickate legitimate software using graphical API call
  and the second one is a shellcode that aimed at decompressing the payload to drop
  and thereby executing it.
  This article is a saved notes to share rathan than a complite packer drill down.
  Some note about the process to unpack it automatically are shared as the final
  script to do it!
  """
publishDate = 2026-02-18T00:00:00+01:00
tags = ["packer", "python"]
categories = ["RE"]
draft = true
+++

![](/ox-hugo/header_textshell.jpeg)]]

Before diving in, here are three previous researches that worth a read before going further:

1.  [ReversingLab - Wrote a detailed drill down of the packer internals](https://www.reversinglabs.com/blog/unpacking-pkr_mtsi)
2.  [Huntress - Expose some key features of the packer and its participation in a campaign](https://www.huntress.com/blog/gootloader-threat-detection-woff2-obfuscation)
3.  [Sekoia.io - Highlight some of the packer internal feature in another type of campaign](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/)


## Context &amp; Overview {#context-and-overview}

If you have been tracking malvertising campaigns over the past year or so, you have probably
run into what is now commonly referred to as the _TextShell_ packer  or `pkr_mtsi` in
ReversingLabs nomenclature. The packer was first spotted in the wild around April 2025 and
has been in continuous use since. It shows up in fake software installer campaigns
impersonating tools like PuTTY, WinSCP, or Rufus: the usual SEO-poisoning and malvertising
playbook. On the payload side, depending on the campaign, it has been observed dropping Oyster
(a.k.a. OysterLoader / Broomstick), Vidar infostealer.

The packer itself was covered in depth by [ReversingLabs](https://www.reversinglabs.com/blog/unpacking-pkr_mtsi) in January 2026, and the Oyster loader
it delivers was documented by [Sekoia.io](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/) in February 2026. The [Huntress report on Gootloader](https://www.huntress.com/blog/gootloader-threat-detection-woff2-obfuscation)
also has a relevant section on the OysterLoader distribution chain.
This post is not a re-analysis of those findings. If you want the full static analysis of the packer internals
API hammering, PEB traversal, hash-based API resolution, the broken `NtProtectVirtualMemory`
calls  those articles cover it well. Read them first.

What this post is about is the _automation side_: given a TextShell packed binary, how do you
extract the final payload programmatically without touching a debugger? The answer is a Python
script that chains together [Unicorn](https://github.com/unicorn-engine/unicorn), [Qiling](https://github.com/qilingframework/qiling), and [Capstone](https://github.com/capstone-engine/capstone) to drive the unpacking end-to-end.

The execution flow of the unpacker mirrors the three-stage architecture of the packer itself:

1.  **Stage 1 (TextShell PE)**: The packer binary is a PE that does API hammering, dynamically
    resolves `VirtualAlloc` or `ZwAllocateVirtualMemory`, and writes the next stage into
    freshly allocated memory chunk by chunk. We emulate this with Qiling, hooking the
    allocation functions to track where the payload lands.

2.  **Stage 2 (custom shellcode)**: The memory dump from stage 1 is a custom shellcode that
    decompresses the actual payload. We emulate it with Unicorn and read out the decompressed
    output from memory. The article of ReversingLab completly and in much more professional
    analyse it key components.

3.  **Stage 3 (final payload)**: Whatever the packer was carrying  Oyster, Vidar, or
    something else  now sitting on disk as a clean binary.

Before any emulation happens though, there is a pre-processing step: the API hammering calls
in the packer's `.text` section get patched to NOPs. Without that, Qiling trips over the
hundreds of GDI calls that have no corresponding implementation in the emulated environment.
The sections below walk through each component in order.

{{< figure src="/ox-hugo/api-hammering.png" caption="<span class=\"figure-number\">Figure 1: </span>Extract of API Hammering used by TextShell" >}}

As a matter of interest, for this packer I wanted to give a try to the Qiling framework.

For the rest of the exercise, the following external dependencies are used:

-   [Lief](https://lief.re/)
-   [Capstone](https://www.capstone-engine.org/)
-   [Qiling](https://qiling.io/)
-   [Unicorn](https://www.unicorn-engine.org/)


## First Layer Unpacking {#first-layer-unpacking}

Before diving into the unpacker logic, a quick summary of what we are dealing with  just
enough context to make the code decisions below make sense.

TextShell is a PE packer. Its job is to carry a compressed next-stage payload and reconstruct
it in memory at runtime. The key structural traits that the unpacker has to handle are:

-   **API hammering**: The `.text` section is saturated with calls to GDI functions
    (`CreateSolidBrush`, `SetMapMode`, `UnrealizeObject`, etc.) that serve no functional
    purpose. They exist to bloat the function call graph, confuse heuristics, and slow down
    analysts. Across a single sample you can easily find hundreds of these scattered between the
    actual payload-write instructions.

-   **Anti-debug trap**: `IsDebuggerPresent` is called repeatedly throughout the code. If it
    returns non-zero, the packer enters an infinite loop. The emulator needs to intercept this
    and return zero.

-   **Dynamic memory allocation**: Earlier variants call `VirtualAlloc` directly to allocate the
    region where the stage 2 payload is reconstructed. More recent variants switched to
    `ZwAllocateVirtualMemory`, adding a layer of indirection through `NTDLL`. Either way the
    unpacker needs to intercept the call and record the allocated address.

-   **Chunked payload reconstruction**: The stage 2 payload is not stored as a blob. It is broken
    into one-to-eight byte immediate values dispersed across hundreds of small functions, each of
    which writes its chunk to a specific offset in the allocated region. This is what makes the
    binary so large and why the chunk count in the YARA rule from ReversingLabs has a threshold
    of 1000.

-   **Shellcode invocation**: At the end of the entry function, after all chunks have been
    written, a `jmp reg` or `call reg` instruction hands execution to the stage 2 shellcode. The
    register value at that point is the entrypoint offset into the allocated buffer.

The stage 2 shellcode is a custom decompression routine. It inflates the stage 3 PE payload
into the beginning of its own memory region, then exits. Stage 3 is the actual malware.

An analayse of different samples indicates that the first stage had a dynamic API resolution with a custom hashing
algorithm, this algorithm varies accross samples.


### Import Cleaner {#import-cleaner}

The screenshot below is cleaned version of the code showned in Figure X.

{{< figure src="/ox-hugo/api-hammering-remove.png" caption="<span class=\"figure-number\">Figure 2: </span>API hammering removed" >}}

Cleaning the code gives two informations:

1.  Better understand the packer logic
2.  Ease its emulation as we won't need to emulate tons of API calls \o/

<!--listend-->

```python
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import (
    X86_INS_JMP,
    X86_INS_CALL,
    X86_OP_REG,
    X86_OP_MEM,
    X86_INS_RET,
)


class TextShellPECleaner:

    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        self.pe = lief.parse(self.pe_path)
        self.instructions: list = []
        self.code: bytes = b""

    def get_imported_function_addresses(self) -> tuple[int, int]:
        """Parse the DIRECTORY_ENTRY_IMPORT to list
        imported DLL to retrieve function's address"""

        _min, _max = math.inf, 0

        for dll in self.pe.imports:
            print(f"[*] Packer import {dll.name}")
            for func in dll.entries:
                _min = min(_min, func.address)
                _max = max(_max, func.address)

        return _min + pe.imagebase, _max + pe.imagebase

    def get_dll_func_address(self, function_name: str) -> int | None:
        """search the address of a function that is imported from a DLL"""

        for func in self.pe.imported_functions:
            if func.name == function_name:
                return func.address

    def get_section(self, section_name: str) -> lief.PE.Section | None:
        """returns the raw content of the given section (by name)
        the data are returned as bytes"""

        for section in self.pe.sections:
            if section.name == section_name
                return section

    def get_instructions(self):
        """Return the instruction of the PE based on the .text section content"""

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        image_base_address = self.pe.imagebase
        text_section = self.get_section(".text")
        self.code = text_section.content.tobytes()

        for insn in md.disasm(
            self.code, image_base_address + text_section.virtual_address
        ):
            self.instructions.append(insn)

    def patch_sample(self, calls: list[int]):
        """Patch the .text section by replacing calls to dlls by NOP
        instructions"""

        base_image_addr = self.pe.imagebase
        text = self.get_section(".text")

        _code = bytearray(self.code)

        # as it only patch call qword ptr [rip + offset]
        # the instructions to patch are always 6 bytes long
        patched_instructions = b"\x90" * 6

        for call in calls:
            offset = call - base_image_addr - text.virtual_address
            _code[offset : offset + 6] = patched_instructions

        self.code = bytes(_code)

    def rebuild_pe(self) -> bytes:
        """rebuild the PE and replace the old .text section
        by the one with call instruction patched"""

        print("[+] rebuild the PE")
        new_pe: bytes = b""

        print(f"[+] Add old PE header {len(self.pe.header)}")
        new_pe = self.pe.header

        print("[+] add the new patched .text section")
        new_pe += self.code

        for section in self.pe.sections:
            if not section.name == ".text":
                print(f"[*] Duplicate the section {section.name}")
                new_pe += section.content.tobytes()

        try:
            _pe = lief.parse(new_pe)
        except Exception as err:
            print(f"[-] failed to build new PE {err}")
        else:
            print("The rebuild PE seems valid")

        return new_pe

    def search_call(
        self, border: tuple[int, int], is_debugger_present_addr: int | None = 0
    ) -> list[int]:
        """Search every call whose destination is located in the address range provided
        by the border paramater, the function explicitly exclude IsDebuggerPresent from
        the call to be patched"""

        calls = []

        for insn in self.instructions:
            if insn.id == X86_INS_CALL:
                operands = insn.operands
                called = operands[0]

                if called.type == X86_OP_MEM:
                    # call qword ptr [rip + offset]
                    rip = insn.address
                    offset = called.mem.disp
                    potential_dll_call = rip + offset + 6
                    if potential_dll_call == is_debugger_present_addr:
                        continue
                    if (
                        potential_dll_call >= border[0]
                        and potential_dll_call <= border[1]
                    ):
                        calls.append(insn.address)
                    else:
                        print(f"[!] {insn} for 0x{potential_dll_call:x}")

        return calls

    def clean(self) -> bytes:
        """Main function of the TextShellPECleaner:
        1. get the range addresses for the imported dlls
        2. get the address of IsDebuggerPresent (KERNEL32.dll) used for the emulator (hook)
        3. list instructions of the PE
        4. Search every call to something located in the address range of the dlls
        5. Patch the PE by replacing the call by NOP instruction
        6. Rebuild the PE (copy header and replace .text section content by the cleaned version
        """

        dll_import_range = self.get_imported_function_addresses()
        is_debugger_present_addr = self.get_dll_func_address(b"IsDebuggerPresent")
        if not is_debugger_present_addr:
            is_debugger_present_addr = 0
        print(f"[+] IsDebuggerPresent address is 0x{is_debugger_present_addr:x}")
        self.get_instructions()

        calls_addresses = self.search_call(dll_import_range, is_debugger_present_addr)
        self.patch_sample(calls_addresses)
        new_pe = self.rebuild_pe()

        return new_pe

if __name__ == "__main__":
    import sys
    cleaner = TextShellPECleaner(sys.argv[1])
    cleaned_pe = cleaner.clean()
```

NB: the cleaner does not remove call to `IsDebuggerPresent` mainly to avoid managing it
return value management. Some sample check that a debugger is not present. Keeping
this call and its verification won't be a matter in this stage emulation as Qiling is able
to hook this function call from `KERNEL32.dll` to return 0 (no debugger present) easly.


### Emulate cleaned stage 1 {#emulate-cleaned-stage-1}

Once the stage 1 has been cleaned, its objective is clear. It does a dynamic api resolution and
a wide number of memory move from a fixed addres with various (not contigous) offset.
So, we want to emulate this stage to reconstruct the buffer that is constructed by
the numerous memory mov.

Before digging in the Qiling usage to emulate the PE removed from the API hammering,
we need to known what to look for. As far as we understand this first stage, the
current stage will attempt somehow to execute the shellcode (stage 2). This could be
via a `JMP` instruction or a `CALL`. With the cleaned version of the packer, and based
on multiple sample analysis, TextShell use a `CALL` to give the control flow execution to
what is call the stage 2.

Great, two last things to identify:

1.  Which address is called
2.  The size of the next stage

The dynamic API resolution give valuable information as the only fonction that could manipulate
memory in terms of allocation is `NtAllocateVirtualMemory`. If we are able to catch this ntdll
call we will be able to answer our two requirements (address and size).

Using Qiling, this can be done by instrumentating hook. See the code below to see how the
hook on `NtAllocateVirtualMemory` is made to access the address of the allocated memory
and the requested size for the buffer.

```python
# BOOL IsDebuggerPresent();
@winsdkapi(cc=STDCALL, params={})
def hook_IsDebuggerPresent(ql: Qiling, address: int, params):
    return __is_debugger_present(ql)


@winsdkapi(
    cc=STDCALL,
    params={
        "ProcessHandle": HANDLE,
        "BaseAddress": POINTER,  # RDX: The pointer to where the address should be stored
        "ZeroBits": ULONG_PTR,
        "RegionSize": POINTER,  # R9: The pointer to the size
        "AllocationType": ULONG,
        "Protect": ULONG,
    },
)
def hook_ZwAllocateVirtualMemory(ql, address, params):

    base_addr_ptr = params["BaseAddress"]
    region_size_ptr = params["RegionSize"]

    try:
        request_size = ql.mem.read_ptr(region_size_ptr)
    except:
        request_size = 0x1000  # Fallback

    # Align size to 0x1000 (4KB page size)
    if request_size % 0x1000 != 0:
        request_size = (request_size + 0x1000) & ~0xFFF

    # Read the value at the pointer. If it is 0, we can pick anywhere.
    try:
        preferred_addr = ql.mem.read_ptr(base_addr_ptr)
    except:
        preferred_addr = 0

    if preferred_addr != 0:
        final_addr = preferred_addr
        ql.mem.map(final_addr, request_size)
        msg = "Fixed Address"
    else:
        final_addr = ql.mem.map_anywhere(request_size)
        msg = "Qiling Chosen"

    # write the allocated address into the pointer (RDX)
    ql.mem.write_ptr(base_addr_ptr, final_addr)

    # We also write back the aligned size (R9)
    ql.mem.write_ptr(region_size_ptr, request_size)

    print(f"\n[+] HOOK: ZwAllocateVirtualMemory ({msg})")
    print(f"    |-- Result written to ptr : {hex(base_addr_ptr)}")
    print(f"    |-- ALLOCATED MEMORY AT   : {hex(final_addr)}  <-- YOUR ADDRESS")
    print(f"    |-- Size                  : {hex(request_size)}")
    unpacker = ql.unpacker_context
    unpacker.shellcode_location = final_addr
    unpacker.shellcode_size = request_size

    return 0
```

Note that in the hook above, a special one one `IsDebuggerPresent` is added to ensure
0 is return to the emulated packer. This way the code won't exits and will execute as we expect!

To emulate PE file that require (and that TextShell case) DLL to work as expected, the framework
required an setup task, which is to provide a directory named `rootfs` that contains the
DLLs required by the PE and therefore the emulator. This is useful mainly for import resolution.

Qiling provide a script to execute on a Windows machine that will extract excalty what is need &lt;3.

```python
class TextShellPEEmulator:

    def __init__(
        self,
        rootfs: str = "samples/rootfs/x8664_windows",
        target_pe: str = "packer.bin",
    ):
        self.shellcode_location = 0
        self.shellcode_size = 0
        self.ql: Qiling | None = None
        self.rootfs = rootfs
        self.target_pe = os.path.join(self.rootfs, target_pe)

    def setup(self):
        if not os.path.exists(self.rootfs):
            print(
                f"Error: Rootfs not found at '{self.rootfs}'.\nPlease run: git clone https://github.com/qilingframework/rootfs.git"
            )
            return

        if not os.path.exists(self.target_pe):
            print(f"Error: Target PE '{self.target_pe}' not found.")
            return

        cfg = {"os": {"aslr": False}}
        # Initialize Qiling
        self.ql = Qiling(
            [self.target_pe], self.rootfs, verbose=QL_VERBOSE.DEFAULT, profile=cfg
        )

        self.ql.unpacker_context = self
        # Hook the API to prove the malware resolved it
        # ql.os.set_api("ZwAllocateVirtualMemory", hook_nt_allocate)
        # 2. Hook 'NtAllocateVirtualMemory' (Zw usually redirects to Nt in emulators)
        # We use QL_INTERCEPT.EXIT to run AFTER the standard logic
        self.ql.os.set_api("ZwAllocateVirtualMemory", hook_ZwAllocateVirtualMemory)
        self.ql.os.set_api("NtAllocateVirtualMemory", hook_ZwAllocateVirtualMemory)
        self.ql.os.set_api("IsDebuggerPresent", hook_IsDebuggerPresent)

        self.ql.loader.PEB.BeingDebugged = 0

    def run(self) -> bytes:
        """ "Run the emulator and extract the dedicated memory area that contains the next stage"""
        print("[*] Starting Qiling Emulation...")
        try:
            self.ql.run()
        except Exception as err:
            print(f"[!] error during Qiling emulation, {err}")

        buff = self.ql.mem.read(self.shellcode_location, self.shellcode_size)

        print(
            f"Succesfully dump the shellcode (aka: next stage) with a size of {len(buff)}"
        )

        return bytes(buff)

    def find_next_stage_ep_offset(self) -> int | None:
        """Search for the last call or jmp in the main function
        that refered to the shellcode invokation"""

        instructions = []
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        pe = lief.parse(self.target_pe)
        image_base_address = pe.imagebase

        for section in pe.sections:
            if section.Name.startswith(b".text"):
                text_section = section

        instructions = []
        code = text_section.get_data()
        ep = pe.entrypoint

        print(f"len of the code is {len(code)}; EP 0x{ep:x}")
        for insn in md.disasm(code, image_base_address + text_section.virtual_address):
            if insn.address > ep:
                instructions.append(insn)
                if insn.id == X86_INS_RET:
                    print(
                        "found RET instruction of the main function -> stop decompiling"
                    )
                    break

        # the shellcode (aka next stage) invokation is done at the end of
        # the entry function
        # the logic here is to read backwark the instruction from the entry function ret instruction
        # until it found the call or jmp instruction (the shellcode invoke)
        _offset = 0
        for idx, insn in enumerate(instructions[::-1]):
            if insn.id in (X86_INS_JMP, X86_INS_CALL):
                print(f"[*] Shellcode invokation is here 0x{insn.address:x}")
                _offset = idx
                break

        offset_invoke = len(instructions) - _offset - 1
        cs_shellcode_jumper = instructions[offset_invoke - 20 : offset_invoke + 1]

        # rebuild the shellcode from the 20 previous instructions
        # before the jmp/call as a raw byte variable
        shellcode = b""
        for insn in cs_shellcode_jumper:
            print(insn)
            shellcode += insn.bytes

        print(
            "[+] setup the TinyShellcode emulator to retrieve the address of the entrypoint of the next stage"
        )
        tiny_shellcode_emu = TinyShellcodeEmulator(shellcode)
        tiny_shellcode_emu.run_emulation()

        if tiny_shellcode_emu.reg_target:
            print(
                f"[*] Next stage entry point offset is at 0x{tiny_shellcode_emu.reg_target:x}"
            )
            return tiny_shellcode_emu.reg_target
```


### Shellcode EP {#shellcode-ep}

Things would be much more simplier if only the shellcode is executed at address 0. So to emulate the second
stage we need to find what the real entrypoint of the stage 2.

Regarding IDA or any decompiler it looks simple because the address is a kind of hardcoded. However, regarding
the chunk of instructions prerior to the shellcode call. We observed that the address is the result
of some basic memory operations (ADD, SUB, MOV, INC).

To answer this question a tiny emulator is used, its strategy is the following one:

1.  Extract only the prior few instruction before the shellcode `CALL`.
2.  Compute the various arithmetic operation resulting in the shellcode address offset computation.

<!--listend-->

```python
class TinyShellcodeEmulator:
    def __init__(self, shellcode: bytes):
        self.shellcode = shellcode
        self.BASE_ADDRESS = 0x10000
        self.ADDRESS_OF_INVOKE = (
            self.BASE_ADDRESS + len(self.shellcode) - 2
        )  # The offset of the 'call reg' or `jmp reg` (last instruction)
        self.reg_target: int = (
            0  # the value of the register used for the shellcode invoke (jmp or call)
        )

    def get_capstone_reg(self, code_bytes) -> str | None:
        """Use Capstone to find out WHICH register is being called."""

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # Disassemble the instruction
        for insn in md.disasm(code_bytes, 0):
            if insn.id in [X86_INS_CALL, X86_INS_JMP] and len(insn.operands) > 0:
                if insn.operands[0].type == X86_OP_REG:
                    return insn.reg_name(insn.operands[0].reg)
        return None

    def hook_code(self, uc, address, size, user_data):
        """# 3. The Hook Function
        # This runs before every instruction. We check if we hit our target.
        """

        # Register mapping (Capstone string -> Unicorn ID)
        REG_MAP = {
            "rax": UC_X86_REG_RAX,
            "rbx": UC_X86_REG_RBX,
            "rcx": UC_X86_REG_RCX,
            "rdx": UC_X86_REG_RDX,
            "rsi": UC_X86_REG_RSI,
            "rdi": UC_X86_REG_RDI,
            "r8": UC_X86_REG_R8,
            "r9": UC_X86_REG_R9,
            "r10": UC_X86_REG_R10,
            "r11": UC_X86_REG_R11,
            "r12": UC_X86_REG_R12,
            "r13": UC_X86_REG_R13,
            "r14": UC_X86_REG_R14,
            "r15": UC_X86_REG_R15,
        }
        print(f"0x{address:x} 0x{self.ADDRESS_OF_INVOKE:x}")

        if address >= self.ADDRESS_OF_INVOKE:
            print(f"[+] Hit target instruction at {hex(address)}")

            # A. Use Capstone to identify the register dynamically
            # Read the memory at the current address to get the instruction bytes
            code_bytes = uc.mem_read(address, size)
            reg_name = self.get_capstone_reg(code_bytes)

            if reg_name:
                print(f"[+] Capstone identified register: {reg_name}")

                # B. Read the value from Unicorn
                uc_reg_id = REG_MAP.get(reg_name)
                if uc_reg_id:
                    target_val = uc.reg_read(uc_reg_id)
                    print(
                        f"[SUCCESS] The jump target (value of {reg_name}) is: {hex(target_val)}"
                    )
                    self.reg_target = target_val
                else:
                    print(f"[-] Register {reg_name} not in map.")

            # Stop emulation (we got what we wanted)
            uc.emu_stop()

    def run_emulation(self):

        print("[-] Initializing Unicorn...")
        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        # 1. Map memory for the code (as you did before)
        # Mapping 2MB at 0x1000000
        uc.mem_map(self.BASE_ADDRESS, 2 * 1024 * 1024)

        # 2. Map memory for the STACK <--- FIX START
        # We map a separate 1MB region specifically for the stack
        STACK_ADDR = 0x2000000
        STACK_SIZE = 1024 * 1024
        uc.mem_map(STACK_ADDR, STACK_SIZE)

        # 3. Set the Stack Pointer (RSP) <--- FIX CONTINUED
        # Stacks "grow down" (from high addresses to low addresses).
        # So we set RSP to the very END of the allocated stack memory.
        # We subtract a small buffer (0x100) just to be safe.
        uc.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x100)

        print(f"[-] Stack initialized at {hex(STACK_ADDR + STACK_SIZE - 0x100)}")

        # Write the shellcode to memory
        uc.mem_write(self.BASE_ADDRESS, self.shellcode)

        # Add the hook
        uc.hook_add(UC_HOOK_CODE, self.hook_code)

        # Start emulation
        try:
            uc.emu_start(self.BASE_ADDRESS, self.BASE_ADDRESS + len(self.shellcode))
        except UcError as e:
            print(f"[-] Emulation error: {e}")
            # Debugging tip: print where RIP was when it crashed
            rip = uc.reg_read(UC_X86_REG_RIP)
            print(f"[-] Crashed at RIP: {hex(rip)}")
        else:
            print("[*] Successfully end emulation")
```


## Stage 2 {#stage-2}

However what can we takes about this shellcode structure:

1.  It decompress a payload in memory using custom LZMA
2.  Make some adjustment in it by fixing `JMP` and `CALL` instruction (<span class="underline">e.g.:</span> reallocation fixup)
3.  Prepare a memory section to host the payload to drop and execute it

{{< figure src="/ox-hugo/shellcode-overview.png" caption="<span class=\"figure-number\">Figure 3: </span>Shellcode overview (LZMA)" >}}

The next sections won't focus on how the packer works but on how to unpack it (automaticaly)! This is
the main topic of this writeup.
