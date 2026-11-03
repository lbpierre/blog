+++
title = "BACK TextShell Automatic Unpacking : Give your F7 key a vacation 🐚"
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

{{< figure src="/ox-hugo/header_textshell.jpeg" >}}


## Introduction {#introduction}

If you have been tracking malvertising campaigns over the past year or so, you have probably
run into what is now commonly referred to as the _TextShell_ packer  or `pkr_mtsi` in
ReversingLabs nomenclature. The packer was first spotted in the wild around April 2025 and
has been in continuous use since. It shows up in fake software installer campaigns
impersonating tools like PuTTY, WinSCP, or Rufus: the usual SEO-poisoning and malvertising
playbook. On the payload side, depending on the campaign, it has been observed dropping Oyster
(a.k.a. OysterLoader / Broomstick), Vidar infostealer, and a handful of other commodity
malware families.

The packer itself was covered in depth by [ReversingLabs](https://www.reversinglabs.com/blog/unpacking-pkr_mtsi) in January 2026, and the Oyster loader
it delivers was documented by [Sekoia.io](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/) in February 2026. The [Huntress report on Gootloader](https://www.huntress.com/blog/gootloader-threat-detection-woff2-obfuscation)
also has a relevant section on the OysterLoader distribution chain. This post is not a
re-analysis of those findings. If you want the full static analysis of the packer internals
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
    output from memory.

3.  **Stage 3 (final payload)**: Whatever the packer was carrying  Oyster, Vidar, or
    something else  now sitting on disk as a clean binary.

Before any emulation happens though, there is a pre-processing step: the API hammering calls
in the packer's `.text` section get patched to NOPs. Without that, Qiling trips over the
hundreds of GDI calls that have no corresponding implementation in the emulated environment.
The sections below walk through each component in order.


## TextShell at a Glance {#textshell-at-a-glance}

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
    `ZwAllocateVirtualMemory`, adding a layer of indirection through NTDLL. Either way the
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


## Pre-processing: Killing the API Hammering {#pre-processing-killing-the-api-hammering}


### The Problem {#the-problem}

Qiling is a full-system emulator. When you run a PE under it, it intercepts Windows API calls
and services them through its own implementation layer. That works well for the APIs you care
about  `VirtualAlloc`, `IsDebuggerPresent`, and so on  but TextShell imports dozens of GDI
functions that Qiling either does not implement or implements incompletely. With hundreds of
calls to those functions spread across the entry function, the emulation either crashes or
produces incorrect behaviour before it reaches the allocation code you actually need to hook.

The fix is straightforward: before handing the binary to Qiling, patch every call to an
irrelevant imported DLL function with NOP instructions. The `TextShellPECleaner` class does
exactly this.


### Finding the Import Address Range {#finding-the-import-address-range}

The cleaner's first step is to establish the address range that corresponds to imported
functions. `pefile` parses the import directory and iterates over every imported symbol to
find the minimum and maximum function addresses:

```python
def get_imported_function_addresses(self) -> tuple[int, int]:
    _min, _max = 0, 0
    for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
        for func in dll.imports:
            if func.address < _min:
                _min = func.address
            elif func.address > _max:
                _max = func.address
    return _min, _max
```

This gives a numeric range `[_min, _max]` that covers all imported function thunks. Any
`call` instruction whose resolved destination falls within that range is a candidate for
patching.


### Identifying Calls to Patch {#identifying-calls-to-patch}

Capstone disassembles the entire `.text` section. For each `CALL` instruction, the cleaner
checks whether the operand is a memory-indirect call through RIP  the typical pattern for
imported function calls in 64-bit PE files:

```python
# call qword ptr [rip + offset]
if called.type == X86_OP_MEM:
    rip = insn.address
    offset = called.mem.disp
    potential_dll_call = rip + offset + 6
    if potential_dll_call in whitelisted_addresses:
        continue
    if potential_dll_call >= border[0] and potential_dll_call <= border[1]:
        calls.append(insn.address)
```

The `+6` accounts for the length of the `call qword ptr [rip+disp32]` instruction itself,
which is how RIP-relative addressing works: RIP points to the **next** instruction at the time
the displacement is evaluated.

Two addresses are explicitly whitelisted before the search runs:

-   `IsDebuggerPresent`  the hook needs this call to remain in place so the Qiling API hook
    fires and returns zero.
-   `VirtualAlloc`  same reason, the allocation hook depends on this call being present.

`ZwAllocateVirtualMemory` does not appear in the import table for the variants that use it
(it is resolved dynamically via PEB traversal), so it does not need special handling here.


## Patching and Rebuilding {#patching-and-rebuilding}

Each identified call address gets six NOP bytes written over it. The instruction is always
six bytes because `call qword ptr [rip+disp32]` encodes as `FF 15 xx xx xx xx`:

```python
def patch_sample(self, calls: list[int]):
    base_image_addr = self.pe.OPTIONAL_HEADER.ImageBase
    text = self.get_section(b".text")
    _code = bytearray(self.code)
    patched_instructions = b"\x90" * 6

    for call in calls:
        offset = call - base_image_addr - text.VirtualAddress
        _code[offset : offset + 6] = patched_instructions

    self.code = bytes(_code)
```

The offset calculation converts the virtual address of the instruction back to a raw offset
into the section data: `VA - ImageBase - SectionVA`.

After patching, the PE is rebuilt by concatenating the original header, the patched `.text`
section, and all other sections verbatim:

```python
def rebuild_pe(self) -> bytes:
    new_pe = self.pe.header
    new_pe += self.code  # patched .text
    for section in self.pe.sections:
        if not section.Name.startswith(b".text"):
            new_pe += section.get_data()
    return new_pe
```

This is a minimal rebuild  it does not update the section headers or recalculate checksums.
It is good enough for Qiling to load and execute, which is all we need.


## Stage 1 Emulation: Extracting the Shellcode {#stage-1-emulation-extracting-the-shellcode}

With a cleaned PE on disk, we can now emulate it under Qiling and intercept the memory
allocation to find out where the stage 2 shellcode lands. Two classes are involved here:
`TextShellPEEmulator` drives the Qiling emulation, and `TinyShellcodeEmulator` handles a
follow-up Unicorn emulation to resolve the shellcode entrypoint offset.


### Qiling Setup {#qiling-setup}

`TextShellPEEmulator` initialises Qiling with ASLR disabled  a necessary setting because we
need predictable addresses when reading back the allocated buffer:

```python
cfg = {"os": {"aslr": False}}
self.ql = Qiling(
    [self.target_pe], self.rootfs, verbose=QL_VERBOSE.DEFAULT, profile=cfg
)
```

Qiling requires the target PE to live inside the rootfs directory it is given. The
`_prepare_workspace` method in `TextShellUnpacker` handles this by copying the (cleaned) PE
into the rootfs before setup runs:

```python
dest = os.path.join(self.rootfs, "packer.bin")
shutil.copy2(self.pe_path, dest)
```

This is a Qiling constraint, not a design choice  Qiling builds its Windows path mappings
relative to the rootfs root, so the binary must be reachable from there.


### Hooking the Allocation Functions {#hooking-the-allocation-functions}

The goal of the emulation is to find out where the packer writes its stage 2 payload. The
packer allocates that region via `VirtualAlloc` (older variants) or `ZwAllocateVirtualMemory`
(newer variants). We hook both.

The hook for `VirtualAlloc` intercepts the call, allocates memory inside Qiling's address
space, and stores the resulting address in the unpacker context object:

```python
@winsdkapi(
    cc=STDCALL,
    params={
        "lpAddress": POINTER,
        "dwSize": SIZE_T,
        "flAllocationType": DWORD,
        "flProtect": DWORD,
    },
)
def hook_VirtualAlloc(ql, address, params):
    preferred_addr = params["lpAddress"]
    request_size = params["dwSize"]

    if request_size % 0x1000 != 0:
        request_size = (request_size + 0x1000) & ~0xFFF

    if preferred_addr != 0:
        final_addr = preferred_addr
        ql.mem.map(final_addr, request_size)
    else:
        final_addr = ql.mem.map_anywhere(request_size)

    unpacker = ql.unpacker_context
    unpacker.shellcode_location = final_addr
    unpacker.shellcode_size = request_size

    return final_addr
```

The `hook_ZwAllocateVirtualMemory` hook follows the same logic but has to deal with
pointer-to-pointer arguments: the base address and size are passed as pointers that the
function is expected to write back into, which is how the NT syscall interface works:

```python
base_addr_ptr = params["BaseAddress"]
region_size_ptr = params["RegionSize"]

request_size = ql.mem.read_ptr(region_size_ptr)
preferred_addr = ql.mem.read_ptr(base_addr_ptr)

# ... allocate ...

ql.mem.write_ptr(base_addr_ptr, final_addr)
ql.mem.write_ptr(region_size_ptr, request_size)
```

Both hooks are registered before the emulation starts:

```python
self.ql.os.set_api("ZwAllocateVirtualMemory", hook_ZwAllocateVirtualMemory)
self.ql.os.set_api("NtAllocateVirtualMemory", hook_ZwAllocateVirtualMemory)
self.ql.os.set_api("IsDebuggerPresent", hook_IsDebuggerPresent)
self.ql.os.set_api("VirtualAlloc", hook_VirtualAlloc)
self.ql.loader.PEB.BeingDebugged = 0
```

Setting `PEB.BeingDebugged = 0` directly is a belt-and-suspenders measure on top of the
`IsDebuggerPresent` hook. The hook itself just reads that field and returns it:

```python
@winsdkapi(cc=STDCALL, params={})
def hook_IsDebuggerPresent(ql: Qiling, address: int, params):
    return ql.loader.PEB.BeingDebugged
```


## Reading Back the Payload {#reading-back-the-payload}

After `ql.run()` completes (or raises, which is expected  the packer will eventually try to
execute the shellcode and crash inside Qiling), `shellcode_location` and `shellcode_size`
hold the address and size of the allocated region. Reading it back is one line:

```python
buff = self.ql.mem.read(self.shellcode_location, self.shellcode_size)
```

This is the raw stage 2 shellcode. Before we can emulate it, we need to know where inside it
execution should start  i.e., the value that the packer loaded into the register it jumps to
at the end of the entry function.


### Finding the Shellcode Entrypoint: Walking .text Backwards {#finding-the-shellcode-entrypoint-walking-dot-text-backwards}

The packer's entry function ends with a `jmp reg` or `call reg` instruction. The register
holds the entrypoint offset into the allocated shellcode buffer. To find that offset without
running a debugger, `find_next_stage_ep_offset` does the following:

1.  Disassemble the `.text` section from the PE entrypoint onwards with Capstone.
2.  Stop at the first `RET` instruction  that is the end of the entry function.
3.  Walk the collected instructions backwards until a `JMP` or `CALL` is found.
4.  Take the 20 instructions preceding that jump and re-emulate them in isolation with
    `TinyShellcodeEmulator`.

<!--listend-->

```python
for insn in md.disasm(code, image_base_address + text_section.VirtualAddress):
    if insn.address > ep:
        instructions.append(insn)
        if insn.id == X86_INS_RET:
            break

_offset = 0
for idx, insn in enumerate(instructions[::-1]):
    if insn.id in (X86_INS_JMP, X86_INS_CALL):
        _offset = idx
        break

offset_invoke = len(instructions) - _offset - 1
cs_shellcode_jumper = instructions[offset_invoke - 20 : offset_invoke + 1]

shellcode = b""
for insn in cs_shellcode_jumper:
    shellcode += insn.bytes
```

The 20-instruction window is pragmatic. The sequence that computes the register value and
then jumps is self-contained  it does not depend on global state set earlier in the function.
In practice, taking the last 20 instructions before the jump captures the entire computation.


### TinyShellcodeEmulator: Resolving the Register Value {#tinyshellcodeemulator-resolving-the-register-value}

`TinyShellcodeEmulator` takes the raw bytes of those `20 instructions and runs them in
Unicorn. It hooks every instruction and watches for the moment execution reaches the
~jmp~/~call` at the end of the sequence. When it does, Capstone disassembles that single
instruction to identify which register is used, and Unicorn reads the register's value:

```python
def hook_code(self, uc, address, size, user_data):
    if address >= self.ADDRESS_OF_INVOKE:
        code_bytes = uc.mem_read(address, size)
        reg_name = self.get_capstone_reg(code_bytes)

        if reg_name:
            uc_reg_id = REG_MAP.get(reg_name)
            if uc_reg_id:
                target_val = uc.reg_read(uc_reg_id)
                self.reg_target = target_val

        uc.emu_stop()
```

`get_capstone_reg` uses Capstone to identify the register operand of the `CALL` or `JMP`:

```python
def get_capstone_reg(self, code_bytes) -> str | None:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code_bytes, 0):
        if insn.id in [X86_INS_CALL, X86_INS_JMP] and len(insn.operands) > 0:
            if insn.operands[0].type == X86_OP_REG:
                return insn.reg_name(insn.operands[0].reg)
    return None
```

The reason for using Capstone here rather than just reading the opcode bytes directly is
register naming: Capstone returns a canonical string like `"rax"` or `"r14"` that maps
cleanly to the Unicorn register constant table. It avoids a fragile manual opcode-to-register
decoding step.

The `ADDRESS_OF_INVOKE` is computed as `BASE_ADDRESS + len(shellcode) - 2`. The last
instruction of the extracted sequence is the `jmp~/~call`, and the `-2` accounts for the
minimum encoding length of those instructions. In practice it means the hook fires on the
last one or two instructions of the miniature emulation, which is all we need.

After `run_emulation()` completes, `tiny_shellcode_emu.reg_target` holds the stage 2
shellcode entrypoint address  the absolute virtual address that the packer would have jumped
to. The caller extracts the offset from there.


## Stage 2 Emulation: Decompressing the Payload {#stage-2-emulation-decompressing-the-payload}


### What Stage 2 Is {#what-stage-2-is}

The memory region extracted from stage 1 is a custom shellcode whose job is to decompress
the actual stage 3 payload. The decompressed output is written to the **beginning** of the
shellcode's own memory region  it inflates in place, overwriting the leading bytes of the
buffer with the result. The end of the buffer remains the compressed shellcode itself.

This in-place layout is what makes extraction straightforward: after the shellcode finishes,
the beginning of the memory region contains the stage 3 PE, and the trailing zeroed-out area
marks where the payload ends.


### Unicorn Setup {#unicorn-setup}

`InflateShellcodeEmulator` maps the shellcode into Unicorn's address space starting at
`0x1000`, sets up a 2MB stack at `0x70000000`, and runs from the entrypoint offset that
`TinyShellcodeEmulator` resolved in the previous step:

```python
def init(self):
    def align_page(size):
        return (size + 0xFFF) & ~0xFFF

    code_size = align_page(len(self.shellcode))
    self.mu.mem_map(self.base_address, code_size)
    self.mu.mem_write(self.base_address, self.shellcode)

    STACK_ADDRESS = 0x70000000
    STACK_SIZE = 2 * 1024 * 1024
    self.mu.mem_map(STACK_ADDRESS, STACK_SIZE)
    self.mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 0x100)
```

Page alignment is required by Unicorn  `mem_map` will reject sizes that are not multiples of
`0x1000`. The `align_page` helper rounds up to the next page boundary.

A hook is added to catch unmapped memory writes, which helps diagnose crashes during
development:

```python
def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(f"[!] Invalid WRITE at {hex(address)}")
    return False

self.mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
```


### Running and Extracting the Output {#running-and-extracting-the-output}

Emulation runs from `base_address + entrypoint` to `base_address + len(shellcode)`:

```python
self.mu.emu_start(
    begin=self.base_address + self.entrypoint,
    until=self.base_address + len(self.shellcode),
)
```

Unicorn will almost certainly raise a `UcError` before reaching the `until` address  the
shellcode will eventually try to do something Unicorn cannot service (an API call, a CPUID,
etc.). That is expected and handled in the `try/except` block. What matters is that the
decompression loop ran to completion before the crash.

After the emulation terminates, `extract_inflate_payload` reads the output back. It scans
forward through the buffer from the beginning, stopping at the first run of zero bytes  that
is where the payload ends and the trailing padding begins:

```python
def find_end_area(self) -> int:
    for offset, byte in enumerate(bytearray(self.shellcode)):
        if byte != 0:
            return offset - 2
    return 0

def extract_inflate_payload(self) -> bytes:
    end = self.find_end_area()
    payload = self.mu.mem_read(self.base_address, self.base_address + end)
    return bytes(payload)
```

A quick sanity check looks for the `MZ` magic bytes in the extracted data:

```python
print("[*] found a valid PE in inflated data") if b"MZ" in next_stage \
    else print("[!] failed to unpack TextShell")
```


## Putting It All Together {#putting-it-all-together}

`TextShellUnpacker` is the top-level class that sequences everything above. Its `run()`
method is a straight pipeline:

```python
def run(self):
    # 1. Clean the API hammering
    self.clean_pe = self.textshell_pe_cleaner.clean()
    filepath = os.path.join(self.rootfs, "packer.bin")
    with open(filepath, "wb") as f:
        f.write(self.clean_pe)

    # 2. Emulate stage 1 under Qiling, get the shellcode buffer
    self.textshell_pe_emulator.setup()
    self.stage2 = self.textshell_pe_emulator.run()

    # 3. Find the shellcode entrypoint
    stage2_entrypoint = self.textshell_pe_emulator.find_next_stage_ep_offset()

    # 4. Emulate stage 2 under Unicorn, decompress stage 3
    self.inflate_shellcode_emulator.entrypoint = stage2_entrypoint
    self.inflate_shellcode_emulator.shellcode = self.stage2
    self.inflate_shellcode_emulator.init()
    self.stage3 = self.inflate_shellcode_emulator.run()

    # 5. Dump the final payload
    self.dump_payload("unpacked", self.stage3)
```

A few practical points worth noting:

-   **The rootfs write happens twice**. `_prepare_workspace` copies the original PE into the
    rootfs at init time. After cleaning, the cleaned PE overwrites the same path. Qiling picks
    up the cleaned version because `setup()` is called after the write.

-   **`dump_all` flag**: When set, the cleaner output (`-clean.bin`) and the raw stage 2
    shellcode (`-stage2.bin`) are also written to disk in addition to the final payload
    (`-unpacked.bin`). Useful for debugging, not needed for routine extraction.

-   **File naming**: Dumps are prefixed with the SHA-1 of the original input file. This keeps
    output directories clean when processing batches of samples and lets you correlate outputs
    back to their source.

The script is invoked from the command line:

```sh
python unpacker.py \
    --pe-path /path/to/sample.exe \
    --rootfs /path/to/rootfs/x8664_windows \
    --output-path /tmp/unpacked \
    --dump-all
```

Qiling's rootfs for Windows x86-64 is a separate repository
(`qilingframework/rootfs`) that needs to be cloned separately. It provides the DLL stubs
that Qiling uses to service Windows API calls during emulation.


## Limitations and Known Blind Spots {#limitations-and-known-blind-spots}

The script works reliably on the variants described in the ReversingLabs and Sekoia.io
reports. There are a few areas where it will need adjustment as the packer evolves:


### The Cleaner Has Blind Spots {#the-cleaner-has-blind-spots}

`TextShellPECleaner` identifies junk calls by checking whether the resolved call destination
falls within the import table address range. This works for `VirtualAlloc`-era variants where
the relevant DLLs are listed in the import directory. For newer variants that resolve all APIs
dynamically via PEB traversal and hash comparison  including `ZwAllocateVirtualMemory`
those calls do not appear in the import table and therefore are not patched. The cleaner will
leave them in place, which may or may not cause problems depending on how Qiling handles the
indirect calls. A solution would be to resolve dynamically the API before cleaning the PE,
then identify one that are used to allocate memory (`VirtualAlloc`, `HeapAlloc`, etc...) and
incorporate these into the API not to clean. And therefore prepare these functions signature
for Qiling hook's.


### The 20-Instruction Window Is a Heuristic {#the-20-instruction-window-is-a-heuristic}

The assumption that 20 instructions before the shellcode invocation are sufficient to
reconstruct the register value is based on observed samples. If a future variant uses a
longer computation to derive the entrypoint  for example, by pulling in a value set much
earlier in the function  the window will need to be widened. The symptom would be
`TinyShellcodeEmulator` producing `reg_target = 0` or a clearly wrong address.


### DLL Variant Support {#dll-variant-support}

The current hooks and emulation flow are designed around the EXE variant of TextShell. DLL
variants have additional execution paths (DLL unload events, `DllRegisterServer` export) and
pass different parameters through to the payload. The `fdwReason` check in the DLL main
function is not currently handled, which means the emulation may not reach the payload
allocation code for DLL samples without additional hooks.


## Conclusion {#conclusion}

The unpacker automates what would otherwise be a manual process: patch the noise, emulate
the loader, intercept the allocation, find the entrypoint, emulate the decompressor, read the
output. Each step maps to a class in the script, and each class has a narrow responsibility.

Chaining Qiling and Unicorn for different stages of the same unpacking pipeline is a
reasonable pattern for this kind of multi-stage loader. Qiling gives you the full Windows API
emulation surface you need for stage 1, and Unicorn gives you the bare-metal speed and
control you need for the raw shellcode in stage 2  where there are no API calls, only
arithmetic and memory writes.

The script as presented handles the variants active through early 2026. As ReversingLabs'
analysis notes, the packer author has been iterating steadily removing UPX artifacts,
switching from `VirtualAlloc` to `ZwAllocateVirtualMemory`, varying hash constants. The
architecture of the unpacker should absorb most of those changes with targeted hook updates
rather than structural rewrites.

The full script is available at: `[link to your repository]`
