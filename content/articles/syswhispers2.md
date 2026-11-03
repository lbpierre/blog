+++
title = "SysWhispers2 analysis 🙊"
author = ["pbo"]
description = """
  This helper comes in handy when reversing samples that use SysWhispers2
  to recover ntdll call from SysWhispers2 hashes.
  """
publishDate = 2024-03-10T00:00:00+01:00
aliases = ["/notes/syswhispers2/"]
tags = ["syscall"]
categories = ["RE"]
draft = false
+++

{{< figure src="/ox-hugo/syswhispers2_header.jpg" >}}


## Readme.md {#readme-dot-md}

[SysWhispers](https://github.com/jthuraisamy/SysWhispers2)
{{% sidenote %}}
[github.com/jthuraisamy/SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
{{% /sidenote %}} helps with evasion by generating header/ASM files implants
can use to make direct system calls.

Various security products place hooks in user-mode API functions which allow
them to redirect execution flow to their engines and detect for suspicious behaviour.
The functions in `ntdll.dll` that make the syscalls consist of just a few
assembly instructions, so re-implementing them in your own implant can bypass the
triggering of those security product hooks. This technique was popularized by [@Cn33liz](https://twitter.com/Cneelis)
and his [blog](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) post has more technical details worth reading.


## Analysis {#analysis}

VMray recently [tweeted](https://twitter.com/vmray/status/1762600614163284466) that [Pikabot](https://malpedia.caad.fkie.fraunhofer.de/details/win.pikabot) incorporates SysWhispers2
This note offers a step-by-step guide to identify the syscalls made by malware
that utilizes SysWhispers2, a technique that can be applied in any situation
where SysWhispers2 is present.
{{% sidenote %}}
_NB: Tools: IDA decompiler and xdbg_
{{% /sidenote %}} The analysis began with the sample `PERFERENDISF.jar` shared in VMRay tweet, which is available on Malware Bazaar, with the
SHA-256: [d26ab01b293b2d439a20d1dffc02a5c9f2523446d811192836e26d370a34d1b4](https://bazaar.abuse.ch/sample/d26ab01b293b2d439a20d1dffc02a5c9f2523446d811192836e26d370a34d1b4/)

We skipped to the stage 2 of the Pikabot loader, which employs ****SysWhispers2**** to load the
malware's core. The malware executes the following steps to perform a direct syscall:

1.  Saves the return address;
2.  Resolves the syscall ID from a hash (a behavior related to SysWhispers2);
3.  Retrieves a stub to invoke the syscall based on the host architecture;
4.  Executes the syscall and resumes program execution.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/wrapper_syscall_call.png" caption="<span class=\"figure-number\">Figure 1: </span>Function used to made the direct syscall" >}}

Here are examples of direct syscalls made by the malware.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/syscall_stub.png" caption="<span class=\"figure-number\">Figure 2: </span>Example of SW2Syscall stubs" >}}

To operate SysWhispers2, it is necessary to populate the `_SW2_SYSCALL_LIST` structure,
which is an array containing correspondences between hashes and `ntdll.dll` addresses.
According to the file `base.h`
{{% sidenote %}}
[jthuraisamy/SysWhispers2/blob/main/data/base.h](https://github.com/jthuraisamy/SysWhispers2/blob/main/data/base.h)
{{% /sidenote %}} the two structures are:

```c++
struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 1:</span>
  SysWhispers2 syscall entry
</div>

The `Hash` field contains a hash value corresponding to a particular syscall,
and the `Address` field contains the address of the corresponding function in `ntdll.dll`.

```c++
struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 2:</span>
  SysWhispers2 syscall list
</div>

The malware stores a pointer to the syscall list as a ****global**** variable,
which is convenient when we later retrieve the populated data with the debugger.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/global_syscall_list.png" caption="<span class=\"figure-number\">Figure 3: </span>Reference of the \_SW2_SYSCALL_LIST structure" >}}

According to the [source code](https://github.com/jthuraisamy/SysWhispers2/blob/main/data/base.c#L128-L141)
{{% sidenote %}}
See function `SW2_GetSyscallNumber` line 131.
{{% /sidenote %}} the function used to get the address in ntdll from hash
ensure that `_SW2_SYSCALL_LIST` structure is populated.

The most "challenging" task is now to identify a call to `SW2_GetSyscallNumber`
and set a breakpoint after the `SW2_PopulateSyscallList` function, at which point a dump
of the list can be made.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/xdb_hex_view_syscall_list.png" caption="<span class=\"figure-number\">Figure 4: </span>Hex memory view of the \_SW2_SYSCALL_LIST structure populated" >}}

Here is a clearest visualization of the memory using [ImHex](https://github.com/WerWolv/ImHex/).

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/imhex_syscall_list.png" caption="<span class=\"figure-number\">Figure 5: </span>Visualization of the \_SW2_SYSCALL_LIST structure populated" >}}


## Mapping Hashes to Syscalls {#mapping-hashes-to-syscalls}

First, the hashes (_SW2_) must be listed, and then the hash must be resolved to obtain the syscall number.

The following IDA script lists the hashes by retrieving the first (single one) function argument:

```python
s2w_direct_call_addr = 0x04111000

for x in XrefsTo(s2w_direct_call_addr):
    syscall_hash = get_wide_dword(x.frm - 0x4) # First args of the function
    print(f"call to SW2 at:0x{x.frm:x} hash:0x{syscall_hash:x}")
```

Which gives the following hashes: `0x312294161`, `0x228075779`, `0x2553518241`,
`0x3309424832`, `0x1605204094`, `0x2236128452`, `0x1881308343`, `0x3327455464`,
`0x3319017158`, `0x2249560824`, `0x397169428`, `0x4066245879`, `0x2629212700`.

Subsequently, the `_SW2_SYSCALL_LIST` structure was parsed to obtain the address
corresponding to each of the aforementioned hashes.

```python
import struct

with open("syscall_entries.dmp", "rb") as f:
    # offset 0x8 is used to remove the DWORD Count of the struct _SW2_SYSCALL_LIST
    SW2_syscallList_raw = f.read()[0x8:]

NTDLL_BASE_ADDRESS = 0x77DA0000 # specifics for each sample
SW2_Entrie = namedtuple("SW2_Entrie", ["hash", "address"])
SW2_syscallList: List = []

for hash, addr_offset in struct.iter_unpack("<Li", SW2_syscallList_raw):
    print(f"0x{hash:x} 0x{addr_offset + NTDLL_BASE_ADDRESS:x}")
    SW2_syscallList.append(SW2_Entrie(hash, addr_offset + NTDLL_BASE_ADDRESS))
```

Next, take a snapshot of ntdll (_to avoid rebasing the DLL base address_)
to list the export functions of `ntdll.dll` and their corresponding addresses.

The subsequent step involves taking a snapshot of `ntdll.dll` to obtain a list
of its export functions along with their corresponding address.
_This approach eliminates the need to rebase the DLL base address._

```python
import pefile

def get_section(pe: pefile.PE, section_name: str) -> pefile.SectionStructure:
    """return section by name, if not found raise KeyError exception."""
    for section in filter(
        lambda x: x.Name.startswith(section_name.encode()), pe.sections
    ):
        return section
    raise KeyError(f"{section_name} not found")

PE_FILE = "ntdll.dll"
pe = pefile.PE(PE_FILE)

text = get_section(pe, ".text")
image_base = pe.OPTIONAL_HEADER.ImageBase
section_rva = text.VirtualAddress

mapping_syscall_id_fn = []
# Build a corresponding address and ntdll function name
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    mapping_syscall_id_fn.append((pe.OPTIONAL_HEADER.ImageBase + exp.address, exp.name))
```

Finally, ****map**** the addresses populated in the `_SW2_SYSCALL_ENTRIES` structure
with the corresponding addresses exported from `ntdll.dll` to obtain their export names.

```python
# hashes obtained in IDA
hashes = [
    0x129D3B11,
    0xD982903,
    0x983398A1,
    0xC541D0C0,
    0x5FAD787E,
    0x85489CC4,
    0x70227CB7,
    0xC654F0E8,
    0xC5D42EC6,
    0x861592F8,
    0x17AC5314,
    0xF25DFCF7,
    0x9CB69A1C,
]

def find_syscall_by_hash(hash) -> Optional[SW2_Entrie]:
    for syscall in SW2_syscallList:
        if syscall.hash == hash:
            return syscall

for addr, name in mapping_syscall_id_fn:
    for syscall in map(find_syscall_by_hash, hashes):
        if addr == syscall.address:
            print(f"0x{syscall.hash:x} <-> {name.decode()}")
            break
```

Output for this sample of Pikabot is:

```txt
0xc5d42ec6 <-> NtAllocateVirtualMemory
0x129d3b11 <-> NtClose
0x85489cc4 <-> NtCreateUserProcess
0x70227cb7 <-> NtFreeVirtualMemory
0x17ac5314 <-> NtGetContextThread
0x5fad787e <-> NtOpenProcess
0xc541d0c0 <-> NtQueryInformationProcess
0x983398a1 <-> NtQuerySystemInformation
0xc654f0e8 <-> NtReadVirtualMemory
0x9cb69a1c <-> NtResumeThread
0xf25dfcf7 <-> NtSetContextThread
0xd982903 <-> NtSystemDebugControl
0x861592f8 <-> NtWriteVirtualMemory
0xc5d42ec6 <-> ZwAllocateVirtualMemory
0x129d3b11 <-> ZwClose
0x85489cc4 <-> ZwCreateUserProcess
0x70227cb7 <-> ZwFreeVirtualMemory
0x17ac5314 <-> ZwGetContextThread
0x5fad787e <-> ZwOpenProcess
0xc541d0c0 <-> ZwQueryInformationProcess
0x983398a1 <-> ZwQuerySystemInformation
0xc654f0e8 <-> ZwReadVirtualMemory
0x9cb69a1c <-> ZwResumeThread
0xf25dfcf7 <-> ZwSetContextThread
0xd982903 <-> ZwSystemDebugControl
0x861592f8 <-> ZwWriteVirtualMemory
```

The full script is available on this [gist](https://gist.github.com/lbpierre/c9c39de0c32bb96a5e12556f75744d42), along with the _S2W_SyscallList.dmp_
file in hexadecimal format. To use the dump, replace lines 32 to 34 with the following:

```python
import binascii
with open("SW2_SyscallList_hex.dmp", "r") as f:
    # offset 0x8 is used to remove the DWORD Count of the struct _SW2_SYSCALL_LIST
    SW2_syscallList_raw = binascii.unhexlify(f.read())[0x8:]
```


## Resources {#resources}

-   <https://github.com/jthuraisamy/SysWhispers2>
-   <https://twitter.com/vmray/status/1760647508038947080>
-   <https://gist.github.com/lbpierre/c9c39de0c32bb96a5e12556f75744d42>
-   <https://joshfinley.github.io/posts/2020-04-17-sycall-dumping/>
