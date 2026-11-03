+++
title = "ACECryptor unpacking walktrough 📦"
author = ["pbo"]
description = """
  **ACECryptor** is a crypter utilized by numerous cybercriminals. The service has been observed dropping various
  types of malicious software, including Remote Access Trojans (RATs), stealers, and loaders
  such as RedLine, SmokeLoader, and GCleaner, among others. This article provides a hands-on,
  step-by-step walkthrough of the process to unpack ACECryptor.
  """
publishDate = 2024-11-04T00:00:00+01:00
tags = ["crypter"]
categories = ["RE"]
draft = false
+++

{{< figure src="/ox-hugo/acecrypter_head.jpg" >}}

The crypter is composed of three stages, for this analysis IDA and xdbg will be used.

The examined sample is:
[SHA-256: b0968bdb6a175a38ec05efcf605ed61411d16e63e692bc0d7b8f1f747ce3b2e5](https://bazaar.abuse.ch/sample/b0968bdb6a175a38ec05efcf605ed61411d16e63e692bc0d7b8f1f747ce3b2e5/)

The IDB for the three stages are available below. Feel free to used it :).

{{< download "IDB/ACECryptor/stage-0.bin.i64" "IDB/ACECryptor/stage-1.i64" "IDB/ACECryptor/stage-2.i64" >}}

_NB: This packed sample deliver GCleaner (a loader working as a Pay Per Install)._

The extracted C2 server of GCleaner set in this sample are:

-   `185.172.128.]90`
-   `5.42.65.]115`


## Stage 0 - Too much noice {#stage-0-too-much-noice}

The first stage of this packer employs a concealment technique that involves multiple
legitimate system calls. These calls differ between each build of the crypter.

The primary responsibility of this initial stage is to load the subsequent stage into memory, decrypt it, and execute it.
This approach is typical for a packer and is not particularly surprising.

Using the [IDAtropy](https://github.com/danigargu/IDAtropy) plugin, we can easily identify an unsual entropy value in the `.text` section.
The Shannon entropy is a mathematical function that corresponds to the amount of variation in information.
Meaning, the more varied the data, the higher entropy is; and the more identical the information is, the lower it entropy is.

<a id="org8728f34"></a>

![](/ox-hugo/entropy.png)
In the above capture of the entropy of ACECryptor sample, an unusual entropy stand out in the `.text` section.
This section should contains only executable code (that what .text is purposed). By taking a look at this
chunk of data in IDA, the tool cannot decompiled it.

_Keep in a note the address of this blob of data, we will validate that this data are in fact the obfuscated stage 1._

The unpacking process for stage 0 can be summarized as follows:

1.  Search for instances of VirtualProtect usage;
2.  Identify the page region where permissions were modified to include execution rights;
3.  Locate the point in the code where this buffer is invoked;
4.  Use a debugger to reach the call to that buffer and create a memory dump.

To better understand the packer's objective, here's a quick method for delving into the second stage:
First, search for cross-references (`XRefs`) to `VirtualProtect` (Figure 2).

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/searchVirtualProtect.png" caption="<span class=\"figure-number\">Figure 2: </span>Search VirtualProtect" >}}

Then decompile the function using `VirtualProtect` from `Kernel32.dll`, whose signature is:

{{% sidenote %}}
According to MSDN document [MSDN VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{% /sidenote %}}

```c++
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```

As noticed in the function that modify the page permission to `PAGE_EXECUTE_READWRITE`, which
is a noteworthy for a next stage execution. Moreover, the last reference is a call to that address,
which is a good indicator for a potential next stage execution.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/xref-to-lpaddress.png" caption="<span class=\"figure-number\">Figure 3: </span>XRef to lpAddress" >}}

Last step to unpack the stage 1 is to add a breakpoint on that specific call
in `sub_401221` at line `245` (`call lpAddress`). And run until it is reached!

In xdbg, use the "follow in dump" the address of the call here: `ds:44588C` and go to memory
map tab for this specifics address (_btw: save the address, it will be useful for
the analysis of the next stage: entrypoint_).

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/follow_memory_map.png" caption="<span class=\"figure-number\">Figure 4: </span>Memory map of the address of the stage 1" >}}

Then create a memory dump of this page:

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/create_memory_dump.png" caption="<span class=\"figure-number\">Figure 5: </span>Create memory dump of the page" >}}


## Stage 1 - Shellcode {#stage-1-shellcode}

In this step of the analysis, we are digging in the previously dumped memory.
A memory dump (in this scenario) induce to a file that is not a valid PE, which
mean no section, no import, etc... To deal with it, it is highly required to
import in IDA the necessary libraries (Open the `Type Libraries` view in IDA
from the toolbar `View` &gt; `Open subviews` &gt; `Type libraries` or `Shift+F11`).

And import the _MS Windows Native API (NDK)_ type library.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/type_libraries.png" caption="<span class=\"figure-number\">Figure 6: </span>Import type libraries" >}}

Because the entrypoint of this stage was saved from the previous analysed stage,
a quick look at the two called functions show a tiny stage. Let walk through each of
them.

The first function is used to resolved and dynamically import functions from `Kernel32.dll`
and to instanciate a structure. Creating the structure will help for the second function
understanding.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/getAPI_raw.png" caption="<span class=\"figure-number\">Figure 7: </span>First function of stage 1" >}}

Before digging in the analysis, a quick check to stack in memory.
It appears that the function only takes one argument and declares bunch of local variables.
Before creating a structure for this, let take a look at the function `sub_673AC3`.

The function loop over a data structure in NtCurrentPeb (_Process Envionment Block_),
starting typing the different local variables using the MSDN documentation

{{% sidenote %}}
MSDN Winternl PEB: <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb>
{{% /sidenote %}}

and the igors-tip-of-the-week, plus looking at the IDA view `Local Types`

{{% sidenote %}}
Hex-rays igors tips: type libraries <https://hex-rays.com/blog/igors-tip-of-the-week-60-type-libraries/>
{{% /sidenote %}}

help to understand the purpose of that function, it goes to

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/dynamic_api_import_raw.png" caption="<span class=\"figure-number\">Figure 8: </span>Raw function `sub_673AC3`" >}}

The for loop travel the PE header starting from the `PEB` to `PEB_LDR_DATA` to go to the
`DataDirectory` and loop over the function in the required _DLL_.

_Of note: because we already import the NtAPI, IDA detects some structures: TEB, Flink._

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/dynamic_api_import_typed.png" caption="<span class=\"figure-number\">Figure 9: </span>Typed function dynamic_api_import" >}}

At the first look, I cannot identify the hashing algorithm however with the IDA plugin
[Hashdb](https://github.com/OALabs/hashdb-ida) give a direct answer to identify the algorithm. (Right click on the first constant and
select the `HashDB Hunt Algorithm` option which answer `Kernel32`, then right click on the second
function argument with the option `HashDB Lookup`, the first function call is for `LoadLibrary`
and the second one for `GetProcAddress`.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/hashdb_steps.png" caption="<span class=\"figure-number\">Figure 10: </span>identification of the hashing algorithm with hashdb" >}}

Finally, a decent structure can be created for the variable `arg0`.

```c
struct MainStruct // sizeof=0x34
{
  _DWORD start;
  Shellcode2Metadata *shellcode_header;
  _DWORD ptr_shellcode_next_stage_offset;
  _DWORD seed;
  int (__stdcall *LoadLibraryA)(_WORD *);
  int (__stdcall *GetProcAddress)(int, _WORD *);
  int GlobalAlloc;
  int (*GetLastError)(void);
  void (__cdecl *Sleep)(int);
  int (__stdcall *VirtualAlloc)(_DWORD, _DWORD, int, int);
  int (__cdecl *CreateToolhelp32Snapshot)(int, _DWORD);
  int (__cdecl *Module32First)(int, int *);
  int (__cdecl *CloseHandle)(int);
};
```

_NB: the stage structure will be detailed later in this section._

So the structure is used to register pointers to the next stage obfuscated and also
to the different functions from `Kernel32.dll` that the program will used later on.

To type correctly the variables that are functions, open a legitimate program in IDA
that import Kernel32.dll functions and copy/past their type signature in the structure
definition.

Now propagate the type in the caller function and the last function called by the main.

Once we propagate the structure in the stage 1 shellcode, we can search for the blob modification.
Using CAPA we have two interesting hits:

-   _Encode data using XOR_;
-   _Decompress data using LZ0_.

So we can retype the function that matches the LZ0 CAPA rule, and take a look at the
XOR function. By searching for the different constants of the algorithm, it appears to be
the LCG (Linea Congruential generator) implementation of Microsoft Visaul C/C++.

```C
// Microsoft RAND
// https://en.wikipedia.org/wiki/Linear_congruential_generator
int __cdecl msvc_lcg(MainStruct *a1)
{
  unsigned int v1; // eax

  v1 = 0x343FD * a1->seed + 0x269EC3;
  a1->seed = v1;
  return HIWORD(v1) & 0x7FFF;
}
```

At this stage of execution, the shellcode needs to unXOR and decompress the next stage.
The location of these data is stored in a structure called `Shellcode2Metadata`,
which is a substructure of what we named `MainStruct`.

```C
struct Shellcode2Metadata // sizeof=0xD
{
  _DWORD size;
  _DWORD seed;
  _BYTE flag;
  _DWORD decompressSize;
};
```

Finally, after unxoring the data and decompressing it with the LZ0 algorithm,
the shellcode uses a jump instruction to proceed to the next stage of execution.

```C { linenos=true, linenostart=1, hl_lines=["17"] }
void __cdecl execute_decompressed_lzo_stage(MainStruct *malware)
{
  int v1; // [esp+0h] [ebp-Ch] BYREF
  unsigned __int8 *buff; // [esp+4h] [ebp-8h]
  int ptr_blob_offset; // [esp+8h] [ebp-4h]

  ptr_blob_offset = malware->ptr_shellcode_next_stage_offset;
  init_blob_headers(malware, ptr_blob_offset, malware->shellcode_header->size, malware->shellcode_header->seed);
  if ( malware->shellcode_header->flag )
  {
    buff = malware->VirtualAlloc(0, malware->shellcode_header->decompressSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    v1 = 0;
    lzo_decrompress(ptr_blob_offset, malware->shellcode_header->size, buff, &v1);
    ptr_blob_offset = buff;
    malware->shellcode_header->size = v1;
  }
  __asm { jmp     [ebp+ptr_blob_offset] }
}
```

To obtain a clean version of the next stage, the same task used in the previous stage can be replicated.
Therefore, before the `jmp [ebp+ptr_blob_offset]` instruction, we save the address where the program jumps
and then dump that memory using the `Memory map` tab in xdbg.


## Stage 2 - Next stage execution {#stage-2-next-stage-execution}

This last stage is also a shellcode. It contains 3 types of data:

1.  The shellcode itself;
2.  An obfuscated structure;
3.  An LZ0 compressed final payload.

As in the previous stage, the shellcode works with a central structure, which this time is more abundant.
The structure contains pointers to loaded functions as well as information about the final payload such as
the number of sections, the address of the entry point, etc.

The challenge in this stage is that the structure uses negative offsets to access its members,
unlike other stages that use the more conventional method.
In IDA, we cannot use the right-click "create new structure" feature from a variable.
This feature is very helpful for building a structure by roughly computing the number of members and their types.
But this does not work for negative offset structure...

In this situation, we should scroll through the function and identify the highest offset (in this case, **254**).
Based on this value, we can create a raw structure with (254 / 8) `_DWORD` members:

```C
struct stage3 {
  _DWORD dword_0;
  _DWORD dword_4;
  _DWORD dword_8;
  _DWORD dword_12;
  _DWORD dword_16;
  _DWORD dword_20;
  _DWORD dword_24;
  _DWORD dword_28;
  _DWORD dword_32;
  _DWORD dword_36;
  _DWORD dword_40;
  _DWORD dword_44;
  _DWORD dword_48;
  _DWORD dword_52;
  _DWORD dword_56;
  _DWORD count_copied_data;
  _DWORD ptr_dest_no_compression;
  _DWORD TerminateProcess;
  LPVOID lpAddress;
  _DWORD BaseOfCode;
  SIZE_T mem_size;
  _DWORD raw_addr_next_stage;
  _DWORD dword_88;
  _DWORD msvcr100_handle;
  _DWORD copy_lpAddress;
  _DWORD dword_100;
  char buff_string[16] __strlit(C,"UTF-8");
  _DWORD dword_120;
  _DWORD dword_124;
  _DWORD dword_128;
  _DWORD dword_132;
  _DWORD copy_nt_header;
  _DWORD dword_140;
  int (__cdecl *GetProcAddress)(HANDLE, char *);
  _DWORD VirtualFree;
  IMAGE_OPTIONAL_HEADER *optionalHeader;
  IMAGE_NT_HEADERS *nt_headers_;
  _DWORD dword_160;
  void (__stdcall *SetErrorMode)(int);
  _DWORD dword_168;
  int (__cdecl *VirtualAlloc)(_DWORD, _DWORD, int, int);
  void (__stdcall *GetVersionExA)(int *);
  _DWORD NEXT_STAGE_ENTRYPOINT;
  _DWORD dword_184;
  HANDLE handle_kernel32;
  _DWORD copy_ptr_allocated_mem;
  _DWORD dword_196;
  void (__cdecl *atexit)(_DWORD);
  _DWORD LoadLibrary;
  int (__cdecl *VirtualProtect)(LPVOID, _DWORD, MACRO_PAGE, _DWORD *);
  _DWORD ptr_lz0_decompress;
  _DWORD lpflOldProtect;
  IMAGE_NT_HEADERS *nt_headers;
  _DWORD TerminateProcess_;
  int (__stdcall *ExitProcess)(_DWORD);
  LPVOID ptr_allocated_mem;
  _DWORD result_virtualProtect;
  _DWORD dword_240;
  _DWORD dword_244;
  _DWORD dword_248;
};
```

We assume that some of the `_DWORD` elements can be merged with others to create arrays,
or they may be split into strings, boolean, or other types.

However, to retype the variable with our newly created structure, we need to make IDA understand
the negative structure offset. This can be done using [`__shifted` pointer](https://hex-rays.com/blog/igors-tip-of-the-week-54-shifted-pointers).

{{% sidenote %}}
Shifted pointers is another custom extension to the C syntax.
They are used by IDA and decompiler to represent a pointer to an object with some offset or adjustment
(positive or negative). Let’s see how they work and several situations where they can be useful.
{{% /sidenote %}}

In our case we retype the variable with this code `int *__shifted(stage2,0xF8) stage3`


### Anti Sandbox {#anti-sandbox}

ACECryptor implemented an anti sandbox feature against cuckoo according [ahnlab article](https://asec.ahnlab.com/en/17147/).

```C
int __cdecl sandbox_bypass(int (__stdcall *SetErrorMode)(_DWORD),
			   int (__stdcall *TerminateProcess)(_DWORD))
  {
    int result;

    SetErrorMode(0x400);
    result = SetErrorMode(0);
    if (result != 0x400)
      return TerminateProcess(0);
    return result;
  }
```

The function `SetErrorMode` is used to set an error mode to the current process and return its previous mode.
However, in Cuckoo sandbox The SetErrorMode is set to `SEM_FAILCRITICALERRORS|SEM_NOALIGNMENTFAULTEXCEPT` (0x8007),
according to Anlab analysis, the problem resids in the `SEM_NOALIGNMENTFAULTEXCEPT`, when an attempt to reset the error mode
previously set to `SEM_NOALIGNMENTFAULTEXCEPT` is ignored and 0x404 is set instead of 0x400.


### Trigger the execution {#trigger-the-execution}

After remaping the sections of the next stage and rebasing the next stage in the memory of the current process, the packer
dynamically load the `atexit` function from `msvcr100.dll`.

&gt; Processes the specified function at exit.

```C
int atexit(
   void (__cdecl *func )( void )
);
```

If the `atexit` function is successfuly loaded, the packer provides as it first argument the address the entry point of
the final payload.


## Other great analysis {#other-great-analysis}

-   [ESET: Shedding light on AceCryptor and its operation](https://www.welivesecurity.com/2023/05/25/shedding-light-acecryptor-operation/)
-   [Anatomy of a simple and popular packer](https://fumik0.com/2021/04/24/anatomy-of-a-simple-and-popular-packer/)


## Tools {#tools}

-   [IDA](https://hex-rays.com/ida-free)
-   [xdbg](https://x64dbg.com/)
-   [IDA plugin: HashDB](https://github.com/OALabs/hashdb-ida)
-   [IDA plugin: IDAtropy](https://github.com/danigargu/IDAtropy)
-   [ret-sync: IDA xdbg synchronize](https://github.com/bootleg/ret-sync)
