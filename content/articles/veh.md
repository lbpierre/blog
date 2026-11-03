+++
title = "It's Called a VEH-tor ↗️"
author = ["pbo"]
description = """
  Reading through an old GuLoader sample in the decompiler, following the exception handler,
  trying to understand what it was actually doing, made it clear that my knowledge of Windows exception
  handling was not structured enough to tackle this kind of obfuscation confidently on another family.
  I knew the broad strokes, enough to recognize the technique, but not enough to follow it precisely or explain it to someone else.

  This is a personal writeup, an attempt to connect the dots properly rather than carry around
  a vague understanding that works until it does not. It covers the theoretical foundation of SEH and VEH,
  and how the internal structures look in a debugger and a disassembler.

  A lot of what ended up here was things I already had a rough idea of but had never verified properly.
  Documenting what I learned about exceptions allowed me to refine my grasp of the subject.
  Nothing revolutionary, just notes from someone who went back to the source and want to avoid future headaches.
  """
publishDate = 2026-05-20T00:00:00+02:00
tags = ["VEH"]
categories = ["Windows"]
draft = false
+++

{{< figure src="/ox-hugo/veh-header.png" >}}

What brought me back to this subject is the analysis of _GuLoader_ that uses VEH (see _SonicWall_, _Zscaler_ and _Unit42_ articles for more deeper
malware analysis).

This article is my attempt to write down what I learned properly, starting from the actual concepts rather than jumping straight to the tricks.
SEH and VEH are legitimate, well-designed mechanisms. Understanding how they are supposed to work is what makes the abuse readable.

The first part covers the concepts and the API, how the OS dispatches exceptions, how SEH and VEH handlers are registered,
and what developers normally use them for. The second part gets into the malware side: how exception handling gets repurposed to hide execution flow.
To wrap things up, I decided to test some detection logic. I hacked together a basic implementation in C;
while my C skills are definitely still a 'work in progress,' the code serves its purpose in demonstrating how to catch this behavior.

If you already know Windows internals well, the first two parts will mostly be a refresher.
If you are coming at this from the analysis side without much background in the underlying mechanism,
I hope starting from the foundation makes the second part easier to follow.

Before going further, here are some interesting external resources related to VEH related to malware domain:

-   [SonicWall - GuLoader Demystified: Unraveling its Vectored Exception Handler Approach](https://www.sonicwall.com/blog/guloader-demystified-unraveling-its-vectored-exception-handler-approach)
-   [Zscaler - Technical Analysis of GuLoader Obfuscation Techniques](https://www.zscaler.com/blogs/security-research/technical-analysis-guloader-obfuscation-techniques)
-   [CrowdStrike - Unmasking the Dark Art of Vectored Exception Handling: Bypassing XDR and EDR in the Evolving](https://www.slideshare.net/slideshow/unmasking-the-dark-art-of-vectored-exception-handling-bypassing-xdr-and-edr-in-the-evolving-cyber-threat-landscape/263989842?utm_source=clipboard_share_button&utm_campaign=slideshare_make_sharing_viral_v2&utm_variation=control&utm_medium=share)
-   [IBM - You just got vectored – using vectored exception handlers (veh) for defense evasion and process injection](https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection)
-   [Unit42 - Tackling Anti-Analysis Techniques of GuLoader and RedLine Stealer](https://unit42.paloaltonetworks.com/malware-configuration-extraction-techniques-guloader-redline-stealer/)


## SEH, VEH and a Word on C++ Exceptions {#seh-veh-and-a-word-on-c-plus-plus-exceptions}

-   What an exception is at the OS level and how Windows dispatches it (brief, just enough to understand the rest)
-   SEH: the stack-based chain, per-thread, per-frame, how the compiler owns it for you
-   VEH: process-wide, heap-resident, fires before SEH, the two-function API
-   The difference with C++ exceptions: try/catch is a language abstraction built on top of SEH, not the same thing, why that distinction matters when you are reading disassembly

The three terms (SEH, VEH and Exception) often get conflated, especially in malware analysis writeups (and especially by myself).

****What is an exception at the OS level?****
When something goes wrong during execution, whether it is a divide by zero, an access to an unmapped memory page,
or an explicit int 3 instruction, the CPU raises an exception.
Control transfers to the kernel, which builds an `EXCEPTION_RECORD` describing what happened and a `CONTEXT` structure capturing the full register state at the time of the fault.
Windows then tries to find something in user space that knows how to handle it. That search is what SEH and VEH are about.


### Structured Exception Handling {#structured-exception-handling}


#### SEH in x86 {#seh-in-x86}

`SEH` is the older of the two mechanisms. The idea is straightforward: each function that wants to handle exceptions registers a handler on the stack,
forming a linked list rooted at `fs:[0]` on x86. When an exception occurs, Windows walks that list from the top, giving each registered handler a chance to deal with it.
If a handler claims the exception, execution resumes. If nothing handles it, the process crashes.

From a developer perspective, SEH is what sits behind `__try` / `__except` / `__finally` in C.
The compiler does most of the work, emitting the registration and cleanup code around the blocks.
On x64 the implementation is different: instead of a runtime chain on the stack, the compiler emits a static table in the `.pdata` section that the OS uses to _unwind_.
The surface API looks the same but the mechanics underneath are not. That is still unclear to me...

```c
#include <windows.h>
#include <stdio.h>

int main(void)
{
    __try
    {
        // intentionally trigger an access violation
        int *ptr = NULL;
        *ptr = 42;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        printf("SEH caught the exception\n");
    }

    return 0;
}
```

The C file is compiled with this command line: `cl.exe /Zi /O1 /GS- test-seh.c`. See below the difference between x86 that uses the `fs:[0]` and
the x64 version that has the logic in the `.pdata` section.

{{< figure src="/ox-hugo/seh-32bit-prologue.png" caption="<span class=\"figure-number\">Figure 1: </span>Main function in 32bit environment" >}}

In the 32bits architecture, the exception is "registered" by the first instruction of the `main` function (see the screenshot below). Where the
compiler add the following instructions:

```asm
push 8
push offset struc_478178
call j__SEH_prolog
xor eax, eax
```

What `__SEH_prolog` does internally is:

1.  Saves the current fs:[0] value (the previous handler in the chain)
2.  Builds an `EXCEPTION_REGISTRATION_RECORD` on the stack
3.  Points `fs:[0]` to it, inserting this function into the SEH chain
4.  Sets up the `ms_exc` local variable, which is the structure MSVC uses to track the current state of the exception handling frame

The structure `struc_478178` is:

{{< figure src="/ox-hugo/seh-32bit-structure.png" caption="<span class=\"figure-number\">Figure 2: </span>struc_478178 content" >}}

<a id="code-snippet--scopetable-entry"></a>
```C
typedef struct _SCOPETABLE_ENTRY
{
    DWORD EnclosingLevel;    // index of the enclosing scope, -1 if none
    PVOID FilterFunc;        // pointer to the filter expression
    PVOID HandlerFunc;       // pointer to the __except or __finally block
} SCOPETABLE_ENTRY;
```

Looking at the entry `<0FFFFFFFFh, offset $LN5, offset catch_except_ptr_42>:`

-   ****EnclosingLevel = 0xFFFFFFFF**** this is `-1`, meaning this `__try` block has no enclosing `__try` block, it is the outermost one in the function
-   ****FilterFunc = $LN5**** this is the compiled form of the filter expression, the code that evaluates `EXCEPTION_EXECUTE_HANDLER` or whatever condition I would put in the C code `__except(...)`
-   ****HandlerFunc = catch_except_ptr_42**** this is the actual `__except` block that runs if the filter says to handle the exception


#### SEH in x64 {#seh-in-x64}

Regarding 64 bits architecture, the following main function is:

{{< figure src="/ox-hugo/seh-64bit-prologue.png" caption="<span class=\"figure-number\">Figure 3: </span>x64 decompiled main function" >}}

Here, as a first observation there is no `fs:[0]`, no `__SEH_prolog` call. There is no explicit registration at function scope level (from my understanding).

The handler is registered statically through the `.pdata` (I read that it also can be store in `.rdata` section too) structures.

The `.pdata` store the `RUNTIME_FUNCTION` structure that is define by three terms: `BeginAddress`, `EndAddress` and `UnwindData` (the last one is
a pointer to the `UNWIND_INFO` structure).

When the access violation fires at `mov dword ptr [rax], 2Ah` (writing 42 to a null pointer), the OS:

1.  Catches the fault in the kernel
2.  Comes back to user mode and calls `RtlDispatchException`
3.  Takes the faulting `RIP`, does a binary search in `.pdata` to find the matching `RUNTIME_FUNCTION` (the structure that validate this condition: `BeginAddress <= FaultyRIP < EndAddress`)
4.  Follows it to the `UNWIND_INFO`, sees `__C_specific_handler` as the registered handler
5.  Calls `__C_specific_handler` which walks the `C_SCOPE_TABLE`, finds the scope covering the faulting address, evaluates the filter `main$filt$0`
6.  Filter returns `EXCEPTION_EXECUTE_HANDLER`, execution jumps to `$LN6` which is the `__except` block calling printf

The "workflow" of the exception is defined as below:

```nil
Exception Triggers
  -> OS looks up RIP in .pdata
    -> Locates RUNTIME_FUNCTION (here stru_140092378)
      -> Follows pointer to UNWIND_INFO
        -> Calls __C_specific_handler
          -> Searches C_SCOPE_TABLE
            -> Jumps to $LN6 (my __except block)
```

{{< figure src="/ox-hugo/seh_pdata_runtime_function.png" caption="<span class=\"figure-number\">Figure 4: </span>.pdata section that hold the RUNTIME_FUNCTION for my exception in the main function" >}}

IDA labeled it ****ExceptionDir**** because it is the first entry in the exception directory. The three fields map directly to the main function:

-   `rva main` is the start address of the function, `0x140007250`
-   `rva byte_14000727E` is the end address of the main function
-   `rva stru_140092378` is the pointer to the ****`UNWIND_INFO`**** structure, the one that contains `__C_specific_handler` and the `C_SCOPE_TABLE`

The structure is as follow:

{{< figure src="/ox-hugo/seh_64bit_runtime_struct.png" caption="<span class=\"figure-number\">Figure 5: </span>IDA view of the structure stru_140092378" >}}

`stru_140092378` is the `UNWIND_INFO` structure that the `.pdata` entry for `main` points to. It is made of three parts:

1.  The `UNWIND_INFO_HDR` is the header. It describes the prologue of the function.
2.  The `UNWIND_CODE` is the actual unwinding instruction.
3.  After the unwind codes, because `UNW_FLAG_EHANDLER` was set, comes the exception handler pointer pointing to [`__C_specific_handler`](https://learn.microsoft.com/en-us/windows/win32/devnotes/--c-specific-handler2),
    followed by the `C_SCOPE_TABLE` (which a bit different from the structure for [x86](#code-snippet--scopetable-entry)).
     That table is where the actual exception handling logic is described: which address range is covered by the `__try` block,
     which function to call as the filter, and where to redirect execution if the filter decides to handle the exception.

In x64 the `C_SCOPE_TABLE_ENTRY` structrure is defined as:

```c
struct _C_SCOPE_TABLE_ENTRY {
    uint32_t BeginAddress;    // RVA of the start of the __try block
    uint32_t EndAddress;      // RVA of the end of the __try block
    uint32_t HandlerAddress;  // RVA of the filter or __finally handler
    uint32_t JumpTarget;
} C_SCOPE_TABLE_ENTRY
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 1:</span>
  C_SCOPE_TABLE defintion
</div>

One structure, three responsibilities: unwind the stack, find the handler, map the guarded region.

So the definition of the structure is:

```C
typedef struct _UNWIND_INFO
{
    BYTE VersionAndFlags;       // UNWIND_INFO_HDR - version + flags (UNW_FLAG_EHANDLER etc.)
    BYTE SizeOfProlog;          // UNWIND_INFO_HDR - prologue size in bytes
    BYTE CountOfCodes;          // UNWIND_INFO_HDR - number of UNWIND_CODE slots
    BYTE FrameRegisterAndOffset;// UNWIND_INFO_HDR - frame register + offset

    UNWIND_CODE UnwindCodes[];  // variable length array, CountOfCodes entries
                                // padded to 4 byte alignment

    // only present if flags contain UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER
    DWORD ExceptionHandlerRVA;  // rva j___C_specific_handler

    // handler specific data, depends on which handler is used
    // for __C_specific_handler this is the C_SCOPE_TABLE
    C_SCOPE_TABLE ScopeTable;

} UNWIND_INFO;
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 2:</span>
  _UNWIND_INFO structure
</div>

At the end of the `UNWIND_INFO` (if certain flags like `UNW_FLAG_EHANDLER` are set), there is an extra field
called the `ExceptionHandler`. For C/C++ code compiled with ****MSVC****, this almost always points to `__C_specific_handler`.

_Link to [Microsoft documentation](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#struct-unwind_info)_


### Vectored Exception Handling {#vectored-exception-handling}

`VEH` was introduced in Windows XP and works differently. Instead of being tied to the stack,
VEH handlers are registered at the process level and stored in a list maintained by `ntdll`. The vectored handler list is consulted before `SEH`.
If any `VEH` handler claims the exception, the SEH chain is never walked at all.

The API is simple. A handler is registered with `AddVectoredExceptionHandler`, which takes a flag indicating whether the handler should be first or last in the list,
and a pointer to the handler function. The handler receives an `EXCEPTION_POINTERS` structure giving it access to both the `EXCEPTION_RECORD` and the `CONTEXT`.
It then returns either `EXCEPTION_CONTINUE_EXECUTION` to resume execution, or `EXCEPTION_CONTINUE_SEARCH` to pass to the next handler.

There is also a sibling mechanism called Vectored Continue Handlers, registered with `AddVectoredContinueHandler`, which fires after a handler has already claimed the exception.
I did not exercice this path in the article.

```c
#include <windows.h>
#include <stdio.h>

LONG CALLBACK MyVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        printf("VEH caught an access violation at 0x%p\n",
               ExceptionInfo->ExceptionRecord->ExceptionAddress);

        // move RIP past the faulting instruction (could be wrapped with macro for 32bit with eip)
        ExceptionInfo->ContextRecord->Rip += 2;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void)
{
    PVOID handler = AddVectoredExceptionHandler(1, MyVectoredHandler);

    // intentionally trigger an access violation
    int *ptr = NULL;
    *ptr = 42;

    RemoveVectoredExceptionHandler(handler);
    return 0;
}
```

Here registration is explicit. The first argument to `AddVectoredExceptionHandler` being `1` means this handler goes to the front of the list,
so it fires before any other `VEH` handler and before `SEH`. The handler inspects the exception code, adjusts `RIP` to skip past the faulting instruction,
and returns `EXCEPTION_CONTINUE_EXECUTION` to resume. If the exception is not one it cares about, it returns `EXCEPTION_CONTINUE_SEARCH` to let the next handler in the chain take over.
The key difference to notice: in the `SEH` example the handler is scoped to the `__try` block and the stack frame it lives in.
In the VEH example the handler is active process-wide from the moment it is registered until `RemoveVectoredExceptionHandler` is called, regardless of which function is currently executing.


### C++ Exceptions are not the Same Thing {#c-plus-plus-exceptions-are-not-the-same-thing}

This one trips people up. When you write `try / catch` in C++, you are using the C++ exception model, which is a language-level abstraction.
Under the hood on Windows, the compiler implements it on top of SEH, using a special SEH filter to match C++ exception types.
But they are not the same layer. A C++ catch block is not an SEH handler, and it is definitely not a VEH handler.

The reason this distinction matters in practice is that when you are reversing a sample and you see `AddVectoredExceptionHandler` being called, you are not looking at a compiler artifact.
There is no language feature that emits that call for you. It is explicit, intentional code, and whoever wrote it made a deliberate
choice to intercept exceptions at the process level before anything else gets a chance to see them.

If you are interested in C++ exceptions, I highly encourage you to read [C++ Unwind Exception Metadata: A Hidden Reverse Engineering Bonanza written by Rolf Rolles](https://www.msreverseengineering.com/blog/2024/8/20/c-unwind-metadata-1).


## How the VEH List is Built and Stored {#how-the-veh-list-is-built-and-stored}

The VEH list is a doubly-linked list maintained per-process in user-mode memory, managed by ntdll.dll. It holds pointers to registered `PVECTORED_EXCEPTION_HANDLER` callbacks.

When `AddVectoredExceptionHandler` is called, it calls a thin wrapper that forwards to `RtlAddVectoredExceptionHandler` in `ntdll.dll`.
That is where the actual work happens, and it is worth understanding what that function does with the handler pointer.

Ntdll maintains two doubly linked lists for exception handling, one for vectored exception handlers and one for vectored continue handlers.
Both lists are anchored by a single global structure that lives inside ntdll's data segment, commonly referred to as `LdrpVectorHandlerList` in debugging sessions.

The structure looks roughly like this:

```c
typedef struct _VECTORED_HANDLER_LIST
{
    SRWLOCK Lock;           // slim reader/writer lock protecting the list
    LIST_ENTRY VEHList;     // head of the vectored exception handler list
    LIST_ENTRY VCHList;     // head of the vectored continue handler list
} VECTORED_HANDLER_LIST;
```

Each registered handler is wrapped in a node that gets allocated on the heap:

```c
typedef struct _VECTORED_EXCEPTION_NODE
{
    LIST_ENTRY ListEntry;         // links to previous and next node
    PVOID EncodedHandler;         // the function pointer, but encoded
    ULONG ReferenceCount;
} VECTORED_EXCEPTION_NODE;
```

The `LIST_ENTRY` is the standard Windows doubly linked list structure, with a `Flink` pointing to the next node and a `Blink` pointing to the previous one.
The list head in `LdrpVectorHandlerList` acts as the sentinel node, so walking from `VEHList.Flink` until you loop back to the head gives you every registered handler in order.

`RtlAddVectoredExceptionHandler` does the following (in order):

1.  Allocates a `VECTORED_EXCEPTION_NODE` on the process heap with `RtlAllocateHeap`
2.  Encodes the function pointer using `RtlEncodePointer` before storing it in `EncodedHandler`
3.  Acquires an exclusive lock on the `SRWLOCK` in `LdrpVectorHandlerList`
4.  Inserts the node either at the front or at the back of the list depending on the first parameter you passed
5.  Releases the lock
6.  Returns the address of the node as the handle you use later to remove it

The first parameter is documented as [ULONG First](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler).
A non-zero value puts the handler at the head of the list, meaning it will be called before any previously registered handler. Zero puts it at the tail.

When an exception occurs, after the kernel-side handling and the transition back to user mode,
ntdll calls `RtlDispatchException`. Before touching SEH, it acquires a shared lock on `LdrpVectorHandlerList` and walks the `VEH` list from head to tail.
For each node it decodes the handler pointer and calls it with the `EXCEPTION_POINTERS` structure.
If a handler returns `EXCEPTION_CONTINUE_EXECUTION`, the walk stops and execution resumes. If it returns `EXCEPTION_CONTINUE_SEARCH`, the walk continues to the next node.
If the entire `VEH` list is exhausted without anyone claiming the exception, the `SEH` chain is walked. If `SEH` also passes, the `VCH` list is walked.
(VCH: Vectored Continue Handlers, where handler are register via `AddVectoredContinueHandler`).

The ordering guarantee is therefore strict: VEH first, in registration order, then SEH, then VCH.


### Practice: Observing it at runtime {#practice-observing-it-at-runtime}

This is a short of note section on how to inspect the exception regarding VEH and its underlaying structure in ****WinDbg****.
For this short exercice, I used the following C code is used:

```c
#include <windows.h>
#include <stdio.h>

LONG CALLBACK FirstHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        printf("FirstHandler: passing to next handler\n");
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG CALLBACK SecondHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        printf("SecondHandler: claiming the exception\n");

        ExceptionInfo->ContextRecord->Eip += 6;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void)
{
    PVOID h1 = AddVectoredExceptionHandler(1, FirstHandler);
    PVOID h2 = AddVectoredExceptionHandler(1, SecondHandler);

    int *ptr = NULL;
    *ptr = 42;

    RemoveVectoredExceptionHandler(h1);
    RemoveVectoredExceptionHandler(h2);

    printf("execution continued after the fault\n");
    return 0;
}
```

_NB: I skip the part where I setup the symbols in windbg._

To watch how: the double linked list work, the following breakpoints are set:

```nil
bp ntdll!RtlpCallVectoredHandlers
bp double_veh!FirstHandler
bp double_veh!SecondHandler
```

Why breaking at `RtlpCallVectoredHandlers`? Reading from the bottom up, this is the full execution path that led to the VEH list walk:

{{< figure src="/ox-hugo/double-veh.png" caption="<span class=\"figure-number\">Figure 6: </span>capture of the stack after reaching the RtlpCallVectoredHandler in ntdll (just after `ACCESS_VIOLATION` occured)" >}}

-   `_RtlUserThreadStart` and `BaseThreadInitThunk` are the standard thread startup boilerplate
-   `__scrt_common_main_seh` is the MSVC CRT startup wrapper that calls main
-   `main+0x30` is my code, specifically line 32 in _double-veh.c_ which is the null pointer write `*ptr = 42`
-   `KiUserExceptionDispatcher` is the first user mode function that ran after the kernel caught the fault, the entry point back from kernel mode
-   `RtlDispatchException+0x67` is where the OS starts looking for a handler
-   `RtlpCallVectoredHandlers` is where the execution is currently -&gt; the function about to walk the process VEH list

The key thing to point out for the article is frames 02, 01 and 00.
That three step sequence from `KiUserExceptionDispatcher` to `RtlDispatchException` to `RtlpCallVectoredHandlers` is the exact dispatch chain.

Let it run with `g` until it hits another breakpoint which should be `SecondHandler`, since it is registered second with parameter ****1****
so the first in the VEH list.

{{< figure src="/ox-hugo/second_handler_called.png" caption="<span class=\"figure-number\">Figure 7: </span>windbg capture of the stack after hitting `SecondHandler` function during the exception management" >}}

Now looking at `dd esp`, the second value `010fec90` is the `EXCEPTION_POINTERS` pointer being passed as the argument to the handler (`SecondHandler`).
Which can follow with: `dt EXCEPTION_POINTERS 010fec90`.

And we obtains:

```nil
double_veh!_EXCEPTION_POINTERS
   +0x000 ExceptionRecord  : 0x010fed74 _EXCEPTION_RECORD
   +0x004 ContextRecord    : 0x010fedc4 _CONTEXT
```

and with `dt _EXCEPTION_RECORD 0x010fed74` to inspect the exception record

{{< figure src="/ox-hugo/exception_code.png" caption="<span class=\"figure-number\">Figure 8: </span>Exception record inspection" >}}

This is what expected to observed the _code_ is `0n-1073741819` which is equivalent to `0xC0000005` (`STATUS_ACCESS_VIOLATION`)

To convert this value from windbg to a hexadecimal representation I used the following Python snippet:

```python
value = -1073741819
print(hex(value & 0xFFFFFFFF))
```

```text
0xc0000005
```


## Using Exceptions as a Control Flow Primitive {#using-exceptions-as-a-control-flow-primitive}

In this section, I decided to put my modest C skills to the test to see if I could trip up the decompiler.

Three source codes are provided as Proof of Concept see them as ladder to tackle the above challenge.

1.  Simple PoC which API hashing.
2.  Introduce inline ASM to produce faulty instruction.
3.  Improve code to trick decompiler to resolv faulty instructions construction.


### VEH combined with API hashing {#veh-combined-with-api-hashing}

The PoC starts by resolving `AddVectoredExceptionHandler` through API hashing rather
than a normal import: the function name is reduced to a single 32-bit ROR13 constant (`0x159B3EA0`),
and a small resolver walks kernel32's export directory at runtime, transparently following the forwarder into _kernelbase.dll_.
No string, no IAT entry, no static cross-reference. Once the address is in hand, the handler is registered with CALL_FIRST priority
so it sees exceptions before anything else in the process, and the program deliberately raises an `int3` to invoke it.
Inside the handler, instead of calling `IsDebuggerPresent`, the code reads `NtGlobalFlag` directly from the `PEB` at offset `0xBC` (x64) or `0x68` (x86)
and tests for the `0x70` heap-debug bit pattern that Windows OR's in whenever a process is launched under a debugger.
I recently came accross this technique which is documented by CheckPoint in there [Anti-Debug: Debug Flags](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-ntglobalflag) documentation.

In the normal case the bits are clear, the handler advances `RIP` past the `int3`,
returns `EXCEPTION_CONTINUE_EXECUTION`, and the program prints its "survived" message and exits cleanly.
Under a debugger the same read returns `0x70`, the process terminates with exit code `0xDEAD`.

```c
#include <windows.h>
#include <stdio.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK    0x10
#define FLG_HEAP_ENABLE_FREE_CHECK    0x20
#define FLG_HEAP_VALIDATE_PARAMETERS  0x40
#define NT_GLOBAL_FLAG_DBG_MASK \
    (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

typedef PVOID (WINAPI *pfnAddVectoredExceptionHandler)(
    ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler);

static ULONG GetNtGlobalFlag(void)
{
#ifdef _WIN64
    PBYTE peb = (PBYTE)__readgsqword(0x60);
    return *(volatile ULONG *)(peb + 0xBC);
#else
    PBYTE peb = (PBYTE)__readfsdword(0x30);
    return *(volatile ULONG *)(peb + 0x68);
#endif
}

static LONG WINAPI MyVectoredHandler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG flag = GetNtGlobalFlag();
    printf("[VEH] hit. NtGlobalFlag = 0x%lx\n", flag);

    if ((flag & NT_GLOBAL_FLAG_DBG_MASK) == NT_GLOBAL_FLAG_DBG_MASK) {
        printf("[VEH] debugger detected via NtGlobalFlag -> bailing.\n");
        ExitProcess(0xDEAD);
    }

    printf("[VEH] clean. Skipping the int3 and resuming.\n");

#ifdef _WIN64
    ep->ContextRecord->Rip += 1;
#else
    ep->ContextRecord->Eip += 1;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

#define HASH_ADDVECTOREDEXCEPTIONHANDLER  0x159B3EA0UL

static DWORD Ror13Hash(const char *s)
{
    DWORD h = 0;
    while (*s) {
        h = (h >> 13) | (h << 19);
        h += (BYTE)*s++;
    }
    return h;
}

static FARPROC ResolveByHash(HMODULE hMod, DWORD target)
{
    PBYTE base = (PBYTE)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)(base + dir.VirtualAddress);
    PDWORD names    = (PDWORD)(base + exp->AddressOfNames);
    PWORD  ordinals = (PWORD) (base + exp->AddressOfNameOrdinals);
    PDWORD funcs    = (PDWORD)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (Ror13Hash(name) != target) continue;

        DWORD funcRva = funcs[ordinals[i]];

        if (funcRva >= dir.VirtualAddress &&
            funcRva <  dir.VirtualAddress + dir.Size)
        {
            const char *fwd = (const char *)(base + funcRva);
            const char *dot = fwd;
            while (*dot && *dot != '.') dot++;
            if (*dot != '.') return NULL;

            char dllName[64];
            size_t n = (size_t)(dot - fwd);
            if (n + 5 > sizeof(dllName)) return NULL;
            for (size_t k = 0; k < n; k++) dllName[k] = fwd[k];
            dllName[n+0] = '.'; dllName[n+1] = 'd';
            dllName[n+2] = 'l'; dllName[n+3] = 'l';
            dllName[n+4] = 0;

            HMODULE hNext = GetModuleHandleA(dllName);
            if (!hNext) hNext = LoadLibraryA(dllName);
            if (!hNext) return NULL;

            return ResolveByHash(hNext, Ror13Hash(dot + 1));
        }

        return (FARPROC)(base + funcRva);
    }
    return NULL;
}

int main(void)
{
    HMODULE hK32;
    pfnAddVectoredExceptionHandler pAddVEH;
    PVOID hVEH;

    hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) {
        fprintf(stderr, "[-] GetModuleHandleA failed (%lu)\n", GetLastError());
        return 1;
    }

    pAddVEH = (pfnAddVectoredExceptionHandler)
        ResolveByHash(hK32, HASH_ADDVECTOREDEXCEPTIONHANDLER);
    if (!pAddVEH) {
        fprintf(stderr, "[-] hash resolution failed\n");
        return 1;
    }
    printf("[+] AddVectoredExceptionHandler resolved at %p\n", (void*)pAddVEH);

    hVEH = pAddVEH(1, MyVectoredHandler);
    if (!hVEH) {
        fprintf(stderr, "[-] AddVectoredExceptionHandler returned NULL\n");
        return 1;
    }
    printf("[+] VEH installed at handle %p. Triggering int3...\n", hVEH);

    __debugbreak();

    printf("[+] Survived. NtGlobalFlag check did not trip.\n");
    return 0;
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 3:</span>
  PoC to implement an Exception that hijack the standard execution flow when it is in a debugger
</div>

{{< figure src="/ox-hugo/exec_poc.png" caption="<span class=\"figure-number\">Figure 9: </span>Output of two execution, one in nominal execution and another in the debug that trigger the ExitProcess(0xDEAD)" >}}

This is a very simple scenario of how malware could abuse this feature to "hijack" the execution flow, here the Exception is made with an explicite `int3`.
But nothing is really hidden when decompiling the binary, even with dynamic api resolution, so analyst just after resolving the hash will pretty fastly
catch what to analyse. So, from an attacker point of view, how could this simple scenario can be improved?


### VEH / A failed way to "Arithmetic as a smokescreen" {#veh-a-failed-way-to-arithmetic-as-a-smokescreen}

First idea is to change the code that raise the exception, so instead of a `int3` why not triggering an `ACCESS_VIOLATION` based on simple arithmetic calculation.

Here for instance, we can add an inline ASM block that will trigger an `ACCESS_VIOLATION` by compute via boolean arithmetic a zero that will be used as an address:

```ASM
mov rbx, 0xdeadbeef
mov rcx, 0xd2acc002
add rcx, 0xc00feed
xor rbx, rcx
mov [rbx], rcx
```

This result in the register `rbx` being set to 0, that could read in C as `int *ptr = NULL; *ptr = 0xdeadbeef;`

```c
#include <windows.h>
#include <stdio.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK    0x10
#define FLG_HEAP_ENABLE_FREE_CHECK    0x20
#define FLG_HEAP_VALIDATE_PARAMETERS  0x40
#define NT_GLOBAL_FLAG_DBG_MASK (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)


static ULONG GetNtGlobalFlag(void)
{
#ifdef _WIN64
    PBYTE peb = (PBYTE)__readgsqword(0x60);
    return *(volatile ULONG *)(peb + 0xBC); // NtGlobalFlag in x64
#else
    PBYTE peb = (PBYTE)__readfsdword(0x30);
    return *(volatile ULONG *)(peb + 0x68); // NtGlobalFlag in x86
#endif
}

/* ---------- The vectored handler --------------------------------------- */
static LONG WINAPI MyVectoredHandler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionInformation[1] != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG flag = GetNtGlobalFlag();
    printf("[VEH] hit. NtGlobalFlag = 0x%lx\n", flag);

    if ((flag & NT_GLOBAL_FLAG_DBG_MASK) == NT_GLOBAL_FLAG_DBG_MASK) {
        printf("[VEH] debugger detected via NtGlobalFlag.\n");
        ExitProcess(0xDEAD);
    }

    printf("[VEH] clean. Skipping the faulting store and resuming.\n");

#ifdef _WIN64
    ep->ContextRecord->Rip += 3;
#else
    ep->ContextRecord->Eip += 2;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void)
{
    PVOID hVEH = AddVectoredExceptionHandler(1, MyVectoredHandler);
    if (!hVEH) {
        fprintf(stderr, "[-] AddVectoredExceptionHandler returned NULL\n");
        return 1;
    }
    printf("[+] VEH installed at handle %p. Triggering AV via arithmetic NULL...\n", hVEH);

    /* Compute a NULL pointer at runtime via boolean arithmetic,
     rcx  = 0xd2acc002 + 0x0c00feed = 0xdeadbeef
     rbx ^= rcx   -> 0xdeadbeef ^ 0xdeadbeef = 0
     [rbx] = rcx  -> write to address 0 -> EXCEPTION_ACCESS_VIOLATION */
    __asm__ volatile (
        ".intel_syntax noprefix\n\t"
        "mov rbx, 0xdeadbeef\n\t"
        "mov rcx, 0xd2acc002\n\t"
        "add rcx, 0x0c00feed\n\t"
        "xor rbx, rcx\n\t"
        "mov [rbx], rcx\n\t"
        ".att_syntax prefix\n\t"
        ::: "rbx", "rcx", "memory"
    );

    printf("[+] Survived. NtGlobalFlag check did not trip.\n");
    return 0;
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 4:</span>
  Source: [veh_arithmetic_access_violationation.c]
</div>

_x86_64-w64-mingw32-gcc -Wall -O0 veh_arithmetic_access_violationation.c -o veh.exe_

From the disasembly view it is what I was expected, however Hex-Rays is doing constant propagation across the basic block.
It sees five instructions with pure-immediate inputs and no external state, so it folds the whole computation at decompile time.

{{< figure src="/ox-hugo/veh_arithmetic_clear.png" caption="<span class=\"figure-number\">Figure 10: </span>Disassembly view and decompiled view in IDA" >}}

This implementation is too transparent: Hex-Rays was able to fold the five constant-driven instructions into a single `MEMORY[0] = 0xdeadbeef`.


### VEH / Sealing the fault {#veh-sealing-the-fault}

This section builds on the previous proof of concept and pushes the obfuscation one step further,
targeting the decompiler specifically: constants are hidden behind an opaque wrapper,
and the handler stops stepping over the fault and starts redirecting execution to an entirely separate function.

Basically what I want to test is the following workflow:

```c
hVEH = AddVectoredExceptionHandler(1, MyVectoredHandler);
t = (uint64_t)hVEH;
g_mask = (t ^ Opaque(t)) + Opaque(0xd2acc002) + 0x0c00feed;
mask_val = g_mask;
__asm { mov rcx, 0xd2acc002; add rcx, 0xc00feed; xor rbx, rcx; mov [rbx], rcx }
printf("(decoy) Survived..."); // I don't want to see this in the decompiled view
```

The idea here was to try to make the decompiler less helpful to the analyst,
both at the operand level and at the control-flow level.
I'm not sure these are the best techniques, but two small changes were layered onto the previous PoC
to see if Hex-Rays could still be coaxed away from showing a tidy `MEMORY[0] = 0xdeadbeef`.

First, the constants feeding the inline asm go through [`Opaque()`](#org-coderef--cbf663-11) function, a noinline identity function wrapping a volatile read.
The two attributes seem to pull in different directions, and I think that's why it works.
noinline forces the compiler to emit a real call at every call site instead of pasting the body inline.
volatile tells it the value inside the function could change between the store and the load
(in practice it can't, but as far as I understand the standard says the compiler has to assume it might),
so it can't reason about what comes out.
Together you get something close to a sealed black box: the compiler has to make the call,
and once execution is inside it can't really prove anything about the return value.

In my tests `0xdeadbeef` no longer shows up as a literal anywhere in the binary,
it only exists in `rbx` at runtime after the [`Opaque()`](#org-coderef--cbf663-11) compute part of the operation with other static variable.

Second, the handler stops being polite. Instead of just stepping over the faulting instruction,
it rewrites [`CONTEXT.Rip`](#org-coderef--cbf663-63) to point at a separate function, named here [`RealNextStage`](#org-coderef--cbf663-35), which is where the real "work" happens.
From what I've seen, IDA seems to treat an access violation as a dead end, so the decompilation of `main` just stops at the fault.
The [`printf`](#org-coderef--cbf663-103) sitting right after it looks like reachable code but never actually runs,
and the code that does run lives in a function with no static reference from `main` at all.

An analyst still has to read the handler, spot the `Rip` write, and follow it by hand.
That probably isn't a huge obstacle for someone experienced, but it does mean `main`'s decompilation on its own won't point the way.

```c { linenos=true, hl_lines=["11-15","35","63","66","81","103"," c -n -r"], anchorlinenos=true, lineanchors=org-coderef--cbf663 }
#include <windows.h>
#include <stdio.h>
#include <stdint.h>


#define FLG_HEAP_ENABLE_TAIL_CHECK    0x10
#define FLG_HEAP_ENABLE_FREE_CHECK    0x20
#define FLG_HEAP_VALIDATE_PARAMETERS  0x40
#define NT_GLOBAL_FLAG_DBG_MASK (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

static __attribute__((noinline)) uint64_t Opaque(uint64_t x)                                                                  (opaque-fnc)
{
    volatile uint64_t v = x;
    return v;
}

/* (volatile, in .bss) */
static volatile uint64_t g_mask;

// Same as previous PoC
static ULONG GetNtGlobalFlag(void)
{
#ifdef _WIN64
    PBYTE peb = (PBYTE)__readgsqword(0x60);
    return *(volatile ULONG *)(peb + 0xBC);
#else
    PBYTE peb = (PBYTE)__readfsdword(0x30);
    return *(volatile ULONG *)(peb + 0x68);
#endif
}

/* Reached only by the VEH rewriting CONTEXT.Rip. It has no static caller,
so IDA shows zero xrefs to it from main. End with ExitProcess because
there is no return address to ret */
static void __attribute__((used, noinline)) RealNextStage(void)                                                               (realnextstage-fnc)
{
    printf("[+] RealNextStage reached. Decompiler thinks main() crashed here.\n");
    printf("[+] This is the path real loaders use to hide their flow.\n");
    ExitProcess(0);
}

static LONG WINAPI MyVectoredHandler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionInformation[1] != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG flag = GetNtGlobalFlag();
    printf("[VEH] hit. NtGlobalFlag = 0x%lx\n", flag);

    if ((flag & NT_GLOBAL_FLAG_DBG_MASK) == NT_GLOBAL_FLAG_DBG_MASK) {
        printf("[VEH] debugger detected via NtGlobalFlag.\n");
        ExitProcess(0xDEAD);
    }

    printf("[VEH] clean. Rewriting Rip to RealNextStage (not visible in IDA).\n");

    /* x64 ABI: at function entry rsp must satisfy rsp % 16 == 8 (because a *
     * CALL would have pushed an 8-byte return address) tkt claude*/
#ifdef _WIN64
    ep->ContextRecord->Rsp = (ep->ContextRecord->Rsp & ~0xFULL) - 8;
    ep->ContextRecord->Rip = (DWORD64)&RealNextStage;                                                                         (rewrite-rip)
#else
    ep->ContextRecord->Esp = (ep->ContextRecord->Esp & ~0xFUL) - 4;
    ep->ContextRecord->Eip = (DWORD)&RealNextStage;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void)
{
    PVOID hVEH = AddVectoredExceptionHandler(1, MyVectoredHandler);
    if (!hVEH) {
        fprintf(stderr, "[-] AddVectoredExceptionHandler returned NULL\n");
        return 1;
    }
    printf("[+] VEH installed at %p. Building opaque mask...\n", hVEH);

    uint64_t t = (uint64_t)hVEH;
    g_mask = (t ^ Opaque(t)) + Opaque(0xd2acc002ULL) + 0x0c00feedULL; // g_mask after calcul is the 0xdeadbeef

    /* Force the volatile read into rbx via the "b" input constraint.
     decompiler should see rbx loaded from a global it cannot fold. */
    uint64_t mask_val = g_mask;

    printf("[+] Compute the opaque arithmetic NULL...\n");

    __asm__ volatile (
        ".intel_syntax noprefix\n\t"
        "mov rcx, 0xd2acc002\n\t"
        "add rcx, 0x0c00feed\n\t"
        "xor rbx, rcx\n\t"
        "mov [rbx], rcx\n\t"
        ".att_syntax prefix\n\t"
        :
        : "b"(mask_val)
        : "rcx", "memory"
    );

    /* Should not be reached at runtime if executed in a debugger because Rip
     point to RealNextStage  */
    printf("[+] (decoy) Survived. NtGlobalFlag check did not trip.\n");                                                       (lastprintf)
    return 0;
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 5:</span>
  Source [veh_hid_arithmetic_result.c]
</div>

_x86_64-w64-mingw32-gcc -Wall -O0 veh_hid_arithmetic_result.c -o veh.exe_

The above code successfuly show what I expected where the "real" execution flow is hidden by the Vector Handler.

{{< figure src="/ox-hugo/split_exec_main_veh.png" caption="<span class=\"figure-number\">Figure 11: </span>Decompiled view of the main function that implement the execution flow hidden" >}}

{{< figure src="/ox-hugo/split_exec_veh.png" caption="<span class=\"figure-number\">Figure 12: </span>Decompiled view of the custom vector handler that change program execution flow if a debugger is detected via NtGlobalFlag" >}}


## Detecting It as a Malware Analyst {#detecting-it-as-a-malware-analyst}

As a first ideas or the two starting points would be YARA and CAPA rules to search for following patterns:

-   YARA: signatures on `RtlAddVectoredExceptionHandler`, `AddVectoredExecptionHandler` and `AddVectoredContinueHandler`, mixed with known patterns such as `IsDebuggerPresent`, `NtQueryInformationProcess`, _etc..._
-   CAPA: relevant rules around exception handler registration and dynamic control flow, what to write if the rule does not exist yet.

This is a lightweight attempt at a CAPA rule. It may produce false positives,
but it has been helpful as a starting point when exploring large binaries. Note that the rule
is at function scope so, if the handler is registered at the beginning of the program and
the fault instructions in different functions, the rules won't trigger.

_NB: The rule only cover 3 types of exceptions: undefined instruction, int3, divide by zero;_

```yaml
rule:
  meta:
    name: register vectored exception handler to redirect control flow
    namespace: anti-analysis/anti-debugging/debugger-evasion
    authors:
      - @plebourhis
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Defense Evasion::Debugger Evasion [T1622]
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection [B0001]
      - Anti-Static Analysis::Disassembler Evasion [B0012]
    references:
      - https://anti-debug.checkpoint.com/techniques/exceptions.html
      - https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler
    description: |
      Malware registers a Vectored Exception Handler and then deliberately
      raises an exception (int3, ud2, divide-by-zero, RaiseException, ...).
  features:
    - and:
      - or:
          - api: AddVectoredExceptionHandler
          - api: kernel32.AddVectoredExceptionHandler
          - api: ntdll.RtlAddVectoredExceptionHandler
      - or:
          - mnemonic: int3
          - mnemonic: ud2
          - api: RaiseException
          - api: kernel32.RaiseException
          - and:
              - mnemonic: div
              - number: 0 = divide-by-zero to trigger EXCEPTION_INT_DIVIDE_BY_ZERO
          - and:
              - mnemonic: int
              - number: 0x2D = EXCEPTION_BREAKPOINT alt path (int 0x2D)
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 6:</span>
  CAPA rules on VEH registration combined with simple instructions that raise EXCEPTION
</div>

A second rule, oriented on the handler itself, looks for code that rewrites the `Eip=/=Rip` field of the `ContextRecord`.

```yaml
rule:
  meta:
    name: vectored exception handler rewrites instruction pointer
    namespace: anti-analysis/anti-debugging/debugger-evasion
    authors:
      - @plebourhis
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Defense Evasion::Debugger Evasion [T1622]
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection [B0001]
    description: |
      A VEH/SEH callback writes to the Eip (x86, CONTEXT+0xB8) or Rip
      (x64, CONTEXT+0xF8) field of the EXCEPTION_POINTERS->ContextRecord
      it was handed, redirecting execution after a planted exception.
  features:
    - and:
      - or:
          - number: 0xB8 = offsetof(CONTEXT, Eip) on x86
          - number: 0xF8 = offsetof(CONTEXT, Rip) on x64
      - or:
          - number: 0x10001 = EXCEPTION_CONTINUE_EXECUTION
          - number: 0xFFFFFFFF = (LONG)-1 EXCEPTION_CONTINUE_EXECUTION
          - number: 0 = EXCEPTION_CONTINUE_SEARCH (handler chooses to skip)
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 7:</span>
  CAPA rule for the Context Rip/Eip redirection
</div>

None of the paths I wanted to follow seams accurate, however, a hint for my future self would be to checks for SEH function handler that could have interesting code inside.
And also when debugging a new piece of malware add breakpoint on `RtlAddVectoredExceptionHandler` to investigate the handler code.

**A Note on the Limits of Detection**

It is important to remain humble about the visibility. While signature-level detection is highly effective against
known threats and reused codebases, it has inherent ceilings:

The Reality Check: Static signatures catch what we have seen before.
Because the underlying technique of using exception handlers to redirect code flow is a generic architectural feature of Windows,
it is relatively easy for an author to tweak the implementation. A new sample can sidestep most rules simply by
changing the "fault" instruction or obfuscating the registration call.

Ultimately, these signatures are starting points for a deeper investigation, rather than a definitive "case closed" for a new piece of malware!


## Wrapping Up {#wrapping-up}

Going into this I expected exception handling to be a small detour
before getting back to the malware sample. It turned out to be a
bigger topic than I thought, and I am sure parts of what I wrote above
are still imprecise, the x64 unwind machinery in particular is
something I want to revisit, because I don't yet have a clean mental
model of how `__C_specific_handler` decides what to do with the scope
table.

What I take away from this exercise:

-   **SEH** and **VEH** are not exotic. They are the documented Windows exception
    model, and most of what makes them feel "tricky" in malware is just
    that the analyst is meeting them for the first time in an adversarial
    context.
-   VEH is interesting to an attacker for a very specific reason: it
    fires **before** SEH, it is process-wide, and the handler has full
    read/write access to the saved register context. That combination is
    what makes it usable as a control-flow primitive (from malware author PoV).
-   On the detection side, my CAPA attempts are honestly a starting
    point. The technique is generic enough that signatures will lag
    behind any author who is willing to swap the faulting instruction or
    wrap the registration call. I think the more durable signal is
    behavioural: a handler that writes to `ContextRecord->Rip` / `Eip` and
    returns `EXCEPTION_CONTINUE_EXECUTION` is doing something a
    well-behaved program almost never needs to do (hope so...) but turning that into
    a rule that does not light up on every C++ runtime is its own
    project.

If you spotted something wrong, or if you have a cleaner way of writing
the CAPA rules, I would genuinely like to hear it. The references at
the top of this post ([SonicWall](https://www.sonicwall.com/blog/guloader-demystified-unraveling-its-vectored-exception-handler-approach), [Zscaler](https://www.zscaler.com/blogs/security-research/technical-analysis-guloader-obfuscation-techniques), [CrowdStrike](https://www.slideshare.net/slideshow/unmasking-the-dark-art-of-vectored-exception-handling-bypassing-xdr-and-edr-in-the-evolving-cyber-threat-landscape/263989842?utm_source=clipboard_share_button&utm_campaign=slideshare_make_sharing_viral_v2&utm_variation=control&utm_medium=share), [IBM](https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection), [Unit42](https://unit42.paloaltonetworks.com/malware-configuration-extraction-techniques-guloader-redline-stealer/))
remain the better place to read about VEH in the wild; this article is
just my attempt to understand the plumbing well enough to recognise it
next time.

_Other great resources:_

-   [Talos - Exceptional behavior: the Windows 8.1 X64 SEH Implementation](https://blog.talosintelligence.com/exceptional-behavior-windows-81-x64-seh/)
-   [Elmo.sg - A deep dive into modern Windows Structured Exception Handler (SEH) ⚠️](https://blog.elmo.sg/posts/structured-exception-handler-x64/)
-   [Datafarm - Code Execution against Windows HVCI](https://datafarm-cybersecurity.medium.com/code-execution-against-windows-hvci-f617570e9df0)
