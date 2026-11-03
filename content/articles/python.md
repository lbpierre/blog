+++
title = "Python 🐍"
author = ["pbo"]
description = "All notes related to Python goes here"
publishDate = 2023-11-24T00:00:00+01:00
aliases = ["/notes/python/"]
lastmod = 2026-11-03T16:05:44+01:00
tags = ["python"]
categories = ["dev"]
draft = false
+++

{{< figure src="/ox-hugo/python_header.jpg" >}}


## Base64 custom alphabet {#base64-custom-alphabet}

Here's a brief Python code snippet for decoding base64 data that uses a non-standard alphabet.
The [Darkgate](https://blog.sekoia.io/darkgate-internals/) sample was observed to use this custom alphabet.

```python
import base64

def custom_b64_decode(s):
     custom_base64 = "KHkFLg9RnhcZNSDl1TsOj2JveVUpfC4Bq67XyIbm5Q8EGi3A=Madwr0uYzt+oWPx"
     std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/="
     o = str(s).translate(str(s).maketrans(custom_base64, std_base64chars))
     return base64.b64decode(o)

custom_b64_decode("jrIO2L2S")
```

```text
b'SYSTEM'
```


## PE resources extraction with pefile {#pe-resources-extraction-with-pefile}

Snippet of code to read each resource of a PE:

```python
pe = pefile.PE("<path to PE>")

offset: int = 0
size: int = 0
resource_type: str = ""

for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    resource_type = str(entry.name)
    for directory in entry.directory.entries:
	for resource in directory.directory.entries:
	    offset = resource.data.struct.OffsetToData
	    size = resource.data.struct.Size
	    content = pe.get_memory_mapped_image()[offset : offset + size]

	    print(
		f"read resource {resource_type} at offset 0x{offset:x} on 0x{size:x} bytes"
	    )
```


## CLSID identifier <span class="org-target" id="org-target--clsid"></span> {#clsid-identifier}

A Python helper to identify the object (class and interface) from the CLSID or the RIID.
The snippet below is trimmed, the complete script (with the full CLSID table) is available here:

{{< download "clsid-identifier.py" >}}

The `CoCreateInstance` function can create various types of COM objects depending on the CLSID provided.
Here are some examples of what these objects could be:

1.  ****Standard COM Objects****: These are typical COM objects implementing various functionalities, such as document handling,
    media processing, or system components.
2.  ****Automation Objects****: Objects that provide OLE Automation interfaces, making them accessible from
    scripting languages like VBScript, JavaScript, and PowerShell.
3.  ****ActiveX Controls****: These are COM objects that can be embedded in
    applications or web pages to provide interactive features.
4.  ****Shell Extensions****: COM objects that extend the functionality of the Windows Shell,
    such as custom context menu handlers, icon handlers, or property sheet handlers.
5.  ****Service Objects****: Objects that provide specific services to other applications, like data access or messaging.

{{% sidenote %}}
<https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance>
{{% /sidenote %}}

```C++
  HRESULT CoCreateInstance(
  [in]  REFCLSID  rclsid,
  [in]  LPUNKNOWN pUnkOuter,
  [in]  DWORD     dwClsContext,
  [in]  REFIID    riid,
  [out] LPVOID    *ppv
);
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 1:</span>
  CoCreateInstance function prototype
</div>

{{< figure src="/ox-hugo/raw_clsid_CoCreateInstance.png" caption="<span class=\"figure-number\">Figure 1: </span>example of Object creation using the class identifier" >}}

{{< figure src="/ox-hugo/clsid_hex_export.png" caption="<span class=\"figure-number\">Figure 2: </span>CLSID export" >}}

```python
import struct

CLSID = {
    "TaskScheduler": "0F87369F-A4E5-4CFC-BD3E-73E6154572DD",
    "ITaskFolderCollection": "79184A66-8664-423F-97F1-637356A5D812",
    "ITaskFolder": "8CFAC062-A080-4C15-9A88-AA7C2AF80DFC",
    "IRegisteredTask": "9C86F320-DEE3-4DD1-B972-A303F26B061E",
    "IRunningTask": "653758FB-7B9A-4F1E-A471-BEEB8E9B834E",
    "IRunningTaskCollection": "6A67614B-6828-4FEC-AA54-6D52E8F1F2DB",
    "ITaskDefinition": "F5BC8FC5-536D-4F77-B852-FBC1356FDEB6",
    "IRegistrationInfo": "416D8B73-CB41-4EA1-805C-9BE9A5AC4A74",
    "ITriggerCollection": "85DF5081-1B24-4F32-878A-D9D14DF4CB77",
    "ITrigger": "09941815-EA89-4B5B-89E0-2A773801FAC3",
    "IRepetitionPattern": "7FB9ACF1-26BE-400E-85B5-294B9C75DFD6",
    "ITaskSettings": "8FD4711D-2D02-4C8C-87E3-EFF699DE127E",
    "IIdleSettings": "84594461-0053-4342-A8FD-088FABF11F32",
    "INetworkSettings": "9F7DEA84-C30B-4245-80B6-00E9F646F1B4",
    "IPrincipal": "D98D51E5-C9B4-496A-A9C1-18980261CF0F",
    "IActionCollection": "02820E19-7B98-4ED2-B2E8-FDCCCEFF619B",
    "IAction": "BAE54997-48B1-4CBE-9965-D6BE263EBEA4",
    "IRegisteredTaskCollection": "86627EB4-42A7-41E4-A4D9-AC33A72F2D52",
    "ITaskService": "2FABA4C7-4DA9-4013-9697-20CC3FD40F85",
    "ITaskHandler": "839D7762-5121-4009-9234-4F0D19394F04",
    "ITaskHandlerStatus": "EAEC7A8F-27A0-4DDC-8675-14726A01A38A",
    "ITaskVariables": "3E4C9351-D966-4B8B-BB87-CEBA68BB0107",
    "ITaskNamedValuePair": "39038068-2B46-4AFD-8662-7BB6F868D221",
    "ITaskNamedValueCollection": "B4EF826B-63C3-46E4-A504-EF69E4F7EA4D",
    "IIdleTrigger": "D537D2B0-9FB3-4D34-9739-1FF5CE7B1EF3",
    "ILogonTrigger": "72DADE38-FAE4-4B3E-BAF4-5D009AF02B1C",
    "ISessionStateChangeTrigger": "754DA71B-4385-4475-9DD9-598294FA3641",
    "IEventTrigger": "D45B0167-9653-4EEF-B94F-0732CA7AF251",
    "ITimeTrigger": "B45747E0-EBA7-4276-9F29-85C5BB300006",
    "IDailyTrigger": "126C5CD8-B288-41D5-8DBF-E491446ADC5C",
    "IWeeklyTrigger": "5038FC98-82FF-436D-8728-A512A57C9DC1",
    "IMonthlyTrigger": "97C45EF1-6B02-4A1A-9C0E-1EBFBA1500AC",
    "IMonthlyDOWTrigger": "77D025A3-90FA-43AA-B52E-CDA5499B946A",
    "IBootTrigger": "2A9C35DA-D357-41F4-BBC1-207AC1B1F3CB",
    "IRegistrationTrigger": "4C8FEC3A-C218-4E0C-B23D-629024DB91A2",
    "IExecAction": "4C3D624D-FD6B-49A3-B9B7-09CB3CD3F047",
    "IExecAction2": "F2A82542-BDA5-4E6B-9143-E2BF4F8987B6",
    "IShowMessageAction": "505E9E68-AF89-46B8-A30F-56162A83D537",
    "IComHandlerAction": "6D2FD252-75C5-4F66-90BA-2A7D8CC3039F",
    "IEmailAction": "10F62C64-7E16-4314-A0C2-0C3683F99D40",
    "IPrincipal2": "248919AE-E345-4A6D-8AEB-E0D3165C904E",
    "ITaskSettings2": "2C05C3F0-6EED-4C05-A15F-ED7D7A98A369",
    "ITaskSettings3": "0AD9D0D7-0C7F-4EBB-9A5F-D1C648DCA528",
    "IMaintenanceSettings": "A6024FA8-9652-4ADB-A6BF-5CFCD877A7BA",
    "TaskHandlerPS": "F2A69DB7-DA2C-4352-9066-86FEE6DACAC9",
    "TaskHandlerStatusPS": "9F15266D-D7BA-48F0-93C1-E6895F6FE5AC",
}


def bytes_to_clsid(byte_data: bytes) -> str:
    if len(byte_data) != 16:
        raise ValueError("A CLSID must be 16 bytes long")

    # Unpack bytes according to CLSID structure
    part1, part2, part3, part4_and_part5 = struct.unpack("<IHH8s", byte_data[:16])

    # Split part4_and_part5 into two parts
    part4 = part4_and_part5[:2]
    part5 = part4_and_part5[2:8]
    part6 = byte_data[8:16]

    # Format the CLSID
    clsid = f"{part1:08X}-{part2:04X}-{part3:04X}-{part4.hex().upper()}-{part5.hex().upper()}{part6.hex().upper()}"
    return clsid


def identify_object(raw_id: str) -> str:
    byte_data = bytes.fromhex(raw_id)
    r_clsid = bytes_to_clsid(byte_data)

    for name, clsid in CLSID.items():
        if clsid.lower() in r_clsid.lower():
            return f"{r_clsid} -> {name}"
    return ""


identify_object("9F36870FE5A4FC4CBD3E73E6154572DD")
```

```text
0F87369F-A4E5-4CFC-BD3E-73E6154572DDBD3E73E6154572DD -> TaskScheduler
```

To no overstock the script  all the CLSID are not included in it, however a script on this [gist](https://gist.github.com/lbpierre/47456aa3229afbf4bfb4b5c84551ca70) contains all
the extracted CLSID and RIID from [WINE](https://github.com/wine-mirror/wine/tree/master) repository is available. The snippet to extract the ID is the following one:

```python
import os
clsids = {}

# make sure to put the script at the root of wine repo
for root_dir, _, filenames in os.walk("include/"):
    for filename in filenames:
	with open(os.path.join(root_dir,  filename), "r") as f:
	    content = f.read().split("\n")
	    for line_nb, line in enumerate(content):
		if "uuid(" in line:
		    if "interface" in content[line_nb+2] or "coclass" in content[line_nb+2]:
			clsid = line.strip().replace('uuid(', '').replace(')','')
			name = content[line_nb+2].split()[1].strip()
			clsids[name] = clsid

print(clsids)
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 2:</span>
  snippet to extract the CLSID and RIID from wine/include
</div>


## XTEA - eXtended TEA {#xtea-extended-tea}

In cryptography, **XTEA** (**eXtended TEA**) is a block cipher designed to correct weaknesses in TEA.
The cipher's designers were David Wheeler and Roger Needham of the Cambridge Computer Laboratory,
and the algorithm was presented in an unpublished technical report in 1997
(Needham and Wheeler, 1997). It is not subject to any patents.

_Source: [wikipedia.org: XTEA](https://en.wikipedia.org/wiki/XTEA)_

-   [web.archive.org: Python XTEA Encryption (Python recipe)](https://web.archive.org/web/20230224082426/https://code.activestate.com/recipes/496737/)
-   [github.com: Varbin/xtea](https://github.com/Varbin/xtea)


### Key features {#key-features}

-   **Block size**: 64 bits;
-   **Key size**: 128 bits;
-   **Rounds**: 64 rounds of encryption, divided into pairs of Feistel rounds.


### Basic structure {#basic-structure}

-   **Feistel network**: XTEA uses a Feistel structure where the input 64-bit block
    is split into two 32-bit halves (typically labeled `v0` and `v1`).
    In each round, one half is modified based on a combination of the other half,
     the key, and a round-dependent constant called the `delta`.
-   **Round operations**: Each round uses _XOR_, addition, and _bitwise shifts_.
-   **Key scheduling**: The 128-bit key is split into four 32-bit subkeys (`k0`, `k1`, `k2`, `k3`),
    which are used in a cyclic manner across the rounds.


### Summary of process {#summary-of-process}

1.  Split the 64-bit input block into two 32-bit halves.
2.  Perform 64 rounds of encryption using XOR, addition, and bitwise shifts.
3.  Use the 128-bit key, broken into four subkeys, in a cyclic manner.
4.  After 64 rounds, the two 32-bit halves are combined to produce the encrypted 64-bit block.

_NB: The delta constante value is defined as the result of 2^32 divided by the [golden ratio](https://en.wikipedia.org/wiki/Golden_ratio)._

```python
import math

_32bit_integer: float = 2**32
golden_ratio: float = (1 + math.sqrt(5)) / 2

print(f"delta = 0x{int(_32bit_integer // golden_ratio):x}")
```

```text
delta = 0x9e3779b9
```


### Implementation {#implementation}

Based on this public `C` implementation:

```C
#include <stdint.h>

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}
```

The following is an implementation of the XTEA algorithm in Python3:

```python
import struct

# ensure to remain in the size of unsigned long
rshift = lambda v, n: (v >> n) & 0xffffffff
lshift = lambda v, n: (v << n) & 0xffffffff

class XTEA:

    XTEA_DELTA: int  = 0x9e3779b9

    @staticmethod
    def encrypt_block(block: bytes, key: bytes, round: int = 64, endian: str = "!") -> bytes:
        """xtea 32 bit block data encryption"""

        assert len(key) == 16
        assert len(block) == 8

        v0, v1 = struct.unpack(endian + "2L", block)
        _key: list[int] = struct.unpack(endian + "4L", key)
        _sum: int = 0
        _delta: int = XTEA.XTEA_DELTA

        for i in range(round):
            v0 = (v0 + (((lshift(v1, 4) ^ rshift(v1, 5)) + v1) ^ (_sum + _key[_sum & 3]))) & 0xffffffff
            _sum = (_sum + _delta) & 0xffffffff
            v1 = (v1 + (((lshift(v0, 4) ^ rshift(v0, 5)) + v0) ^ (_sum + _key[(_sum >> 11) & 3]))) & 0xffffffff

        return struct.pack(endian + "2L", v0, v1)

    @staticmethod
    def decrypt_block(block: bytes, key: bytes, round: int = 64, endian: str = "!") -> bytes:
        """xtea 32 bit block data decryption """

        assert len(key) == 16
        assert len(block) == 8

        v0, v1 = struct.unpack(endian + "2L", block)
        _key: list[int] = struct.unpack(endian + "4L", key)
        _delta: int = XTEA.XTEA_DELTA
        _sum: int = (_delta * round) & 0xffffffff

        for i in range(round):
            v1 = (v1 - (((lshift(v0, 4) ^ rshift(v0, 5)) + v0) ^ (_sum + _key[rshift(_sum, 11) & 3]))) & 0xffffffff
            _sum = (_sum - _delta) & 0xffffffff
            v0 = (v0 - (((lshift(v1, 4) ^ rshift(v1, 5)) + v1) ^ (_sum + _key[_sum & 3]))) & 0xffffffff

        return struct.pack(endian + "2L", v0, v1)


    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, round: int = 64, endian: str = "!") -> bytes:
        """xtea decryption of a complete ciphertext"""

        ciphertext = XTEA.pad(ciphertext, 8, b"\x00")
        return XTEA.__xtea_wrapper(XTEA.decrypt_block, ciphertext, key, round, endian)

    @staticmethod
    def encrypt(cleartext: bytes, key: bytes, round: int = 64, endian: str = "!") -> bytes:
        """xtea encryption of a complete cleartext"""

        cleartext = XTEA.pad(cleartext, 8, b"\x90")
        return XTEA.__xtea_wrapper(XTEA.encrypt_block, cleartext, key, round, endian)


    @staticmethod
    def __xtea_wrapper(xtea_function: callable, blob: bytes, key: bytes, round: int = 64, endian: str ="!") -> bytes:
        """decrypt a complete payload, key must be 16 bytes long"""

        assert len(key) == 16
        output: bytes = b""

        for block_index in range(0, len(blob), 8):
            output += xtea_function(blob[block_index: block_index + 8], key, round, endian)

        return output

    @staticmethod
    def pad(data: bytes, block_size: int = 8, padding_byte: bytes = b"\x90") -> bytes:

        if not len(data) % block_size:
            return data

        pad_size = len(data) + (block_size - len(data) % block_size)
        print(f"add {pad_size - len(data)} {padding_byte} byte(s) padding")
        data = data.ljust(pad_size, padding_byte)

        return data

# note that the key below will be padded to 16 bytes with null byte
# to fit the algorithm standard, the data to encrypt will also be
# padded to a multiple of 8 (here 2 padding bytes)
key = XTEA.pad(b"Hello there", 16, b"\x00")
cleartext = XTEA.pad(b"General Kenobi", 8, b"\x90")
print(f"encrypt `{cleartext}` with xTEA algorithm, key=`{key}`")
ciphertext = XTEA.encrypt(key=key, cleartext=cleartext, round=32)
print(f"ciphertext: {ciphertext.hex()}")
decrypted = XTEA.decrypt(key=key, ciphertext=ciphertext, round=32)
assert decrypted == cleartext
```

```text
add 5 b'\x00' byte(s) padding
add 2 b'\x90' byte(s) padding
encrypt `b'General Kenobi\x90\x90'` with xTEA algorithm, key=`b'Hello there\x00\x00\x00\x00\x00'`
ciphertext: 36939f6855904465a5dd89f714429dad
```


## FNV-1 {#fnv-1}

****Fowler–Noll–Vo**** is a hashing algorithm, whose speucode is:

```nil
algorithm fnv-1 is
    hash := FNV_offset_basis

    for each byte_of_data to be hashed do
        hash := hash × FNV_prime
        hash := hash XOR byte_of_data

    return hash
```

There is a variant of this algorithm called FNV-1\*\*a\*\* where the XOR and the multiplication are switched.
The XOR operation is performed prior to the multiplication.

The Python implementation is as fallow:

```python
from enum import Enum
from typing import Union


class ARCH(Enum):
    """Supported hash architecture to handle FNV1
    PRIME, init offset and the bit mask for max value"""
    X32 = 32
    X64 = 64

class FNV1Variant(Enum):
    FNV1 = "FNV-1"    # Original FNV-1 (multiply, then XOR)
    FNV1A = "FNV-1A"  # FNV-1a variant (XOR, then multiply)


class FNV1Hash:
    """Implementation of FNV hash algorithms (FNV-1 and FNV-1a)
    for 32-bit and 64-bit architectures."""

     # FNV constants
    _CONSTANTS = {
        ARCH.X32: {
            'prime': 0x01000193,
            'init': 0x811C9DC5,
            'size': 2**32
        },
        ARCH.X64: {
            'prime': 0x00000100000001B3,
            'init': 0xCBF29CE484222325,
            'size': 2**64
        }
    }


    @classmethod
    def hash(cls,
             data: Union[bytes, str],
             arch: ARCH = ARCH.X32,
             variant: FNV1Variant = FNV1Variant.FNV1) -> int:
        """
        Compute the FNV hash of the input data

        Args:
            data: The data to hash, can be string or bytes
            arch: Architecture (32-bit or 64-bit)
            variant: FNV1 or FNV1A

        Returns: computed hash as an integer

        Raises:
            TypeError: if input data is not str or bytes
            ValueError: if ARCH is not supported
        """

        if isinstance(data, str):
            data = data.encode()
        elif not isinstance(data, bytes):
            raise TypeError(f"Input data must be str or bytes not: {type(data)}")

        if arch not in cls._CONSTANTS:
            raise ValueError(f"Unsupported architecture: {arch}")

        constants = cls._CONSTANTS[arch]
        hval = constants['init']
        fnv_prime = constants['prime']
        fnv_size = constants['size']

        if variant is FNV1Variant.FNV1A:
            # FNV-1A: XOR then multiply
            for byte in data:
                hval = hval ^ byte
                hval = (hval * fnv_prime) % fnv_size
        else: # FNV1
            # FNV-1: multiply then XOR
            for byte in data:
                hval = (hval * fnv_prime) % fnv_size
                hval = hval ^ byte

        return hval


class FNV1aHash:
    """Alias for FNVHash class with FNV-1a variant."""

    @classmethod
    def hash(cls, data: Union[bytes, str], arch: ARCH = ARCH.X32) -> int:
        """Calculate the FNV-1a hash of input data."""
        return FNV1Hash.hash(data, arch, FNV1Variant.FNV1A)

test_input = "Lotus"

hash_32_fnv1a = FNV1aHash.hash(test_input)
hash_32_fnv1 = FNV1Hash.hash(test_input)

print(f"FNV-1a (32-bit) of '{test_input}' is 0x{hash_32_fnv1a:08x}")
print(f"FNV-1  (32-bit) of '{test_input}' is 0x{hash_32_fnv1:08x}")
```

```text
FNV-1a (32-bit) of 'Lotus' is 0xeac834bc
FNV-1  (32-bit) of 'Lotus' is 0x8861a036
```
