+++
title = "Focus on XWorm obfuscation 🪱"
author = ["pbo"]
description = """
  **XWorm** is a **Remote Access Trojan** (_RAT_) developed in .NET, the malware is mostly spread via
  phishing campaigns using homemade or opensource packing tools. Note, that some versions of the source code have **leaked**
  on Cybercrime forums and also on Telegram channels. This analysis focuses on the XWorm version 3.0.
  """
publishDate = 2023-06-07T00:00:00+02:00
tags = ["RAT", "dotnet", "campaign"]
categories = ["RE"]
draft = false
+++

{{< figure src="/ox-hugo/xworm_head_image_3.png" >}}


## TL;DR XWorm {#tl-dr-xworm}

The malware has many functionalities: Virtual environment detection, command execution, file download/upload, persistent after reboot, keylogging, etc...
An interesting feature of the RAT is the plugin configuration; attackers can
configure plugins that are downloaded and executed by the RAT during the infection.
The plugins are mainly DLL in .NET, the last section explains how to extract XWorm plugins from network capture.

The next sections detail how the RAT managed its configuration deobfuscation, then how the Command and Control (_C2_) communication works.

Links to download the sample used for this analysis:

-   [MalwareBaazar: SHA256-6f2e22d541680c151da164b02f916a3d72da0517b2f052f7356d05e8b374690b](https://bazaar.abuse.ch/sample/6f2e22d541680c151da164b02f916a3d72da0517b2f052f7356d05e8b374690b/)
-   [Tria.ge sandbox](https://tria.ge/230227-la7fkach56/behavioral1)

The RAT have been spotted at the end of November 2022 distributed in malspam campaigns, as reported in this tweet:

<blockquote align="center" class="twitter-tweet"><p lang="en" dir="ltr">Most people don&#39;t tag their precise location in Tweets, so we&#39;re removing this ability to simplify your Tweeting experience. You&#39;ll still be able to tag your precise location in Tweets through our updated camera. It&#39;s helpful when sharing on-the-ground moments.</p>&mdash; Twitter Support (@TwitterSupport) <a href="https://twitter.com/0xToxin/status/1597247779084337152?ref_src=twsrc%5Etfw">June 18, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

One reason of the rise of XWorm observed in the wild could be the leak of the source code:

-   XSS forum: `xss.]is/threads/75837/`;
-   Shinyenigma Github repository: [Shinyenigma/XWorm-RAT](https://github.com/Shinyenigma/XWorm-RAT).


## XWorm data obfuscation {#xworm-data-obfuscation}

The RAT configuration is stored in a class of the namespace `Stub`, where variables value are encoded in base64, in this version of the sample namespaces, classes
and variables names are randomized to slow down the analysis, however, the structure of the code remains the same as clear sample!
This naming randomization is becoming more and more popular amoung threat actors that have XWorm in their arsenal.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/xworm_decryption_conf.png" caption="<span class=\"figure-number\">Figure 1: </span>XWorm configuration decryption using AES (ECB No padding)" >}}

XWorm first deobufscates its configuration, it initiates a `CryptServiceProvider`,
then the RAT compute the **MD5** hash of a variable (named `Mutex`) located in its configuration
class. Finally the hash is manipulated (oddly 🙃) to create the decryption key used to decrypt
the rest of configuration (host, port, etc.).

XWorm uses **Rijndael**

{{% sidenote %}}
The Advanced Encryption Standard (AES), also known by its original name Rijndael
<https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>
{{% /sidenote %}}

encryption in ECB (_Electronic CodeBook_) mode, no IV (_Initial Vector_) is required here.
To create the key, the malware creates the MD5 hash of a variable copies the 8 first bytes to store them at the beginning of a new allocated array (_of 16 bytes; the
decryption key length_), then re-copies these same 8 bytes to the key array but not after the 8 first bytes but from the 7^th byte to the 15 byte.
The last byte (16^th) is zero (due to the array initialization). The figure below schematizes how the key is built.

```text
+----------+  Base64 decode    +--------+
| Variable +------------------>| Array  |
+----------+                   +-----+--+
                                     |
                                     +-MD5
                                     |
                               +-----v--------------------------+
                               |dfe3ee833129588467dcf63d547b5806|
                               +--------------------------------+
                               0               8                16 (bytes)
                               + -----+------- +
                                      |  Copy
                                      +---------------+
                                      |               |
                                      |               v
                                      |       + --------------+
                                      v       |dfe3ee8331295884|
                               +--------------- +
                               |dfe3ee8331295884|
                               +--------------+-+---------------+--+
                               |              |X|               |00|
                               +--------------+-+---------------+--+
                               0              7 8               15 16 (bytes)
```

_NB:_

-   the bytes 7 is overwritten
-   the last byte of the key is fill with null byte
-   the Rijndael key is 16 bytes long.

Code of the class in charge of the configuration ⤵️

<details>
<div class="details">

<a id="code-snippet--post-subtrees-collapsed"></a>
```csharp { linenos=true, linenostart=1, hl_lines=["32","42"] }
using System;
using Microsoft.VisualBasic;

// Token: 0x02000007 RID: 7
public class 1155SI5ci4n22Hgtjad9sWuTzrR6TsPd3
{

	public static string 1mDweS2QdR()
	{
		return "1CWdwE8cqZ";
	}

	public static int EzSG3aY6W9()
	{
		return 99534703;
	}

	public static string Kxcu3hu0i2()
	{
		return "3SXF4Z2FNV";
	}

	public static int mOGPU4rRYz()
	{
		return 1112926;
	}

	public static string P9aS8dF2nvwBlMKsX6mGmz9cpNwVvrwuR = "VpmZ71vaW8IbCUUhXaZYmIZ+fg3gEPqzqfEpJeFIWv0=";

	public static string O3fw8tjb6Ybd2xdW1giyBzQmbNOjR0msp = "a6SLXA5CKiTAVsnJwB7XJw==";

	public static string hmapdKWqyxSWCy3WcMMHwiP4mJaWTptDB = "bvUFyfn2d6e7YEJt9/zw/A==";

	public static string iOHL4ozmm3zDihnbDjArk0EELSZcjGaht = "suGMnRXFX/LRVfGLaUEsHA==";

	public static int bq1mI0Edvncwx7ALBYKSeIcOOIBhaoFYg = 3;

	public static string vJsr4si0NzLXgwfc4qHHmiEQitrHJl3Dk = "5D+67sZ9S91x7RZPyaBWwBnRhFtzU62dUOgoP7j7MdQ=";

	public static string xDJM0Hxvl8n38SrNt95dqrkiScRfNClzh = "%AppData%";

	public static string uVIC8wouZBTVmqNmkP5u6gKlFXjOtuSz8 = "FIubOp8mcEdS0i5b";

	public static string w4IoWC1BczHdJNaHCSWko7r27h7MJfJJM = Interaction.Environ("temp") + "\\Log.tmp";
}
```
<div class="src-block-caption">
  <span class="src-block-number"><a href="#code-snippet--post-subtrees-collapsed">Code Snippet 1</a>:</span>
  Configuration class of XWorm (source: DnSpy)
</div>
</div>
</details>

In this version of the RAT variables name are obfuscated, the two highlighted variables are the communication key (first variable from the top)
and the second one is what was named `Mutex`. The mutex is the variable holding the base string
used to build the decryption key for the configuration. The variable holding the key used for communication encryption/decryption need
to be first decrypted by the same method used for the rest of the configuration decryption before behing used for the communication.

Once decrypted, the configuration of XWorm is:

| Purpose                   | Value obfuscated                             | Cleartext                   |
|---------------------------|----------------------------------------------|-----------------------------|
| C2 Host                   | VpmZ71vaW8IbCUUhXaZYmIZ+fg3gEPqzqfEpJeFIWv0= | `names-again.at.playit.]gg` |
| C2 Port                   | a6SLXA5CKiTAVsnJwB7XJw==                     | `59741`                     |
| AES key for communication | bvUFyfn2d6e7YEJt9/zw/A==                     | `<123456789>`               |
| Message split pattern     | suGMnRXFX/LRVfGLaUEsHA==                     | `<Xwormmm>`                 |
| Installation name         | 5D+67sZ9S91x7RZPyaBWwBnRhFtzU62dUOgoP7j7MdQ= | `Microsoft OneDrive.exe`    |

Here is the cyberchef [recipe](https://cyberchef.org/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'Hex','string':'dfe3ee833129588467dcf63d547b58dfe3ee833129588467dcf63d547b580600'%7D,%7B'option':'Hex','string':''%7D,'ECB/NoPadding','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=VnBtWjcxdmFXOEliQ1VVaFhhWlltSVorZmczZ0VQcXpxZkVwSmVGSVd2MD0KYTZTTFhBNUNLaVRBVnNuSndCN1hKdz09CmJ2VUZ5Zm4yZDZlN1lFSnQ5L3p3L0E9PQpzdUdNblJYRlgvTFJWZkdMYVVFc0hBPT0KNUQrNjdzWjlTOTF4N1JaUHlhQld3Qm5SaEZ0elU2MmRVT2dvUDdqN01kUT0).


## Command and Control Communication {#command-and-control-communication}

XWorm communications are encrypted with AES algorithm in ECB mode. The RAT uses **raw TCP connection** on a
port defined by the attacker. Exchanged messages are not fully encrypted, in fact the first bytes contains the size
of the message followed by a null bytes (_used as a split pattern_) in cleartext, see the figure below where the size of the message is in black,
the split pattern in red and the encrypted message in blue.

<a id="figure--xworm-communication-hexdump"></a>

{{< figure src="/ox-hugo/xworm_pcap_hexdump.png" caption="<span class=\"figure-number\">Figure 2: </span>XWorm raw TCP message in hexdump format" >}}

Once the mutex and the communication key are identified you can use this script to deobfuscate the RAT communication.

<a id="code-snippet--post-subtrees-collapsed"></a>
```python { linenos=true, linenostart=46 }
import sys
import argparse
import binascii
import hashlib
from base64 import b64decode
from collections import deque
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()


def decrypt_XWorm_configuration(mutex: str, configuration: str) -> bytes:
    """configuration are stored in base64, the key used for the
    configuration decryption is the MD5 hash (re-arranged) of the
    variable `Mutex`"""

    md5 = hashlib.md5(mutex.encode())
    md5 = md5.digest()

    key = md5[:-1] + md5 + b"\x00"

    decoded_configuration = b64decode(configuration)

    decryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).decryptor()

    return decryptor.update(decoded_configuration)



def decrypt_XWorm_communication(mutex: str, com_key: str, packet: str):
    """Rijndael decryption of XWorm communcation"""

    clear_com_key = decrypt_XWorm_configuration(mutex, com_key)
    clear_com_key = clear_com_key[:-clear_com_key[-1]]

    hpacket = binascii.unhexlify(packet)
    hpacket = hpacket.split(b"\x00", maxsplit=1)
    size, message = int(hpacket[0]), hpacket[1]

    clear_com_key = hashlib.md5(clear_com_key).digest()

    decryptor = Cipher(algorithms.AES(clear_com_key), modes.ECB(), backend).decryptor()
    cleartext = decryptor.update(message)
    cleartext = cleartext[:-cleartext[-1]]

    if len(cleartext) < 1000 and cleartext:
	  print(size, cleartext)

    if not abs(len(cleartext) - size) >= 16 and len(cleartext) > 1000:
	  print(f"Download plugin: {cleartext[:100]}")
	  with open(f"packet-{len(cleartext)}.bin", "wb") as f:
	      f.write(cleartext)

    return False if abs(len(cleartext) - size) >= 16 else True


def main(mutex: str, com: str):
    """Main function to decrypt XWorm communication"""

    queue = deque(map(lambda x: x.replace("\n", ""), sys.stdin.readlines()))

    while queue:
	  try:
	      packet = queue.popleft()
	      if not decrypt_XWorm_communication(mutex, com, packet):
		  queue.insert(0, f"{packet}{queue.popleft()}")
	  except Exception as err:
	      if queue:
		  queue.insert(0, f"{packet}{queue.popleft()}")


if __name__ == "__main__":
    # mutex = "FIubOp8mcEdS0i5b"
    # com = "bvUFyfn2d6e7YEJt9/zw/A=="

    parser = argparse.ArgumentParser("Script to decrypt XWorm communication")
    parser.add_argument("-m", "--mutex", help="Mutex holding the configuration decryption key")
    parser.add_argument("-c", "--com", help="Communication key (encrypted version)")

    args = parser.parse_args()

    main(mutex=args.mutex, com=args.com)
```
<div class="src-block-caption">
  <span class="src-block-number"><a href="#code-snippet--post-subtrees-collapsed">Code Snippet 2</a>:</span>
  Python script to decrypt XWorm communication
</div>

To dump the XWorm messages in cleartext from a PCAP, use the following command:

```bash
tshark -r /tmp/dump.pcapng -Y "tcp.port == 3395" -e tcp.payload -Tjson |
    jq -r ".[]._source.layers[][]" |
    python3 decrypt_xworm_com.py --mutex="FIubOp8mcEdS0i5b" --com="bvUFyfn2d6e7YEJt9/zw/A=="
```

_This sample of XWorm communicates on port `3395`_.

<a id="code-snippet--post-subtrees-collapsed"></a>
```text
b'INFO<Xwormmm>9623CE2085896DD4BD55<Xwormmm>Admin<Xwormmm> Windows 10 Pro 64bit<Xwormmm>XWorm V3.0<Xwormmm>23/02/2023<Xwormmm>False<Xwormmm>True<Xwormmm>False<Xwormmm>None'
b'PING!'
b'plugin<Xwormmm>179DCD0BAD17DB8E467A40D7B57437461CDC3263090966A687BDD40B279E4DF2<Xwormmm>0'
b'sendPlugin<Xwormmm>179DCD0BAD17DB8E467A40D7B57437461CDC3263090966A687BDD40B279E4DF2
	...
```
<div class="src-block-caption">
  <span class="src-block-number"><a href="#code-snippet--post-subtrees-collapsed">Code Snippet 3</a>:</span>
  Output of XWorm PCAP decryption by the Python script
</div>


## XWorm plugins {#xworm-plugins}

As introduced, XWorm has the capability to download and execute plugins. This mechanism is simple,
here is its workflow:

1.  The C2 send available plugins: `plugin<Xwormmm>Id of the plugin<Xwormmm>`
2.  The RAT ask the C2 to send the plugin: `sendPlugin<Xwormmm>Id of the plugin`
3.  The C2 send the plugin: `savePlugin<Xwormmm>Id of the plugin<Xwormmm>\x00\xc2\x07\x00<DLL .NET >`

Referred to [2](#figure--xworm-communication-hexdump) where the last packet (in the figure) received by the infected host has a size of `420736` bytes,
in fact this is a plugin sent by the C2.
This sample of XWorm downloads a plugin name _Recover.dll_ with the following [SHA-256: 179dcd0bad17db8e467a40d7b57437461cdc3263090966a687bdd40b279e4df2](https://bazaar.abuse.ch/sample/179dcd0bad17db8e467a40d7b57437461cdc3263090966a687bdd40b279e4df2),
the plugin attempts to loot passwords and other authentication items.

The script dumps messages whose size exceeds 1000 bytes into a file, which is useful to dump XWorm plugins downloaded from the C2.
