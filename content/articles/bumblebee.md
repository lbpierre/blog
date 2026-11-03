+++
title = "BumbleBee notes 🐝"
author = ["pbo"]
description = """
  BumbleBee is categorized as a ****Loader****, the malware is used by Initial Access Brokers to gain access
  in targeted companies. This article aims to summarizing the different TTPs observed in campaigns
  distributing BumbleBee and provides a script to extract its configuration.
  """
publishDate = 2023-03-29T00:00:00+02:00
tags = ["extractor", "loader"]
categories = ["RE"]
draft = false
+++

{{< figure src="/ox-hugo/bumblebee_head_image.png" >}}


## TL;DR BumbleBee {#tl-dr-bumblebee}

The loader delivers diverse payloads (_e.g: Cobalt Strike, ransomware, etc_), the operators of BumbleBee have been named _EXOTIC LILY_ by the TAG in a report published in March 2022.
{{% sidenote %}}
Google TAG article mentionned BumbleBee Loader (_e.g:_ The user-agent set to bumblebee, hence dubbed BUMBLEBEE.
<https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/>
{{% /sidenote %}} Moreover, similarities with other loaders in terms of operation have been noticed notably with IcedID and Emotet.
Code similarty (_hook installation_) with Trickbot have been observed and explained in the post [The chronicles of Bumblebee: The Hook, the Bee, and the Trickbot connection](https://elis531989.medium.com/the-chronicles-of-bumblebee-the-hook-the-bee-and-the-trickbot-connection-686379311056).
The malware is well documented by now (_March 2023_) as evidenced by the number of reports on [malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee).


## BumbleBee capabilities {#bumblebee-capabilities}

The malware has a custom unpacking mechanism, it manipulates hooks to setup its execution chain,
the loader uses multiple environment detection techniques because of the complete integration of the project [al-khaser](https://github.com/LordNoteworthy/al-khaser)
{{% sidenote %}}
al-khaser is a PoC "malware" application with good intentions that aims to stress your anti-malware system. It performs a bunch of common malware tricks with the goal of seeing if you stay under the radar.
{{% /sidenote %}} . It communicates with its command and control over HTTP. Since August 2022 the malware embeds a list of IP addresses in its configuration,
some of them are legitimate IP addresses, this technique is also used by other malware such as Emotet and Trickbot.

BumbleBee command and control IP addresses, port and the bot (or botnet) identifier are stored in the `.data` section, obfuscated with the _RC4_ encryption algorithm. A script to extract and deobfuscate
them is provided at the end of this post.


## Campaigns file format {#campaigns-file-format}

First malspam campaign which delivered BumbleBee contains a web link to a protected ZIP archive.

1.  The archive contains an ISO file;
2.  The ISO contains a LNK file and a DLL file;
3.  The LNK executes `rundll32.exe` to invoke the embedded DLL;

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/infection-chain-iso.png" caption="<span class=\"figure-number\">Figure 1: </span>BumbleBee infection chain with ISO file" >}}

This model of campaign was used for months. During the summer of 2022, actors updated the disk image format from ISO to VHD.
Content of disk image (_VHD_) changed too, the DLL is no more stored as a file, but it is embed obfuscated in a PowerShell script. The script is executed by
the LNK with the **execution policy** set to **bypass**. The BumbleBee's DLL is stored in the PowerShell script in obfuscated strings (_e.g:_ `$elem30=$elem30.$casda.Invoke(0,"H")`).
After strings replacement, the base64 encoded variable is decoded, decrompressed (`ungzip`) and invoked (_e.g:_ `scriptPath | iex`).

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/infection-chain-vhd.png" caption="<span class=\"figure-number\">Figure 2: </span>BumbleBee infection chain with VHD file" >}}

_NB: File sharing service used to deliver BumbleBee change regulary e.g.: WeTransfer, Onedrive, Smash, etc.
Details of a campaign using onedrive file sharing website are written in the article: [Bumblebee DocuSign Campaign](https://0xtoxin-labs.gitbook.io/malware-analysis/malware-analysis/bumblebee-docusign-campaign)._

**Examples IOCs**:

-   ISO: [SHA-256: 8695f4936f2942d322e2936106f78144f91602c7acace080e48c97e97b888377](https://bazaar.abuse.ch/sample/8695f4936f2942d322e2936106f78144f91602c7acace080e48c97e97b888377/)
-   VHD: [SHA-256: e9a1ce3417838013412f81425ef74a37608754586722e00cacb333ba88eb9aa7](https://bazaar.abuse.ch/sample/e9a1ce3417838013412f81425ef74a37608754586722e00cacb333ba88eb9aa7)


## Configuration extractor {#configuration-extractor}

As introduced above, the configuration is stored encrypted with the RC4 algorithm.
{{% sidenote %}}
RC4: Rivest Cipher 4, also known as ARC4: <https://en.wikipedia.org/wiki/RC4>
{{% /sidenote %}} The key is in cleartext in the binary and its length is repeatedly (for BumbleBee case) fixed to <span class="underline">10 characters</span>.

Here is the two functions that implement RC4 algorithm in BumbleBee:

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/bumblebee_prga.png" caption="<span class=\"figure-number\">Figure 3: </span>BumbleBee implemenation of PRGA of RC4 algorithm" >}}

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/bumblebee_ksa.png" caption="<span class=\"figure-number\">Figure 4: </span>BumbleBee implementation of KSA of RC4 algorithm" >}}

The key is stored at the end of the blob of data containing the encrypted list of IP addresses.
After analysing few samples of BumbleBee, it appears that the blob of data containing the IP addresses is always **4105 bytes** long (_plus one null byte_) which is
a pattern to look for in the DLL for a C2 extractor.

<a id="figure--post-subtrees-collapsed"></a>

{{< figure src="/ox-hugo/bumblebee_blob.png" caption="<span class=\"figure-number\">Figure 5: </span>Location of the blob and the RC4 key" >}}

The script below attempts to loop over data until a blob matches the blob size, then it extracts the RC4 key (the last 10 bytes of the blob)
to finally decrypt the data.

```python { linenos=true, linenostart=1 }
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ARC4


def decrypt_rc4(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt RC4 encrypt data, `pip install cryptography`"""

    algorithm = ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    cleartext = decryptor.update(ciphertext)

    return cleartext


def get_bumblebee_c2(data: bytes) -> bytes:
    """
    Command and Control are stored at the end of the .data section,
    the configuration of the obfuscated C2 and its associated RC4
    are stored in the same blob with a fixed lenght of
    4105 plus one null byte (4106).
    !\xac\xd2\xfe=;\x87\x94\xebP\x8e@\x08}\x00/^I\xd4\x86\xaf\xd2\x14-
    \x16\x89A\xa9uT\x00\xbduC\xb7\x9e~\x19\xac\x9f\xb4\x0f\xae>\xcc
    \x96S]\xb56\x93C\x9d*p\xed\xc9\x04:Oew\xc3*X`:a\xe0T\x8e\x93>\xf9
    \xf8\xe2\x17Q\x15b,8\xa8[\xf5N\x93\xffMM]\x8d\xec\xde\x13\x95z\xc3
    ...
    ...
    ... <redatacted> ...
    \xd4\x00\xa1xZ:\x1e\x90\x00X\xea\xca\x0c\'\xee\xffOR5tw\xc0I\x86R"!
    \xf8\xa3\x87\xc8\x16Mo_5\x82_\x81\x9f<RC4 key composed by 10 bytes>
    """

    c2 = b""

    for blob in map(lambda x: x.strip(b"\x00"), data.split(b"\x00" * 4)):
	  if len(blob) == 4106:
	      key = blob[-10:]
	      ciphertext = blob[:-10]
	      c2 = decrypt_rc4(key, ciphertext)
	      c2 = c2.replace(b"\x00", b"")
	      print(f"BumbleBee Command and Control IoCs: {c2}")

    return c2


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
	  get_bumblebee_c2(f.read())
```
<div class="src-block-caption">
  <span class="src-block-number">Code Snippet 1:</span>
  BumbleBee C2 extractor
</div>

_PS: Tested with the package `cryptography` with the version: `3.4.8`._

Go head and re-use, adapt the script for your needs!


## Resources {#resources}

-   <https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/>
-   <https://elis531989.medium.com/the-chronicles-of-bumblebee-the-hook-the-bee-and-the-trickbot-connection-686379311056>
-   <https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee>
-   <https://0xtoxin-labs.gitbook.io/malware-analysis/malware-analysis/bumblebee-docusign-campaign>
