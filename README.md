# DriversCloud BYOVD

`DriversCloud_amd64.sys` by CybelSoft exposes arbitrary physical memory read and MSR write with no access controls. The device is created with a null security descriptor. Any process, including low-integrity sandboxed processes, can open a handle.

WHQL signed. Not on the HVCI blocklist. 0/68 AV detections at time of discovery.

## Driver

| Field | Value |
|-------|-------|
| Vendor | CYBELSOFT EURL |
| Product | DriversCloud |
| SHA256 | `2BC72D11FA0BEDA25DC1DBC372967DB49BD3C3A3903913F0877BFF6792724DFE` |
| Device | `\\.\DriversCloud_amd64` |
| Transfer | METHOD_BUFFERED |
| LOLDrivers | [magicsword-io/LOLDrivers#284](https://github.com/magicsword-io/LOLDrivers/issues/284) |
| CVE | Requested (MITRE) |

## Primitives

Three IOCTLs are used directly:

**`0x80FF2010` — Arbitrary physical memory read**
Maps a user-supplied physical address via `MmMapIoSpace` and copies up to 2 MB back to the caller. No address validation. No size validation beyond a 2 MB cap.

**`0x80FF2024` — Arbitrary MSR read**
Reads any MSR via `rdmsr`. Used to leak `IA32_LSTAR` (KiSystemCall64) and save `IA32_FMASK` before modification.

**`0x80FF2040` — Arbitrary MSR write**
Writes any MSR via `wrmsr`. No whitelist, no index restriction. Writing `IA32_LSTAR` (0xC0000082) redirects every syscall on the core to any address.

**Kernel write primitive via LSTAR hijack**
Chain: read LSTAR via `0x80FF2024`, clear AC bit in FMASK via `0x80FF2040`, write gadget address into LSTAR via `0x80FF2040`, issue `SYSCALL`. CPU enters ring 0 at the gadget. ROP chain atomically restores LSTAR via `wrmsr` then returns to ring 3 via `iretq`. Thread is pinned to core 0 at REALTIME priority for the duration. Zero crashes across all test runs.

Gadgets scanned from ntoskrnl.exe on disk, rebased to runtime VA:
- `mov [rdx],rax; ret` (48 89 02 C3) — write gadget
- `mov rax,[rdx]; ret` (48 8B 02 C3) — read gadget
- `pop rcx; ret` (59 C3)
- `pop rax; ret` (58 C3)
- `pop rdx; ret` (5A C3)
- `wrmsr; ret` (0F 30 C3)
- `iretq` (48 CF)

Physical write is done via PTE remapping: overwrite a scratch page's PTE to point at the target physical page, write through the remapped VA, restore the original PTE.

## Build

Requires Visual Studio x64 Native Tools Command Prompt (ml64 + cl in PATH).

```
build.bat
```

Output: `driverscloud_rw.exe`

## Requirements

- Windows 10/11 x64
- Administrator
- HVCI disabled

## Credit

X: @weezerOSINT / Telegram: @weezer
