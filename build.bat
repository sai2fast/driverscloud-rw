@echo off
REM Build DriversCloud R/W POC — requires VS x64 Native Tools Command Prompt
REM Or run from a shell with vcvarsall.bat x64 sourced.

where ml64 >nul 2>&1
if errorlevel 1 (
    echo [!] ml64 not found. Run from "x64 Native Tools Command Prompt for VS"
    exit /b 1
)

echo [*] Assembling syscall_trampoline.asm ...
ml64 /nologo /c /Fo syscall_trampoline.obj syscall_trampoline.asm
if errorlevel 1 ( echo [-] MASM failed & exit /b 1 )

echo [*] Compiling driverscloud_rw.cpp ...
cl /nologo /EHsc /W4 /O2 driverscloud_rw.cpp syscall_trampoline.obj advapi32.lib psapi.lib /Fe:driverscloud_rw.exe
if errorlevel 1 ( echo [-] CL failed & exit /b 1 )

echo [+] Build OK: driverscloud_rw.exe
