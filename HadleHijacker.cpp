#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4244)
#pragma warning(disable : 4005)
#pragma warning(disable : 4477)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)
#pragma warning(disable : 4313)
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <direct.h>
#include <thread>
#include <TlHelp32.h>
#include <intrin.h>
#include "Registry.h"
using namespace std;
string RandomString(int len)
{
    srand(time(0));
    string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    string newstr; int pos;
    while (newstr.size() != len)
    {
        pos = (rand() % 61);
        newstr += str.substr(pos, 1);
    }
    return newstr;
}
DWORD GetProcId(const char* ProcName)
{
    PROCESSENTRY32 pe32; HANDLE hSnapshot = NULL;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            if (strstr(pe32.szExeFile, ProcName) != nullptr)
            {
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    return -1;
}
#ifndef byte
typedef unsigned char byte;
#endif
typedef DWORD COMPATIBLE_DWORD;
typedef uint32_t uint_compatible;
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);
typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT;
static DWORD __stdcall CustomEntryPoint(PVOID p)
{
    PMANUAL_INJECT ManualInject; HMODULE hModule = NULL;
    DWORD i, Function, count, delta;
    PDWORD ptr; PWORD list;
    PIMAGE_BASE_RELOCATION pIBR;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PIMAGE_IMPORT_BY_NAME pIBN;
    PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;
    PDLL_MAIN EntryPoint;
    ManualInject = (PMANUAL_INJECT)p;
    pIBR = ManualInject->BaseRelocation;
    delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);
    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            list = (PWORD)(pIBR + 1);
            for (i = 0; i < count; i++)
            {
                if (list[i])
                {
                    ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }
        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }
    pIID = ManualInject->ImportDirectory;
    while (pIID->Characteristics)
    {
        OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);
        hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);
        if (!hModule)
        {
            return FALSE;
        }
        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
                if (!Function)
                {
                    return FALSE;
                }
                FirstThunk->u1.Function = Function;
            }
            else
            {
                pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                if (!Function)
                {
                    return FALSE;
                }
                FirstThunk->u1.Function = Function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        pIID++;
    }
    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }
    return TRUE;
}
static DWORD __stdcall EntryPointEnd()
{
    return 0;
}
void HijackThreadContext(HANDLE hProcess, DWORD ProcID, DWORD struct_address, DWORD loader_address)
{
    DWORD retAddr = 0x0; LPVOID ShellCode = VirtualAllocEx(hProcess, 0, 20, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    auto GetThreadID = [&, ProcID]() -> DWORD
    {
        THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (Thread32First(hSnapshot, &th32))
        {
            do
            {
                if (th32.th32OwnerProcessID != ProcID) continue;
                return th32.th32ThreadID;
            } while (Thread32Next(hSnapshot, &th32));
        }
        if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
        return 0;
    };
    HANDLE pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetThreadID());
    if (pThread)
    {
        SuspendThread(pThread); CONTEXT ctx; ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(pThread, &ctx); retAddr = ctx.Eip; ctx.Eip = (DWORD)ShellCode;
        byte SaveRegisters[] = { 0x60, 0x66, 0x60 };
        byte PushEAX[] = { 0x68, 0x90, 0x90, 0x90, 0x90 };
        byte CallDWORD[] = { 0xE8, 0x54, 0x50, 0xCE, 0x0F };
        byte RestoreRegisters[] = { 0x66, 0x61, 0x61 };
        byte JmpEIP[] = { 0xE9, 0x25, 0x00, 0xA8, 0xCE };
        auto FindDelta = [](DWORD DestinyAddress, DWORD SourceAddress, size_t InstructionLength) -> uint32_t
        {
            return DestinyAddress - (SourceAddress + InstructionLength);
        };
        memcpy(&PushEAX[1], &struct_address, 4); DWORD Delta = FindDelta(loader_address,
            ((DWORD)ShellCode + sizeof(SaveRegisters) + sizeof(PushEAX)), sizeof(CallDWORD));
        memcpy(&CallDWORD[1], &Delta, 4); Delta = FindDelta(retAddr, ((DWORD)ShellCode + sizeof(SaveRegisters) + sizeof(PushEAX) +
            sizeof(CallDWORD) + sizeof(RestoreRegisters)), sizeof(JmpEIP)); memcpy(&JmpEIP[1], &Delta, 4);
        WriteProcessMemory(hProcess, ShellCode, SaveRegisters, sizeof(SaveRegisters), NULL);
        WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode + sizeof(SaveRegisters)), PushEAX, sizeof(PushEAX), NULL);
        WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode + sizeof(SaveRegisters) + sizeof(PushEAX)), CallDWORD, sizeof(CallDWORD), NULL);
        WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode + sizeof(SaveRegisters) + sizeof(PushEAX) + sizeof(CallDWORD)),
            RestoreRegisters, sizeof(RestoreRegisters), NULL); WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode +
                sizeof(SaveRegisters) + sizeof(PushEAX) + sizeof(CallDWORD) + sizeof(RestoreRegisters)), JmpEIP, sizeof(JmpEIP), NULL);
        SetThreadContext(pThread, &ctx); ResumeThread(pThread); CloseHandle(pThread);
    }
}
int main()
{
    SetConsoleTitleA(RandomString(rand() % 16 + 1).c_str());
    setlocale(LC_ALL, "russian"); system("color 03");
    DWORD ProcessId = -1;
    char dllname[256]; memset(dllname, 0, 256); _getcwd(dllname, 256);
    strcat(dllname, "\\Hijacker.dll"); // указываем путь DLL хайжакера
    char procName[] = { "Multi Theft Auto.exe" };
    printf("\nSearch of target process...\n");
    auto EnableDebugPrivilege = [](bool fEnable) -> bool
    {
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
            tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
            AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
            CloseHandle(hToken);
        }
        return true;
    }; EnableDebugPrivilege(true);
    while (GetProcId(procName) == -1) { Sleep(1); }
    ProcessId = GetProcId(procName);
    printf("Finded ProcID: %d\n", ProcessId);
    PIMAGE_DOS_HEADER pIDH; PIMAGE_NT_HEADERS pINH;
    PIMAGE_SECTION_HEADER pISH; HANDLE hProcess;
    HANDLE hFile; PVOID image, mem;
    DWORD i, FileSize, read; MANUAL_INJECT ManualInject;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (!hProcess)
    {
        while (!hProcess)
        {
            ProcessId = GetProcId(procName);
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
        }
    }
    else printf("Opened process handle: 0x%X\n", hProcess);
    hFile = CreateFileA(dllname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\nError: Unable to open the DLL (%d)\n", GetLastError());
        system("pause");
    }
    FileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        printf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());
        CloseHandle(hFile);
        system("pause");
    }
    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        printf("\nError: Unable to read the DLL (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        system("pause");
    }
    CloseHandle(hFile);
    pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\nError: Invalid executable image.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        system("pause");
    }
    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("\nError: Invalid PE header.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        system("pause");
    }
    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        printf("\nError: The image is not DLL.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        system("pause");
    }
    printf("\nAllocating memory for the headers.\n");
    image = VirtualAllocEx(hProcess, 0, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        printf("\nError: Unable to allocate memory for the headers (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
    }
    printf("\nMemory allocated at 0x%llx\n", image);
    printf("\nCopying headers into target process.\n");
    BOOL rslt = WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL);
    if (!rslt)
    {
        printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
    }
    else printf("Headers writed at: 0x%llx\n", image);
    pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);
    printf("\nCopying sections to target process.\n");
    for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
        printf("PE Section %d writed at: 0x%llx\n", i, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress));
    }
    printf("\nAllocating memory for loader stub.\n");
    mem = VirtualAllocEx(hProcess, 0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
    {
        printf("\nError: Unable to allocate memory for loader stub (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
    }
    printf("\nMemory for loader stub allocated at 0x%llx\n", mem);
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT)); ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;
    printf("\nWriting loader structure to target process.\n");
    BOOL zbm = WriteProcessMemory(hProcess, mem, &ManualInject, sizeof(MANUAL_INJECT), NULL);
    if (zbm) printf("Loader structure writed at: 0x%llx\n", mem);
    else
    {
        printf("Failed to write loader structure. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
    }
    PVOID stub = VirtualAlloc(0, ((DWORD)EntryPointEnd - (DWORD)CustomEntryPoint), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(stub, &CustomEntryPoint, ((DWORD)EntryPointEnd - (DWORD)CustomEntryPoint));
    BOOL stb = WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem + 1), stub, ((DWORD)EntryPointEnd - (DWORD)CustomEntryPoint), NULL);
    if (stb) printf("Loader stub writed at: 0x%llx\n", ((PMANUAL_INJECT)mem + 1));
    else
    {
        printf("Failed to write loader stub code. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
    }
    printf("\nErasing DOS-Headers into DLL...\n");
    PVOID dos_header = VirtualAlloc(0, sizeof(IMAGE_DOS_HEADER), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(dos_header, buffer, sizeof(IMAGE_DOS_HEADER));
    for (int i = 0; i < sizeof(IMAGE_DOS_HEADER); i++) *(BYTE*)((BYTE*)dos_header + i) = 0x90;
    rslt = WriteProcessMemory(hProcess, image, dos_header, sizeof(IMAGE_DOS_HEADER), NULL);
    if (!rslt)
    {
        printf("\nError: Unable to erase DOS-Header into target process (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
    }
    HANDLE myHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    printf("DOS-Header successfully erased! Size: %d\n", sizeof(IMAGE_DOS_HEADER));
    printf("\nExecuting loader stub code...\n");
    printf("\nMapped at 0x%x\n", image);
    CEasyRegistry *reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\MftJacker", true);
    reg->WriteInteger("Hijacked", 0x0);
    HijackThreadContext((HANDLE)hProcess, ProcessId, (COMPATIBLE_DWORD)mem, (COMPATIBLE_DWORD)((PMANUAL_INJECT)mem + 1));
    printf("\nDLL injected at 0x%llx\n", image);
    if (pINH->OptionalHeader.AddressOfEntryPoint)
    {
        printf("\nDLL entry point: 0x%llx\n", (PVOID)((LPBYTE)image + pINH->OptionalHeader.AddressOfEntryPoint));
    }
    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    while (reg->ReadInteger("Hijacked") != 0x1) { Sleep(1); }
    DWORD procID = GetProcId("proxy_sa.exe");
    HANDLE mtaProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    procID = GetProcId("gta_sa.exe");
    if (!mtaProc) mtaProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (mtaProc)
    {
        printf("SUCCESSFULL HIJACKING!\n");
        CloseHandle(mtaProc);
    }
    else printf("FAILED ON HIJACKING!\n");
    reg->WriteInteger("Hijacked", 0x0);
    system("pause");
    return 1;
}