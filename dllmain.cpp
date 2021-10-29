#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4244)
#pragma warning(disable : 4005)
#pragma warning(disable : 4477)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)
#pragma warning(disable : 4313)
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>
#include "Registry.h"
#pragma comment(lib, "Psapi.lib")
using namespace std;
DWORD_PTR hookAddr, origAddr;
DWORD __stdcall ExceptionFilter(EXCEPTION_POINTERS *pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
#ifdef _WIN64
        if (pExceptionInfo->ContextRecord->Rip == origAddr) pExceptionInfo->ContextRecord->Rip = hookAddr;
#else
        if (pExceptionInfo->ContextRecord->Eip == origAddr) pExceptionInfo->ContextRecord->Eip = hookAddr;
#endif
        pExceptionInfo->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        DWORD dwOld; VirtualProtect((void*)origAddr, 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
void SetupVEH(DWORD_PTR funcAddr, DWORD_PTR hookedFunc)
{
    hookAddr = hookedFunc; origAddr = funcAddr;
    AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)ExceptionFilter);
    DWORD dwOld; VirtualProtect((void*)origAddr, 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld);
}
void DeleteVEH()
{
    DWORD dwOld; VirtualProtect((void*)origAddr, 1, PAGE_EXECUTE_READWRITE, &dwOld);
    RemoveVectoredExceptionHandler(ExceptionFilter);
}
typedef HANDLE(__stdcall *CallRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
CallRemoteThread CRT = nullptr;
HANDLE __stdcall HookRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)
{
    auto strdel = [](char *s, size_t offset, size_t count) -> char*
    {
        size_t len = strlen(s);
        if (offset > len) return s;
        if ((offset + count) > len) count = len - offset;
        strcpy(s + offset, s + offset + count);
        return s;
    };
    auto GetExternalProcName = [&, strdel](HANDLE hProc) -> string
    {
        CHAR szFileName[MAX_PATH + 1];
        K32GetModuleFileNameExA(hProc, NULL, szFileName, MAX_PATH + 1);
        char fname[256]; char *ipt = strrchr(szFileName, '\\');
        memset(fname, 0, sizeof(fname));
        strdel(szFileName, 0, (ipt - szFileName + 1));
        strncpy(fname, szFileName, strlen(szFileName));
        std::string ProcName(fname);
        return ProcName;
    };
    DeleteVEH();
    HANDLE hRet = CRT(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress,
    lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
    if (!strcmp(GetExternalProcName(hProcess).c_str(), "proxy_sa.exe") ||
    !strcmp(GetExternalProcName(hProcess).c_str(), "gta_sa.exe"))
    {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        if (hProc)
        {
            CEasyRegistry *reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\MftJacker", false);
            reg->WriteInteger("Hijacked", 0x1);
            CloseHandle(hProc);
        }
    }
    else SetupVEH((DWORD)CRT, (DWORD)&HookRemoteThread);
    return hRet;
}
void EntryPoint()
{
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
    CRT = (CallRemoteThread)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CreateRemoteThreadEx");
    SetupVEH((DWORD)CRT, (DWORD)&HookRemoteThread);
}
int __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        EntryPoint();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DeleteVEH();
        break;
    }
    return 1;
}