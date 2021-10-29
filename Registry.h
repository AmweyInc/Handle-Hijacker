#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <windows.h>
#include <string>
#include <assert.h>
#include <process.h>
class CRegistry
{
protected:
    HKEY _hKey;
    bool error_success;
    bool GetRegister(LPCSTR lpName, DWORD dwType, void* outBuf, DWORD size);
    bool SetRegister(LPCSTR lpName, DWORD dwType, void* inBuf, DWORD size);
    bool GetRegisterDefault(LPSTR outBuf, LONG maxSize);
    bool SetRegisterDefault(LPCSTR inBuf);
    bool DeleteRegister(LPCSTR lpName);
    bool AutoSizeWrite(DWORD dwType, void* inBuf, DWORD &size);
    bool AutoSizeRead(DWORD dwType, void* outBuf, DWORD &size);
    CRegistry(HKEY hKey, LPCSTR lpSubKey, bool mode);
    ~CRegistry();
};
class CEasyRegistry : CRegistry
{
public:
    bool no_error;
    bool ErrorSuccess();
    void WriteString(LPCSTR lpName, LPSTR lpString, ...);
    std::string ReadString(LPCSTR lpName);
    void WriteInteger(LPCSTR lpName, int value);
    int ReadInteger(LPCSTR lpName);
    void WriteFloat(LPCSTR lpName, float value);
    float ReadFloat(LPCSTR lpName);
    void WriteLongLong(LPCSTR lpName, long long value);
    long long ReadLongLong(LPCSTR lpName);
    void WriteDouble(LPCSTR lpName, double value);
    double ReadDouble(LPCSTR lpName);
    void DeleteKey(LPCSTR lpName);
    bool IsError();
    CEasyRegistry(HKEY hKey, LPCSTR lpSubKey, bool mode);
    ~CEasyRegistry();
};