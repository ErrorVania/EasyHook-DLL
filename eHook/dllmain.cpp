#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
#include "easyhook.h"

#pragma region util
DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}
BOOL verbose = FALSE;
#pragma endregion

#pragma region HookFunctions
BOOL WINAPI HOOK_Beep				( _In_ DWORD dwFreq, _In_ DWORD dwDuration) {
	if (verbose) {
		printf("beeped!");
	}
	
	
	DWORD FreqIncrement     = 1000;
	DWORD DurationIncrement = 1000;

	if (dwFreq < 0x7FFF - FreqIncrement && dwDuration < 0xFFFFFFFF - dwDuration) {
		return Beep(dwFreq + FreqIncrement, dwDuration + DurationIncrement);
	} else { return Beep(dwFreq, dwDuration); }
}
BOOL WINAPI HOOK_ReadProcessMemory	( _In_ HANDLE hProcess,	_In_ LPCVOID lpBaseAddress, _Out_ LPVOID  lpBuffer, _In_ SIZE_T nSize, _Out_ SIZE_T  *lpNumberOfBytesRead) {
	if (verbose) {
		printf("RPM");
	}

	std::wstring s = L"beeper.exe";

	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileNameEx(hProcess,NULL,buffer,MAX_PATH);
	std::wstring path = buffer;


	if (path.find(s) != std::wstring::npos) {
		SetLastError(ERROR_ACCESS_DENIED);
		return 0;
	}
	else {
		return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}
}
BOOL WINAPI HOOK_WriteProcessMemory	( _In_ HANDLE hProcess,	_In_ LPVOID  lpBaseAddress, _In_  LPCVOID lpBuffer, _In_ SIZE_T nSize, _Out_ SIZE_T  *lpNumberOfBytesWritten) {
	if (verbose) {
		printf("WPM");
	}

	std::wstring s = L"beeper.exe";

	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileNameEx(hProcess, NULL, buffer, MAX_PATH);
	std::wstring path = buffer;


	if (path.find(s) != std::wstring::npos) {
		SetLastError(ERROR_ACCESS_DENIED);
		return 0;
	}
	else {
		return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}
}
HANDLE		HOOK_OpenProcess		( _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwProcessId) {
	if (verbose) {
		printf("OP");
	}

	if (dwProcessId == FindProcessId(L"beeper.exe")) {
		SetLastError(ERROR_ACCESS_DENIED);
		return INVALID_HANDLE_VALUE;
	}
	else {
		return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	}
}
#pragma endregion

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	if ((DWORD)inRemoteInfo->UserData == 0xDEADBEEF && inRemoteInfo->UserDataSize == sizeof(DWORD)) { verbose = TRUE; }

	ULONG   ACLEntries[1] = { 0 };
	HMODULE KERNEL32 = GetModuleHandleA("kernel32");



	FARPROC Beep_Address               = GetProcAddress(KERNEL32, "Beep"			  );
	FARPROC ReadProcessMemory_Address  = GetProcAddress(KERNEL32, "ReadProcessMemory" );
	FARPROC WriteProcessMemory_Address = GetProcAddress(KERNEL32, "WriteProcessMemory");
	FARPROC OpenProcess_Address		   = GetProcAddress(KERNEL32, "OpenProcess"		  );


	HOOK_TRACE_INFO BeepHook_TraceInfo				 = { NULL };
	HOOK_TRACE_INFO ReadProcessMemoryHook_TraceInfo  = { NULL };
	HOOK_TRACE_INFO WriteProcessMemoryHook_TraceInfo = { NULL };
	HOOK_TRACE_INFO OpenProcessHook_TraceInfo		 = { NULL };

	NTSTATUS installBeepHook               = LhInstallHook(Beep_Address              , HOOK_Beep              , NULL, &BeepHook_TraceInfo				);
	NTSTATUS installReadProcessMemoryHook  = LhInstallHook(ReadProcessMemory_Address , HOOK_ReadProcessMemory , NULL, &ReadProcessMemoryHook_TraceInfo  );
	NTSTATUS installWriteProcessMemoryHook = LhInstallHook(WriteProcessMemory_Address, HOOK_WriteProcessMemory, NULL, &WriteProcessMemoryHook_TraceInfo );
	NTSTATUS installOpenProcesHook		   = LhInstallHook(OpenProcess_Address		 , HOOK_OpenProcess		  , NULL, &OpenProcessHook_TraceInfo		);

	LhSetExclusiveACL(ACLEntries, 1, &BeepHook_TraceInfo				);
	LhSetExclusiveACL(ACLEntries, 1, &ReadProcessMemoryHook_TraceInfo	);
	LhSetExclusiveACL(ACLEntries, 1, &WriteProcessMemoryHook_TraceInfo	);
	LhSetExclusiveACL(ACLEntries, 1, &OpenProcessHook_TraceInfo			);

	return;
}
