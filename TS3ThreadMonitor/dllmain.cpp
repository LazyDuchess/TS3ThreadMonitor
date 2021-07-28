#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <sstream>
#include <fstream>

FARPROC functionAddress = NULL;
FARPROC functionAddress2 = NULL;
SIZE_T bytesWritten = 0;
char originalBytes[6] = {};
char newBytes[6] = {};
char originalBytes2[6] = {};
char newBytes2[6] = {};

HANDLE _stdcall HookCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId)
{
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)functionAddress2, originalBytes2, sizeof(originalBytes2), &bytesWritten);
	HANDLE result = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)functionAddress2, newBytes2, sizeof(newBytes2), &bytesWritten);
	int threadId = GetThreadId(result);
	int priority = GetThreadPriority(result);
	std::cout << "Creating new thread with ID " << std::dec << threadId << " (" << std::hex << threadId << "), priority " << std::dec << priority << " (" << std::hex << priority << ")" << std::endl;
	return result;
}

BOOL _stdcall HookSetThreadPriority(HANDLE hThread, int nPriority)
{
	int threadId = GetThreadId(hThread);
	std::cout << "Set Priority " << std::dec << nPriority << " (" << std::hex << nPriority << ") on Thread ID " << std::dec << threadId << " (" << std::hex << threadId << ")" << std::endl;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)functionAddress, originalBytes, sizeof(originalBytes), &bytesWritten);
	BOOL result = SetThreadPriority(hThread, nPriority);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)functionAddress, newBytes, sizeof(newBytes), &bytesWritten);
	return result;
}

inline bool exists(const std::wstring& name) {
	struct _stat buffer;
	return (_wstat(name.c_str(), &buffer) == 0);
}

int stuff()
{
	AllocConsole();
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
	wchar_t wcs[MAX_PATH];
	GetFullPathName(L"sign.txt", MAX_PATH, wcs, NULL);
	if (exists(wcs))
	{
		std::wifstream file(wcs);
		std::wstring str;
		while (std::getline(file, str))
		{
			if (wcslen(str.c_str()) > 0)
			{
				wprintf(str.c_str());
				std::cout << std::endl;
			}
		}
		file.close();
	}
	HINSTANCE library = GetModuleHandleA("kernel32.dll");
	SIZE_T bytesRead = 0;
	functionAddress = GetProcAddress(library, "SetThreadPriority");
	functionAddress2 = GetProcAddress(library, "CreateThread");
	std::cout << "Hooking Address " << std::hex << functionAddress << std::endl;
	std::cout << "Hooking Address " << std::hex << functionAddress2 << std::endl;

	ReadProcessMemory(GetCurrentProcess(), functionAddress, originalBytes, 6, &bytesRead);
	ReadProcessMemory(GetCurrentProcess(), functionAddress2, originalBytes2, 6, &bytesRead);

	// create a patch "push <address of new func>; ret"

	void* hookedFuncAddress = &HookSetThreadPriority;

	memcpy_s(newBytes, 1, "\x68", 1);
	memcpy_s(newBytes + 1, 4, &hookedFuncAddress, 4);
	memcpy_s(newBytes + 5, 1, "\xC3", 1);

	hookedFuncAddress = &HookCreateThread;

	memcpy_s(newBytes2, 1, "\x68", 1);
	memcpy_s(newBytes2 + 1, 4, &hookedFuncAddress, 4);
	memcpy_s(newBytes2 + 5, 1, "\xC3", 1);

	WriteProcessMemory(GetCurrentProcess(), (LPVOID)functionAddress, newBytes, sizeof(newBytes), &bytesWritten);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)functionAddress2, newBytes2, sizeof(newBytes2), &bytesWritten);

	return 0;
}

DWORD WINAPI MainThread(LPVOID param) {
	stuff();
	FreeLibraryAndExitThread((HMODULE)param,0);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		
		CreateThread(0, 0, &MainThread, 0, 0, 0);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
