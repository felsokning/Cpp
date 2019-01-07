// UnmanagedDebugging.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")

// Struct used for the array declaration below.
typedef struct _STR_ARRAY
{
	CHAR Desc[32];
} STR_ARRAY;

// Human-readable names for the different synchronization types.
STR_ARRAY STR_OBJECT_TYPE[] =
{
	{ "CriticalSection" },
	{ "SendMessage" },
	{ "Mutex" },
	{ "AdvancedLocalProcedureCall" },
	{ "COM" },
	{ "ThreadWait" },
	{ "ProcWait" },
	{ "Thread" },
	{ "ComActivation" },
	{ "Unknown" },
	{ "Max" }
};

// Global variable to store the WCT session handle
HWCT g_WctHandle = NULL;

// Global variable to store OLE32.DLL module handle.
HMODULE g_Ole32Hnd = NULL;

// Global variable used to pass back to the Marshalled caller.
//wchar_t* OutString;
std::wstring OutString = std::wstring();

/*++
	Define the method.
++*/
void
PrintWaitChain(
	__in DWORD ThreadId
);

BOOL
InitCOMAccess()
/*++

Routine Description:

	Register COM interfaces with WCT. This enables WCT to provide wait
	information if a thread is blocked on a COM call.

--*/
{
	PCOGETCALLSTATE			CallStateCallback;
	PCOGETACTIVATIONSTATE	ActivationStateCallback;

	// Get a handle to OLE32.DLL. You must keep this handle around
	// for the life time for any WCT session.
	g_Ole32Hnd = LoadLibrary(L"ole32.dll");
	if (!g_Ole32Hnd)
	{
		OutString.append(L"ERROR: GetModuleHandle failed: 0x%X\n", GetLastError());
		return FALSE;
	}

	// Retrieve the function addresses for the COM helper APIs.
	CallStateCallback = (PCOGETCALLSTATE)GetProcAddress(g_Ole32Hnd, "CoGetCallState");
	if (!CallStateCallback)
	{
		OutString.append(L"ERROR: GetProcAddress failed: 0x%X\n", GetLastError());
		return FALSE;
	}

	ActivationStateCallback = (PCOGETACTIVATIONSTATE)GetProcAddress(g_Ole32Hnd, "CoGetActivationState");
	if (!ActivationStateCallback)
	{
		OutString.append(L"ERROR: GetProcAddress failed: 0x%X\n", GetLastError());
		return FALSE;
	}

	// Register these functions with WCT.
	RegisterWaitChainCOMCallback(CallStateCallback, ActivationStateCallback);
	return TRUE;
}

BOOL
GrantDebugPrivilege()
/*++

Routine Description:

	Enables the debug privilege (SE_DEBUG_NAME) for the process.
	This is necessary if we want to retrieve wait chains for processes
	not owned by the current user.

Arguments:

	None.

Return Value:

	TRUE if this privilege could be enabled; FALSE otherwise.

--*/
{
	BOOL                fSuccess = FALSE;
	HANDLE              TokenHandle = INVALID_HANDLE_VALUE;
	TOKEN_PRIVILEGES    TokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&TokenHandle))
	{
		OutString.append(L"Could not get the process token. Error (0X%x)\n", GetLastError());
		goto Cleanup;
	}

	TokenPrivileges.PrivilegeCount = 1;

	if (!LookupPrivilegeValue(NULL,
		SE_DEBUG_NAME,
		&TokenPrivileges.Privileges[0].Luid))
	{
		OutString.append(L"Couldn't lookup the SeDebugPrivilege name. Error (0X%x)\n", GetLastError());
		goto Cleanup;
	}

	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(TokenHandle,
		FALSE,
		&TokenPrivileges,
		sizeof(TokenPrivileges),
		NULL,
		NULL))
	{
		OutString.append(L"Could not revoke the debug privilege. Error (0X%x)\n", GetLastError());
		goto Cleanup;
	}

	fSuccess = TRUE;
	goto Cleanup;


Cleanup:
	if (TokenHandle)
	{
		CloseHandle(TokenHandle);
	}

	return fSuccess;
}

HANDLE
GetProcessHandle(
	__in DWORD	ProcId
)
/*++

Routine Description:

	Obtains a handle to the process specified by the caller.

Arguments:

	ProcId--Specifies the process ID to obtain the handle for.

Return Value:

	A handle to the process specified. Otherwise, INVALID_HANDLE_VALUE for the fact the handle was unable to be obtained.

--*/
{
	HANDLE      processHandle = INVALID_HANDLE_VALUE;
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcId);
	if (processHandle == NULL || processHandle == INVALID_HANDLE_VALUE)
	{
		std::string test = std::string();
		test = "We were unable to obtain the handle for the process specified. Error: ";
		test += std::to_string(GetLastError());
		std::wstring testing = std::wstring(test.begin(), test.end());
		OutString.append(testing);
	}

	// Caller is responsible for disposable.
	return processHandle;
}

HANDLE
GetProcessSnapShotHandle(
	__in HANDLE Process
)
{
	HANDLE snapShotHandle = INVALID_HANDLE_VALUE;
	std::string test = std::string();
	std::wstring testing = std::wstring();

	snapShotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(Process));
	if (snapShotHandle == INVALID_HANDLE_VALUE)
	{
		test = "We were unable to obtain the snapshot handle for the process specified. Error: ";
		test += std::to_string(GetLastError());
		testing = std::wstring(test.begin(), test.end());
		OutString.append(testing);
	}

	return snapShotHandle;
}

void
WalkThreadsAndPrintChains(
	__in HANDLE process,
	__in HANDLE processSnapShot
)
{
	THREADENTRY32	thread;
	thread.dwSize = sizeof(thread);
	DWORD processId = GetProcessId(process);

	// No point in continuing if we can't get in.
	if (Thread32First(processSnapShot, &thread))
	{
		// Walk the thread list and print each wait chain
		do
		{
			if (thread.th32OwnerProcessID == processId)
			{
				// Open a handle to this specific thread
				HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread.th32ThreadID);
				if (threadHandle != NULL)
				{
					// Check whether the thread is still running
					DWORD exitCode;
					GetExitCodeThread(threadHandle, &exitCode);

					if (exitCode == STILL_ACTIVE)
					{
						// Print the wait chain.
						PrintWaitChain(thread.th32ThreadID);
					}

					// Always close your handles for SCIENCE!
					CloseHandle(threadHandle);
				}
			}
		} while (Thread32Next(processSnapShot, &thread));
	}
}

void
PrintWaitChain(
	__in DWORD ThreadId
)
/*++

Routine Description:

	Enumerates only the threads for a given process in the system.
	It the calls the WCT API on each thread.

Arguments:

	ThreadId--Specifies the thread ID to analyze.

Return Value:

	(none)

--*/
{
	WAITCHAIN_NODE_INFO		NodeInfoArray[WCT_MAX_NODE_COUNT];
	DWORD					Count, i;
	BOOL					IsCycle;

	std::string ts = std::to_string(ThreadId);
	ts += "	";
	std::wstring test = std::wstring(ts.begin(), ts.end());
	OutString.append(test);

	Count = WCT_MAX_NODE_COUNT;

	// Make a synchronous WCT call to retrieve the wait chain.
	if (!GetThreadWaitChain(g_WctHandle,
		NULL,
		WCTP_GETINFO_ALL_FLAGS,
		ThreadId,
		&Count,
		NodeInfoArray,
		&IsCycle))
	{
		OutString.append(L"Received error in GetThreadWaitChain call: (0X%x)\n", GetLastError());
		return;
	}

	// Check if the wait chain is too big for the array we passed in.
	if (Count > WCT_MAX_NODE_COUNT)
	{
		OutString.append(L"Found additional nodes beyond allowed count: %d\n", Count);
		Count = WCT_MAX_NODE_COUNT;
	}

	// Loop over all the nodes returned and print useful information.
	for (i = 0; i < Count; i++)
	{
		std::string test = std::string();
		std::wstring testing = std::wstring();
		switch (NodeInfoArray[i].ObjectType)
		{
		case WctThreadType:
			// A thread node contains process and thread ID.
			test = "[";
			test += std::to_string(NodeInfoArray[i].ThreadObject.ProcessId) + ":";
			test += std::to_string(NodeInfoArray[i].ThreadObject.ThreadId) + ":";
			test += (NodeInfoArray[i].ObjectStatus == WctStatusBlocked) ? "blocked" : "running";
			test += "]->";
			testing = std::wstring(test.begin(), test.end());
			OutString.append(testing);
			break;

		default:
			// It is a synchronization object and some of these objects have names.
			if (NodeInfoArray[i].LockObject.ObjectName[0] != L'\0')
			{
				test = "[";
				test += STR_OBJECT_TYPE[NodeInfoArray[i].ObjectType - 1].Desc;
				test += ":";
				WCHAR * objName = NodeInfoArray[i].LockObject.ObjectName;
				char ch[260];
				char DefChar = ' ';
				WideCharToMultiByte(CP_ACP, 0, objName, -1, ch, 260, &DefChar, NULL);
				test += std::string(ch);
				test += "]->";
				testing = std::wstring(test.begin(), test.end());
				OutString.append(testing);
			}
			else
			{
				test = "[";
				test += STR_OBJECT_TYPE[NodeInfoArray[i].ObjectType - 1].Desc;
				test += "]->";
				testing = std::wstring(test.begin(), test.end());
				OutString.append(testing);
			}
			if (NodeInfoArray[i].ObjectStatus == WctStatusAbandoned)
			{
				OutString.append(L"<abandoned>");
			}
			break;
		}
	}

	OutString.append(L"[End]");

	// Did we find a deadlock?
	if (IsCycle)
	{
		OutString.append(L" !!!Deadlock!!! ");
	}

	OutString.append(L"\n");
}

extern "C" __declspec(dllexport) LPCWSTR _cdecl
WctEntry(
	__in DWORD procId
)
/*++

Routine Description:

  Main entry point for this application.

--*/
{
	OutString = L"";
	HANDLE processHandle = INVALID_HANDLE_VALUE;
	HANDLE processSnapShotHandle = INVALID_HANDLE_VALUE;

	// Initialize the WCT interface to COM. Fail if this fails.
	if (!InitCOMAccess())
	{
		OutString.append(L"Could not enable COM access\n");
		goto Cleanup;
	}

	// Open a synchronous WCT session.
	g_WctHandle = OpenThreadWaitChainSession(0, NULL);
	if (g_WctHandle == NULL || g_WctHandle == INVALID_HANDLE_VALUE)
	{
		OutString.append(L"ERROR: OpenThreadWaitChainSession failed\n");
		goto Cleanup;
	}

	if (GrantDebugPrivilege())
	{
		processHandle = GetProcessHandle(procId);
		if (processHandle != NULL || processHandle != INVALID_HANDLE_VALUE)
		{
			processSnapShotHandle = GetProcessSnapShotHandle(processHandle);
			if (processSnapShotHandle != NULL || processSnapShotHandle != INVALID_HANDLE_VALUE)
			{
				// Only enumerate threads in the specified process.
				WalkThreadsAndPrintChains(processHandle, processSnapShotHandle);
				goto Cleanup;
			}
			goto Cleanup;
		}
	}
	else
	{
		OutString.append(L"ERROR: GrantDebugPrivilege failed\n");
		goto Cleanup;
	}


	// Close the WCT session.
	CloseThreadWaitChainSession(g_WctHandle);

Cleanup:

	if (NULL != g_Ole32Hnd)
	{
		FreeLibrary(g_Ole32Hnd);
	}

	// Don't want to leak handles with every run.
	CloseHandle(processHandle);
	CloseHandle(processSnapShotHandle);

	// Because Native Run-time controls the lifetime of the std::wstring object,
	// we must copy it to a structure that .NET can Marshal the pointer to and will
	// "live" outside of the lifetime of the native instance.
	// To demonstrate this problem, try returning the std::wstring as a wchar_t* and
	// notice that you'll hit a NullReferencePointer or a MemoryAccessViolation when
	// trying to return that object directly back to the .NET caller.
	LPCWSTR newLPWSTR = LPCWSTR(OutString.c_str());
	return newLPWSTR;
}