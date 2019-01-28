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
STR_ARRAY str_object_type[] =
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
HWCT g_WctHandle = nullptr;

// Global variable to store OLE32.DLL module handle.
HMODULE g_Ole32Hnd = nullptr;

// Global variable used to pass back to the caller.
//wchar_t* OutString;
std::wstring out_string = std::wstring();

/*++
	Define the method.
++*/
void
print_wait_chain(
	__in DWORD thread_id
);

BOOL
init_com_access()
/*++

Routine Description:

	Register COM interfaces with WCT. This enables WCT to provide wait
	information if a thread is blocked on a COM call.

--*/
{
	// Get a handle to OLE32.DLL. You must keep this handle around
	// for the life time for any WCT session.
	g_Ole32Hnd = LoadLibrary(L"ole32.dll");
	if (!g_Ole32Hnd)
	{
		out_string.append(L"ERROR: GetModuleHandle failed: 0x%X\n", GetLastError());
		return FALSE;
	}

	// Retrieve the function addresses for the COM helper APIs.
	// ReSharper disable CppLocalVariableMayBeConst
	PCOGETCALLSTATE call_state_callback = reinterpret_cast<PCOGETCALLSTATE>(GetProcAddress(g_Ole32Hnd, "CoGetCallState"));
	// ReSharper restore CppLocalVariableMayBeConst
	if (!call_state_callback)
	{
		out_string.append(L"ERROR: GetProcAddress failed: 0x%X\n", GetLastError());
		return FALSE;
	}

	// ReSharper disable CppLocalVariableMayBeConst
	PCOGETACTIVATIONSTATE activation_state_callback = reinterpret_cast<PCOGETACTIVATIONSTATE>(GetProcAddress(g_Ole32Hnd, "CoGetActivationState"));  // NOLINT
	// ReSharper restore CppLocalVariableMayBeConst
	if (!activation_state_callback)
	{
		out_string.append(L"ERROR: GetProcAddress failed: 0x%X\n", GetLastError());
		return FALSE;
	}

	// Register these functions with WCT.
	RegisterWaitChainCOMCallback(call_state_callback, activation_state_callback);
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
	BOOL                f_success = FALSE;
	HANDLE              token_handle = INVALID_HANDLE_VALUE;
	TOKEN_PRIVILEGES    token_privileges;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&token_handle))
	{
		out_string.append(L"Could not get the process token. Error (0X%x)\n", GetLastError());
		goto Cleanup; // NOLINT
	}

	token_privileges.PrivilegeCount = 1;

	if (!LookupPrivilegeValue(nullptr,
		SE_DEBUG_NAME,
		&token_privileges.Privileges[0].Luid))
	{
		out_string.append(L"Couldn't lookup the SeDebugPrivilege name. Error (0X%x)\n", GetLastError());
		goto Cleanup; // NOLINT
	}

	token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token_handle,
		FALSE,
		&token_privileges,
		sizeof(token_privileges),
		nullptr,
		nullptr))
	{
		out_string.append(L"Could not revoke the debug privilege. Error (0X%x)\n", GetLastError());
		goto Cleanup;  // NOLINT
	}

	f_success = TRUE;
	goto Cleanup; // NOLINT


Cleanup:
	if (token_handle)
	{
		CloseHandle(token_handle);
	}

	return f_success;
}

HANDLE
GetProcessHandle(
	// ReSharper disable CppParameterMayBeConst
	__in DWORD	proc_id
	// ReSharper restore CppParameterMayBeConst
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
	// ReSharper disable CppInitializedValueIsAlwaysRewritten
	HANDLE      process_handle = INVALID_HANDLE_VALUE;
	// ReSharper restore CppInitializedValueIsAlwaysRewritten
	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
	if (process_handle == nullptr || process_handle == INVALID_HANDLE_VALUE)
	{
		std::string process_handle_string = "We were unable to obtain the handle for the process specified. Error: ";
		process_handle_string += std::to_string(GetLastError());
		// ReSharper disable CppLocalVariableMayBeConst
		std::wstring testing = std::wstring(process_handle_string.begin(), process_handle_string.end());
		// ReSharper restore CppLocalVariableMayBeConst
		out_string.append(testing);
	}

	// Caller is responsible for disposable.
	return process_handle;
}

HANDLE
get_process_snap_shot_handle(
	// ReSharper disable CppParameterMayBeConst
	__in HANDLE process
	// ReSharper restore CppParameterMayBeConst
)
{
	// ReSharper disable CppInitializedValueIsAlwaysRewritten
	HANDLE snap_shot_handle = INVALID_HANDLE_VALUE;
	std::string process_snapshot_handle_string = std::string();
	std::wstring process_snapshot_handle_wide_string = std::wstring();
	// ReSharper restore CppInitializedValueIsAlwaysRewritten

	snap_shot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(process));
	if (snap_shot_handle == INVALID_HANDLE_VALUE)
	{
		process_snapshot_handle_string = "We were unable to obtain the snapshot handle for the process specified. Error: ";
		process_snapshot_handle_string += std::to_string(GetLastError());
		process_snapshot_handle_wide_string = std::wstring(process_snapshot_handle_string.begin(), process_snapshot_handle_string.end());
		out_string.append(process_snapshot_handle_wide_string);
	}

	return snap_shot_handle;
}

void
walk_threads_and_print_chains(
	// ReSharper disable CppParameterMayBeConst
	__in HANDLE process,
	__in HANDLE process_snap_shot
	// ReSharper restore CppParameterMayBeConst
)
{
	THREADENTRY32	thread;
	thread.dwSize = sizeof(thread);
	// ReSharper disable CppLocalVariableMayBeConst
	DWORD process_id = GetProcessId(process);
	// ReSharper restore CppLocalVariableMayBeConst

	// No point in continuing if we can't get in.
	if (Thread32First(process_snap_shot, &thread))
	{
		// Walk the thread list and print each wait chain
		do
		{
			if (thread.th32OwnerProcessID == process_id)
			{
				// Open a handle to this specific thread
				// ReSharper disable CppLocalVariableMayBeConst
				HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread.th32ThreadID);
				// ReSharper restore CppLocalVariableMayBeConst
				if (thread_handle != nullptr)
				{
					// Check whether the thread is still running
					DWORD exitCode;
					GetExitCodeThread(thread_handle, &exitCode);

					if (exitCode == STILL_ACTIVE)
					{
						// Print the wait chain.
						print_wait_chain(thread.th32ThreadID);
					}

					// Always close your handles for SCIENCE!
					CloseHandle(thread_handle);
				}
			}
		} while (Thread32Next(process_snap_shot, &thread));
	}
}

void
print_wait_chain(
	__in DWORD thread_id
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

	std::string ts = std::to_string(thread_id);
	ts += "	";
	std::wstring test = std::wstring(ts.begin(), ts.end());
	out_string.append(test);

	Count = WCT_MAX_NODE_COUNT;

	// Make a synchronous WCT call to retrieve the wait chain.
	if (!GetThreadWaitChain(g_WctHandle,
	                        NULL,
	                        WCTP_GETINFO_ALL_FLAGS,
	                        thread_id,
	                        &Count,
	                        NodeInfoArray,
	                        &IsCycle))
	{
		out_string.append(L"Received error in GetThreadWaitChain call: (0X%x)\n", GetLastError());
		return;
	}

	// Check if the wait chain is too big for the array we passed in.
	if (Count > WCT_MAX_NODE_COUNT)
	{
		out_string.append(L"Found additional nodes beyond allowed count: %d\n", Count);
		Count = WCT_MAX_NODE_COUNT;
	}

	// Loop over all the nodes returned and print useful information.
	for (i = 0; i < Count; i++)
	{
		std::string thread_string = std::string();
		std::wstring testing = std::wstring();
		switch (NodeInfoArray[i].ObjectType)
		{
		case WctThreadType:
			// A thread node contains process and thread ID.
			thread_string = "[";
			thread_string += std::to_string(NodeInfoArray[i].ThreadObject.ProcessId) + ":";
			thread_string += std::to_string(NodeInfoArray[i].ThreadObject.ThreadId) + ":";
			thread_string += (NodeInfoArray[i].ObjectStatus == WctStatusBlocked) ? "blocked" : "running";
			thread_string += "]->";
			testing = std::wstring(thread_string.begin(), thread_string.end());
			out_string.append(testing);
			break;

		default:
			// It is a synchronization object and some of these objects have names.
			if (NodeInfoArray[i].LockObject.ObjectName[0] != L'\0')
			{
				thread_string = "[";
				thread_string += str_object_type[NodeInfoArray[i].ObjectType - 1].Desc;
				thread_string += ":";
				WCHAR * objName = NodeInfoArray[i].LockObject.ObjectName;
				char ch[260];
				char DefChar = ' ';
				WideCharToMultiByte(CP_ACP, 0, objName, -1, ch, 260, &DefChar, nullptr);
				thread_string += std::string(ch);
				thread_string += "]->";
				testing = std::wstring(thread_string.begin(), thread_string.end());
				out_string.append(testing);
			}
			else
			{
				thread_string = "[";
				thread_string += str_object_type[NodeInfoArray[i].ObjectType - 1].Desc;
				thread_string += "]->";
				testing = std::wstring(thread_string.begin(), thread_string.end());
				out_string.append(testing);
			}
			if (NodeInfoArray[i].ObjectStatus == WctStatusAbandoned)
			{
				out_string.append(L"<abandoned>");
			}
			break;
		}
	}

	out_string.append(L"[End]");

	// Did we find a deadlock?
	if (IsCycle)
	{
		out_string.append(L" !!!Deadlock!!! ");
	}

	out_string.append(L"\n");
}

extern "C"
{
__declspec(dllexport) LPCWSTR _cdecl WctEntry(
	// ReSharper disable CppParameterMayBeConst
	__in DWORD proc_id
	// ReSharper restore CppParameterMayBeConst
)
/*++

Routine Description:

  Main entry point for this application.

--*/
{
	out_string = L"";
	HANDLE process_handle = INVALID_HANDLE_VALUE;
	HANDLE process_snap_shot_handle = INVALID_HANDLE_VALUE;

	// Initialize the WCT interface to COM. Fail if this fails.
	if (!init_com_access())
	{
		out_string.append(L"Could not enable COM access\n");
		goto Cleanup; // NOLINT
	}

	// Open a synchronous WCT session.
	g_WctHandle = OpenThreadWaitChainSession(0, nullptr);
	if (g_WctHandle == nullptr || g_WctHandle == INVALID_HANDLE_VALUE)
	{
		out_string.append(L"ERROR: OpenThreadWaitChainSession failed\n");
		goto Cleanup; // NOLINT
	}

	if (GrantDebugPrivilege())
	{
		process_handle = GetProcessHandle(proc_id);
		if (process_handle != nullptr || process_handle != INVALID_HANDLE_VALUE)
		{
			process_snap_shot_handle = get_process_snap_shot_handle(process_handle);
			if (process_snap_shot_handle != nullptr || process_snap_shot_handle != INVALID_HANDLE_VALUE)
			{
				// Only enumerate threads in the specified process.
				walk_threads_and_print_chains(process_handle, process_snap_shot_handle);
				goto Cleanup; // NOLINT
			}
			goto Cleanup; // NOLINT
		}
	}
	else
	{
		out_string.append(L"ERROR: GrantDebugPrivilege failed\n");
		goto Cleanup; // NOLINT
	}


	// Close the WCT session.
	CloseThreadWaitChainSession(g_WctHandle);

Cleanup:

	if (nullptr != g_Ole32Hnd)
	{
		FreeLibrary(g_Ole32Hnd);
	}

	// Don't want to leak handles with every run.
	CloseHandle(process_handle);
	CloseHandle(process_snap_shot_handle);

	// Because Native Run-time controls the lifetime of the std::wstring object,
	// we must copy it to a structure that .NET can Marshal the pointer to and will
	// "live" outside of the lifetime of the native instance.
	// To demonstrate this problem, try returning the std::wstring as a wchar_t* and
	// notice that you'll hit a NullReferencePointer or a MemoryAccessViolation when
	// trying to return that object directly back to the .NET caller.

	// ReSharper disable CppLocalVariableMayBeConst  
	LPCWSTR new_lpwstr = LPCWSTR(out_string.c_str()); // NOLINT
	// ReSharper restore CppLocalVariableMayBeConst
	return new_lpwstr;
}
}