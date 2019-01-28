// WlanTestDll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#pragma comment(lib, "wlanapi.lib")

BOOL b_wait = TRUE;

// We create outside of the stack scope, so that the LPCWSTSR pointer has a valid object to reference
// when returning to the Marshal. If left on the stack, the object is disposed of when scope is left
// and we have empty/invalid data for the pointer's reference.
std::wstring return_w_string;

VOID
WlanNotification(
	__in WLAN_NOTIFICATION_DATA *wireless_lan_notify_data,
	__in VOID *p)
	/*++

		Routine Description:
			Determines the enum value and returns whether we should wait or not.

		Arguments:
			WLAN_NOTIFICATION_DATA
				Wireless LAN Notification contains detailed information on the notification.
			VOID
				Client context can be a NULL pointer if that is what was passed to the WlanRegisterNotification function.

		Return Value:
			TRUE if we should wait; FALSE otherwise.

	--*/
{
	if (wireless_lan_notify_data->NotificationCode == wlan_notification_acm_scan_fail || wlan_notification_acm_scan_complete)
	{
		b_wait = FALSE;
	}
}

VOID
WlanRegisterForNotificationsAndScans(
	// ReSharper disable CppParameterMayBeConst
	__in HANDLE handle,
	// ReSharper restore CppParameterMayBeConst
	__in GUID interface_guid,
	__in DWORD dw_notify)
/*++

	Routine Description:
		Registers the interface for callback notification, tells the interface to scan (assuming Beacon and ), and then
		un-registers the callback, since this required to obtain the BSSIDs from the AutoConfig.

	Arguments:
		HANDLE
			The client's session handle, obtained by a previous call to the WlanOpenHandle function.
		GUID
			The GUID of the interface to be queried.
		DWORD
			Used for the validation of the previous notification source.

	Return Value:
		VOID - Function returns no values.

--*/
{
	// Scan takes a hot minute so we will need to register a callback
	if (WlanRegisterNotification(handle, WLAN_NOTIFICATION_SOURCE_ACM, TRUE, static_cast<WLAN_NOTIFICATION_CALLBACK>(WlanNotification), nullptr, nullptr, &dw_notify) != ERROR_SUCCESS)
		throw std::exception("Unable to register for notifications");
	if (WlanScan(handle, &interface_guid, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
		throw std::exception("Scan failed, check adapter status.");

	// Need to sleep for SCIENCE!!!!
	while (b_wait)
		Sleep(1000);

	// Un-register callback, we - technically - do not care if it actually succeeds or not
	WlanRegisterNotification(handle, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, nullptr, nullptr, nullptr, &dw_notify);
}

std::wstring
wlan_get_bssids(
	// ReSharper disable CppParameterMayBeConst
	__in HANDLE handle,
	// ReSharper restore CppParameterMayBeConst
	__in GUID interface_guid)
/*++

	Routine Description:
		Obtains the BSSIDs and SSIDs found on the given wireless interface.

	Arguments:
		HANDLE
			The client's session handle, obtained by a previous call to the WlanOpenHandle function.
		GUID
			The GUID of the interface to be queried.

	Return Value:
		std::wstring - Wide-string used to return the BSSID (MAC Address of the Broadcast Device) and the SSID.

--*/
{
	WLAN_BSS_LIST wlan_bss_list = WLAN_BSS_LIST();
	WLAN_BSS_LIST * p_wlan_bss_list = &wlan_bss_list;
	PWLAN_BSS_LIST * pp_wlan_bss_list = (&p_wlan_bss_list);
	std::wstring returning_w_string = std::wstring();

	// We must validate that the Win32Code came back as successful before continuing.
	// See: https://msdn.microsoft.com/en-us/library/cc231199.aspx
	if (WlanGetNetworkBssList(handle, &interface_guid, nullptr, dot11_BSS_type_infrastructure, NULL, nullptr, pp_wlan_bss_list) == ERROR_SUCCESS)
	{
		// De-reference seems to be required here to access the object returned from the call.
		// De-reference also puts the object directly on the stack. So... There's that.
		PWLAN_BSS_LIST pWLanBssList = (*pp_wlan_bss_list);

		// Because of the native object on the stack, we need to iterate forward.
		// Otherwise, the SSID becomes munged when we work backwards. #justThingsYouLearn
		for (unsigned int t = 0; t < pWLanBssList->dwNumberOfItems; t++)
		{
			WLAN_BSS_ENTRY wl_be = pWLanBssList->wlanBssEntries[t];

			// Since the SSID is not null-terminated, let's do that for SCIENCE!
			// See: https://docs.microsoft.com/en-us/windows/desktop/nativewifi/dot11-ssid
			UCHAR * ssid = wl_be.dot11Ssid.ucSSID + '\0'; // NOLINT

			char mac[200];
			sprintf_s(mac,
			          200,
			          "%02x-%02x-%02x-%02x-%02x-%02x",
			          wl_be.dot11Bssid[0],
			          wl_be.dot11Bssid[1],
			          wl_be.dot11Bssid[2],
			          wl_be.dot11Bssid[3],
			          wl_be.dot11Bssid[4],
			          wl_be.dot11Bssid[5]);

			// Because the SSID can be ANYTHING, we have to account for large names
			// and large size character sets. This was discovered by testing in the wild.
			char target[4096];
			sprintf_s(target,
			          4096,
			          "%s %s%p%s",
			          mac,
			          "(",
			          ssid,
			          ");" /* We add the delimiter. It's up to the caller to parse it. */);
			std::string tempString = std::string(target);
			returning_w_string.append(tempString.begin(), tempString.end());
		}
	}

	return return_w_string;
}

std::wstring
GetWlanNetworkBssids()
/*++

	Routine Description:
		Finds the wireless network devices on the machines, iterates through them, and
		obtains the BSSIDs and SSIDs found on the given wireless interface, adding those
		values to a wstring to be returned back to the caller.

	Arguments:
		HANDLE
			The client's session handle, obtained by a previous call to the WlanOpenHandle function.
		GUID
			The GUID of the interface to be queried.

	Return Value:
		std::wstring - Wide-string used to return the BSSID (MAC Address of the Broadcast Device) and the SSID.

--*/
{
	// ReSharper disable CppLocalVariableMayBeConst
	DWORD dw_prev_notify = 0;
	// ReSharper restore CppLocalVariableMayBeConst
	DWORD dw_supported_version = 0;
	// ReSharper disable CppLocalVariableMayBeConst
	DWORD dw_client_version = (IsWindowsVistaOrGreater() ? 2 : 1);
	// ReSharper restore CppLocalVariableMayBeConst

	// LPCWSTR only takes wchar_t*, so we need to pass back a wstring to convert back to
	// the wchar_t*, once received. std::string only returns const char* and would still
	// need conversion, otherwise.
	std::wstring targetWString = std::wstring();
	GUID guidInterface;

	HANDLE hWlan = INVALID_HANDLE_VALUE;
	WLAN_INTERFACE_INFO_LIST *wlan_interface_list = static_cast<WLAN_INTERFACE_INFO_LIST*>(WlanAllocateMemory(sizeof(WLAN_INTERFACE_INFO_LIST)));  // NOLINT
	WLAN_AVAILABLE_NETWORK_LIST *wlan_network_list = static_cast<WLAN_AVAILABLE_NETWORK_LIST*>(WlanAllocateMemory(sizeof(WLAN_AVAILABLE_NETWORK_LIST))); // NOLINT

	// Securely zero-out the memory. ZeroMemory can be ignored/removed because of optimisation.
	// For details, see: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366877(v=vs.85).aspx
	SecureZeroMemory(&guidInterface, sizeof(GUID));
	SecureZeroMemory(wlan_interface_list, sizeof(WLAN_INTERFACE_INFO_LIST));
	SecureZeroMemory(wlan_network_list, sizeof(WLAN_AVAILABLE_NETWORK_LIST));

	try
	{
		if (WlanOpenHandle(dw_client_version, nullptr, &dw_supported_version, &hWlan) != ERROR_SUCCESS || hWlan == INVALID_HANDLE_VALUE)
			throw std::exception("Unable access wireless interface");

		if (WlanEnumInterfaces(hWlan, nullptr, &wlan_interface_list) != ERROR_SUCCESS)
			throw std::exception("Unable to enum wireless interfaces");

		// Make sure were not null-referencing and we can iterate multiple interfaces.
		if (wlan_interface_list->dwNumberOfItems > 0)
		{
			for (unsigned int i = 0; i < wlan_interface_list->dwNumberOfItems; i++)
			{
				if (wlan_interface_list->InterfaceInfo[i].isState != wlan_interface_state_not_ready)
				{
					guidInterface = wlan_interface_list->InterfaceInfo[i].InterfaceGuid;
					WlanRegisterForNotificationsAndScans(hWlan, guidInterface, dw_prev_notify);
					std::wstring returned_w_string = wlan_get_bssids(hWlan, guidInterface);
					targetWString.append(returned_w_string.begin(), returned_w_string.end());
				}
				else
					// TODO: We probably don't want to throw here, since we're iterating.
					throw std::exception("Default wireless adapter disabled");
			}
		}
		else
			throw std::exception("No valid interfaces found.");

		goto Cleanup; // NOLINT
	}
	catch (char *sz_error)
	{
		printf("%s \nQuitting...\n", sz_error);
		goto Cleanup; // NOLINT
	}

Cleanup:
	WlanFreeMemory(wlan_network_list);
	WlanFreeMemory(wlan_interface_list);
	WlanCloseHandle(hWlan, nullptr);

	return targetWString;
}

extern "C"
{
	__declspec(dllexport) LPCWSTR WlanEntry()
	/*++

	Routine Description:
		Calls the inner native methods, adding the results to an std::wstring, and
		subsequently creates an LPCWSTR to be passed back to the managed caller.

	Arguments:
		None.

	Return Value:
		LPCWSTR - A pointer to a constant wide-string, used to return the BSSID (MAC
		Address of the Broadcast Device) and the SSID back to the managed caller via
		Marshalling the native object by the pointer.

	--*/
	{
		// For consecutive runs, we need to reset the wstring.
		return_w_string = L"";
		return_w_string.assign(GetWlanNetworkBssids());

		// Need the LPCWSTR (Long Pointer to Constant Wide String), since we use 
		// Marshal.PtrToStringUni in Managed Code to translate it to a readable string in .NET.
		// ReSharper disable CppLocalVariableMayBeConst
		LPCWSTR return_lpcuwstr = return_w_string.c_str();
		// ReSharper restore CppLocalVariableMayBeConst
		return return_lpcuwstr;
	}
}