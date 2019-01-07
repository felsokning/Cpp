// WlanTestDll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#pragma comment(lib, "wlanapi.lib")

BOOL bWait = TRUE;

// We create outside of the stack scope, so that the LPCWSTSR pointer has a valid object to reference
// when returning to the Marshal. If left on the stack, the object is disposed of when scope is left
// and we have empty/invalid data for the pointer's reference.
std::wstring returnWString = L"";

VOID
WlanNotification(
	__in WLAN_NOTIFICATION_DATA *wlanNotifData,
	__in VOID *p)
	/*++

		Routine Description:
			Determines the enum value and returns whether we should wait or not.

		Arguments:
			WLAN_NOTIFICATION_DATA
				WLAN Notification contains detailed information on the notification.
			VOID
				Client context can be a NULL pointer if that is what was passed to the WlanRegisterNotification function.

		Return Value:
			TRUE if we should wait; FALSE otherwise.

	--*/
{
	if (wlanNotifData->NotificationCode == wlan_notification_acm_scan_fail || wlan_notification_acm_scan_complete)
	{
		bWait = FALSE;
	}
	else
	{
		bWait = TRUE;
	}
}

VOID
WlanRegisterForNotificationsAndScans(
	__in HANDLE handle,
	__in GUID interfaceGuid,
	__in DWORD dwNotif)
	/*++

		Routine Description:
			Registers the interface for callback notification, tells the interface to scan (assuming Beacon and ), and then
			unregisters the callback, since this required to obtain the BSSIDs from the AutoConfig.

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
	if (WlanRegisterNotification(handle, WLAN_NOTIFICATION_SOURCE_ACM, TRUE, (WLAN_NOTIFICATION_CALLBACK)WlanNotification, NULL, NULL, &dwNotif) != ERROR_SUCCESS)
		throw("Unable to register for notifications");
	if (WlanScan(handle, &interfaceGuid, NULL, NULL, NULL) != ERROR_SUCCESS)
		throw("Scan failed, check adapter status.");

	// Need to sleep for SCIENCE!!!!
	while (bWait)
		Sleep(1000);

	// Unregister callback, we - technically - do not care if it actually succeeds or not
	WlanRegisterNotification(handle, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, NULL, NULL, NULL, &dwNotif);
}

std::wstring
WlanGetBssids(
	__in HANDLE handle,
	__in GUID interfaceGuid)
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
	WLAN_BSS_LIST wlanBssList = WLAN_BSS_LIST();
	WLAN_BSS_LIST * pWlanBssList = &wlanBssList;
	PWLAN_BSS_LIST * ppWlanBssList = (&pWlanBssList);
	std::wstring returningWString = std::wstring();

	// We must validate that the Win32Code came back as successful before continuing.
	// See: https://msdn.microsoft.com/en-us/library/cc231199.aspx
	if (WlanGetNetworkBssList(handle, &interfaceGuid, NULL, dot11_BSS_type_infrastructure, NULL, NULL, ppWlanBssList) == ERROR_SUCCESS)
	{
		// De-reference seems to be required here to access the object returned from the call.
		// De-reference also puts the object directly on the stack. So... There's that.
		PWLAN_BSS_LIST pWLanBssList = (*ppWlanBssList);

		// Because of the native object on the stack, we need to iterate forward.
		// Otherwise, the SSID becomes munged when we work backwards. #justThingsYouLearn
		for (unsigned int t = 0; t < pWLanBssList->dwNumberOfItems; t++)
		{
			WLAN_BSS_ENTRY wlBE = pWLanBssList->wlanBssEntries[t];

			// Since the SSID is not null-terminated, let's do that for SCIENCE!
			// See: https://docs.microsoft.com/en-us/windows/desktop/nativewifi/dot11-ssid
			UCHAR * ssid = wlBE.dot11Ssid.ucSSID + '\0';

			char mac[200];
			sprintf_s(mac,
				200,
				"%02x-%02x-%02x-%02x-%02x-%02x",
				wlBE.dot11Bssid[0],
				wlBE.dot11Bssid[1],
				wlBE.dot11Bssid[2],
				wlBE.dot11Bssid[3],
				wlBE.dot11Bssid[4],
				wlBE.dot11Bssid[5]);

			// Because the SSID can be ANYTHING, we have to account for large names
			// and large size character sets. This was discovered by testing in the wild.
			char target[4096];
			sprintf_s(target,
				4096,
				"%s %s%s%s",
				mac,
				"(",
				ssid,
				");" /* We add the delimeter. It's up to the caller to parse it. */);
			std::string tempString = std::string(target);
			returningWString.append(tempString.begin(), tempString.end());
		}
	}

	return returnWString;
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
	DWORD dwPrevNotif = 0;
	DWORD dwSupportedVersion = 0;
	DWORD dwClientVersion = (IsWindowsVistaOrGreater() ? 2 : 1);

	// LPCWSTR only takes wchar_t*, so we need to pass back a wstring to convert back to
	// the wchar_t*, once received. std::string only returns const char* and would still
	// need conversion, otherwise.
	std::wstring targetWString = std::wstring();
	GUID guidInterface;

	HANDLE hWlan = INVALID_HANDLE_VALUE;
	WLAN_INTERFACE_INFO_LIST *wlanInterfaceList = (WLAN_INTERFACE_INFO_LIST*)WlanAllocateMemory(sizeof(WLAN_INTERFACE_INFO_LIST));
	WLAN_AVAILABLE_NETWORK_LIST *wlanNetworkList = (WLAN_AVAILABLE_NETWORK_LIST*)WlanAllocateMemory(sizeof(WLAN_AVAILABLE_NETWORK_LIST));

	// Securely zero-out the memory. ZeroMemory can be ignored/removed because of optimisation.
	// For details, see: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366877(v=vs.85).aspx
	SecureZeroMemory(&guidInterface, sizeof(GUID));
	SecureZeroMemory(wlanInterfaceList, sizeof(WLAN_INTERFACE_INFO_LIST));
	SecureZeroMemory(wlanNetworkList, sizeof(WLAN_AVAILABLE_NETWORK_LIST));

	try
	{
		if (WlanOpenHandle(dwClientVersion, NULL, &dwSupportedVersion, &hWlan) != ERROR_SUCCESS || hWlan == INVALID_HANDLE_VALUE)
			throw("Unable access wireless interface");

		if (WlanEnumInterfaces(hWlan, NULL, &wlanInterfaceList) != ERROR_SUCCESS)
			throw("Unable to enum wireless interfaces");

		// Make sure were not null-referencing and we can iterate multiple interfaces.
		if (wlanInterfaceList->dwNumberOfItems > 0)
		{
			for (unsigned int i = 0; i < wlanInterfaceList->dwNumberOfItems; i++)
			{
				if (wlanInterfaceList->InterfaceInfo[i].isState != wlan_interface_state_not_ready)
				{
					guidInterface = wlanInterfaceList->InterfaceInfo[i].InterfaceGuid;
					WlanRegisterForNotificationsAndScans(hWlan, guidInterface, dwPrevNotif);
					std::wstring returnedWString = WlanGetBssids(hWlan, guidInterface);
					targetWString.append(returnedWString.begin(), returnedWString.end());
				}
				else
					// TODO: We probably don't want to throw here, since we're iterating.
					throw("Default wireless adapter disabled");
			}
		}
		else
			throw("No valid interfaces found.");

		goto Cleanup;
	}
	catch (char *szError)
	{
		printf("%s \nQuitting...\n", szError);
		goto Cleanup;
	}

Cleanup:
	WlanFreeMemory(wlanNetworkList);
	WlanFreeMemory(wlanInterfaceList);
	WlanCloseHandle(hWlan, NULL);

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
		returnWString = L"";
		returnWString.assign(GetWlanNetworkBssids().c_str());

		// Need the LPCWSTR (Long Pointer to Constant Wide String), since we use 
		// Marshal.PtrToStringUni in Managed Code to translate it to a readable string in .NET.
		LPCWSTR returnLpcuwstr = returnWString.c_str();
		return returnLpcuwstr;
	}
}