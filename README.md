# Cpp
This is C++ code (almost always a DLL) for reference/example.

## UnmanagedDebugging
This C++ code interops with the [Wait-Chain Traversal API](https://docs.microsoft.com/en-us/windows/desktop/Debug/wait-chain-traversal) and returns an LPCWSTR back to the caller, containing all of the Wait-Chains found for the given process (specified by PID).

## WlanObtainBssids
This C++ code interops with the Windows API (Specifically, [WlanGetNetworkBssList](https://docs.microsoft.com/en-us/windows/desktop/api/wlanapi/nf-wlanapi-wlangetnetworkbsslist)) to return an LPCWSTR containing all of the SSIDs (and their corresponding BSSIDS) available on the wireless network interface.
