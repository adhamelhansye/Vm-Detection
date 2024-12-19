#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wbemidl.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")


void detectProcesses() {
    printf("Checking running processes for VMware...\n");
    system("tasklist | findstr /i \"vmware\"");
    printf("\n");
}

void detectRegistry() {
    HKEY hKey;
    printf("Checking registry keys for VMware...\n");
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("VMware registry key found!\n");
        RegCloseKey(hKey);
    } else {
        printf("VMware registry key not found.\n");
    }
    printf("\n");
}

void detectDrivers() {
    printf("Checking for VMware drivers...\n");
    system("driverquery | findstr /i \"vm\"");
    printf("\n");
}

void detectMACAddress() {
    printf("Checking MAC addresses for VMware...\n");
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufferSize = sizeof(adapterInfo);
    DWORD result = GetAdaptersInfo(adapterInfo, &bufferSize);

    if (result == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            printf("Adapter: %s\n", adapter->Description);
            printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   adapter->Address[0], adapter->Address[1], adapter->Address[2],
                   adapter->Address[3], adapter->Address[4], adapter->Address[5]);
            if ((adapter->Address[0] == 0x00 && adapter->Address[1] == 0x0C && adapter->Address[2] == 0x29) ||
                (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x05 && adapter->Address[2] == 0x69)) {
                printf("VMware MAC Address detected!\n");
            }
            adapter = adapter->Next;
        }
    } else {
        printf("Error retrieving MAC addresses.\n");
    }
    printf("\n");
}

void detectVMUsingCPUID() {
    unsigned int eax, ebx, ecx, edx;

    __asm {
        mov eax, 0x40000000
        cpuid
        mov eax, eax
        mov ebx, ebx
        mov ecx, ecx
        mov edx, edx
    }

    printf("Checking CPUID for VMware...\n");
    if (ebx == 0x566D6551) { 
        printf("VMware detected using CPUID.\n");
    } else {
        printf("No VMware signature found in CPUID.\n");
    }
    printf("\n");
}

void detectHardware() {
    printf("Checking hardware details for VMware...\n");

    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        printf("Failed to initialize COM library.\n");
        return;
    }

    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres)) {
        printf("Failed to create IWbemLocator object.\n");
        CoUninitialize();
        return;
    }

    IWbemServices *pSvc = NULL;
    hres = pLoc->ConnectServer(L"ROOT\\CIMV2", NULL, NULL, 0, NULL, 0, 0, &pSvc);

    if (SUCCEEDED(hres)) {
        IEnumWbemClassObject *pEnumerator = NULL;
        hres = pSvc->ExecQuery(L"WQL", L"SELECT * FROM Win32_ComputerSystem",
                               WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

        if (SUCCEEDED(hres)) {
            IWbemClassObject *pObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator) {
                hres = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn);
                if (uReturn == 0) break;

                VARIANT varManufacturer;
                VariantInit(&varManufacturer);
                hres = pObj->Get(L"Manufacturer", 0, &varManufacturer, 0, 0);

                if (SUCCEEDED(hres) && varManufacturer.vt == VT_BSTR) {
                    if (wcsstr(varManufacturer.bstrVal, L"VMware")) {
                        printf("VMware detected in hardware details.\n");
                    } else {
                        printf("No VMware detected in hardware details.\n");
                    }
                }

                VariantClear(&varManufacturer);
                pObj->Release();
            }

            pEnumerator->Release();
        }

        pSvc->Release();
    }

    pLoc->Release();
    CoUninitialize();
    printf("\n");
}


int main() {
    printf("========== VMware Detection Program ==========\n\n");

    detectProcesses();
    detectRegistry();
    detectDrivers();
    detectMACAddress();
    detectVMUsingCPUID();
    detectHardware();

    printf("==============================================\n");
    return 0;
}
