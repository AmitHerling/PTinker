#define _UNICODE 1
#define UNICODE 1

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h> 
#include <wchar.h>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <processthreadsapi.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include "DLLTinkerer.h"

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")


void VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    /* An adapted example from MSDN for the wintrust api
    * [in] pwszSourceFile *wchar
    */
    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);

    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            _tprintf_s(TEXT("\tNOT SIGNED ->\t%s\n"), pwszSourceFile);
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            _tprintf_s(TEXT("\tINVALID SIGN ->\t % s\n"), pwszSourceFile);
        }
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        _tprintf_s(TEXT("Error is: 0x%x.\n",
            lStatus));
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

}

void walkOnModules(HANDLE pHandle, BOOL verifySign) {
    /* Walks the process module tree and prints output accordingly 
    * [in] pHandle Handle
    * [in] verifySign BOOL 
    */
    DWORD bNeeded;
    HMODULE Modules[0xFFFF];

    if (EnumProcessModules(pHandle, Modules, sizeof(Modules), &bNeeded)) {
        for (int i = 1; i < (bNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(pHandle, Modules[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                if (verifySign)
                {
                    VerifyEmbeddedSignature(szModName);
                }
                else
                {
                    _tprintf_s(TEXT("\t%s\n"), szModName);
                }
            }
        }
    }
}

BOOL safeCompareWide(TCHAR* szUserString, TCHAR* szModuleString) {
    /* Wide character compare operations
    * intended to gurantee case insensetive wchar to wchar comparison 
    * return bool relaxed match
    * [in] szUserString wchar
    * [in] szModuleString wchar
    */
    BOOL match = false;
    TCHAR szNewModuleString[_MAX_FNAME];
    TCHAR szNewUserString[_MAX_FNAME];

    _wsplitpath_s(szModuleString, NULL, NULL, NULL, NULL, szNewModuleString, _MAX_FNAME, NULL, NULL);
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szUserString, -1, szNewUserString, _MAX_FNAME); // ->
    //probably can extract wcha with wmain and tchar argv (which is better?).

    TCHAR* ext = wcsrchr(szNewUserString, TEXT('.'));

    if ((ext != NULL && _wcsnicmp(szNewModuleString, szNewUserString, ext - szNewUserString) == 0) ||
        _wcsnicmp(szNewModuleString, szNewUserString, _MAX_FNAME) == 0) {
        match = true;
    }
    return match;
}

void fishModByName(TCHAR* moduleName, HANDLE pHandle) {
    /* Enumerates on modules, prints specified mod by name 
    * (I'm not sure by design but I chose not to include this logic in modWalk because 
    * this operation may be more specific)
    * [in] moduleName *wchar
    * [in] pHandle Handle
    */
    DWORD bNeeded;
    HMODULE Modules[0xFFFF];

    if (EnumProcessModules(pHandle, Modules, sizeof(Modules), &bNeeded)) 
    {
        for (int i = 1; i < (bNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(pHandle, Modules[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                if (safeCompareWide(moduleName, szModName)) 
                {
                    _tprintf_s(TEXT("process %d has:\t%s\n"),GetProcessId(pHandle), szModName);
                }
            }
        }
    }
}

void fishProcByName(TCHAR* processName, HANDLE pHandle)
{   
    /* Compares proc by name and prints modules accordingly
    * [in] processName *wchar
    * [in] pHandle Handle
    */
    TCHAR szProcessName[MAX_PATH];

    GetProcessImageFileName(pHandle, szProcessName,
            sizeof(szProcessName) / sizeof(TCHAR)); // I use this explicitly due to remarks in msdn
    if (safeCompareWide(processName, szProcessName))
    {
        _tprintf(TEXT("\nprocess %d modules:\n"), GetProcessId(pHandle));
        walkOnModules(pHandle, false);
    }

}

void procByPid(ActionType action, DWORD pId) {
    /* Does specific logics on process specified pid 
    * [in] ActionType Enum 
    * [in] pId DWORD
    */
    HANDLE pHandle;
    pHandle = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, pId);

    switch (action)
    {
    case list:
        _tprintf(TEXT("\nprocess %d modules:\n"), GetProcessId(pHandle));
        walkOnModules(pHandle, false);
        break;
    case sign:
        _tprintf(TEXT("\nprocess %d unsinged modules:\n"), GetProcessId(pHandle));
        walkOnModules(pHandle, true);
        break;
    default:
        break;
    }
    CloseHandle(pHandle);
};

void walkOnProcesses(TCHAR* pName, BOOL findMod) {
    /* Enumerates all processs and does specifc logic by name
    * [in] pName *wchar
    * [out] findMod BOOL
    */
    DWORD procArray[0xFFFF], countSize, procCount;
    HANDLE pHandle;
    if (!EnumProcesses(procArray, sizeof(procArray), &countSize))
    {
        return 0;
    }

    procCount = countSize / sizeof(DWORD);

    for (int i = 0; i < procCount; i++)
    {
        if (procArray[i] != 0)
        {
            pHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_READ,
                FALSE, procArray[i]);
            
            if (pHandle != NULL) 
            {
                if (findMod) {
                    fishModByName(pName, pHandle);
                }
                else {
                    fishProcByName(pName, pHandle);
                }
                CloseHandle(pHandle);
            }
        }
    }

}


int main(int argc, char *argv[]) {
    DWORD pId = NULL;
    char cOpt;
    char* pmName;
    int nOpt;

    if (argc != 4) {
        _tprintf_s(TEXT("usage: tinker {-n <NAME> -p <PID>} [-l -m -s]"));
        return 1;
    }

    if (strncmp(argv[1], "-p", 2) == 0 && strlen(argv[2]) != 0)
    {

        char* p;
        errno = 0;
        long arg = strtol(argv[2], &p, 10);
        if (*p != '\0' || errno != 0) {
            return 1; 
        }

        if (arg < INT_MIN || arg > INT_MAX) {
            return 1;
        }
        pId = arg;
    }
    
    cOpt = argv[3][1];
    switch (cOpt)
    {
    case 'l':
        if (pId != NULL) {
            procByPid(list, pId);
        }
        else { 
            pmName = argv[2];
            walkOnProcesses(pmName, false);
        }
        break;
    case 'm':
        pmName = argv[2];
        walkOnProcesses(pmName, true);
        break;

    case 's':
        procByPid(sign, pId);
        break;

    default:
        _tprintf_s(TEXT("usage: tinker {-n <NAME> -p <PID>} [-l -m -s]"));
        break;
    }
}