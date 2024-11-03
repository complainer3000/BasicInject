#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

BOOL InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Error: Unable to open process." << std::endl;
        return FALSE;
    }

    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteBuf == NULL) {
        std::cerr << "Error: Unable to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    if (WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL) == 0) {
        std::cerr << "Error: Unable to write memory to target process." << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteBuf, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Error: Unable to create remote thread." << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

DWORD GetProcessIDByWindowName(const char* windowName) {
    HWND hwnd = FindWindowA(NULL, windowName);
    if (hwnd == NULL) {
        std::cerr << "Error: No window found with the specified name." << std::endl;
        return 0;
    }

    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: Injector.exe <window name or PID> <DLL path>" << std::endl;
        return 1;
    }

    const char* dllPath = argv[2];
    DWORD processID = 0;

    // Check if the first argument is a number (PID) or a window name
    if (isdigit(argv[1][0])) {
        processID = atoi(argv[1]);
    } else {
        processID = GetProcessIDByWindowName(argv[1]);
        if (processID == 0) {
            return 1; // Error getting PID
        }
    }

    if (InjectDLL(processID, dllPath)) {
        std::cout << "DLL injected successfully." << std::endl;
    } else {
        std::cout << "DLL injection failed." << std::endl;
    }

    return 0;
}
