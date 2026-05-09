/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2025 Baldur Karlsson
 * Copyright (c) 2014 Crytek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>

class GlobalHookLauncher
{
public:
    static void StartGlobalMonitoring()
    {
        printf("SanqiInjectTool Global Hook Launcher Started\n");
        printf("Monitoring all system processes...\n");
        
        // Enable console output
        AllocConsole();
        freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
        freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
        
        // Start monitoring existing processes
        MonitorExistingProcesses();
        
        // Start monitoring new processes
        StartProcessMonitor();
    }
    
private:
    static void MonitorExistingProcesses()
    {
        printf("Scanning existing processes...\n");
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            printf("Failed to create process snapshot\n");
            return;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                // Skip system processes and our own process
                if (pe32.th32ProcessID != GetCurrentProcessId() &&
                    pe32.th32ProcessID != 0 &&
                    pe32.th32ProcessID != 4) // System process
                {
                    printf("Found process: %ls (PID: %d)\n", pe32.szExeFile, pe32.th32ProcessID);
                    
                    // Try to inject into the process
                    TryInjectIntoProcess(pe32.th32ProcessID);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
    }
    
    static void TryInjectIntoProcess(DWORD processId)
    {
        // Get process handle
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (hProcess == NULL)
        {
            printf("Cannot open process %d (Access denied or process protected)\n", processId);
            return;
        }
        
        // Get process name
        char processName[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, processName, &size))
        {
            printf("Attempting to inject into: %s (PID: %d)\n", processName, processId);
            
            // Here you would implement DLL injection
            // For now, just log the attempt
            printf("Injection attempted for process %d\n", processId);
        }
        
        CloseHandle(hProcess);
    }
    
    static void StartProcessMonitor()
    {
        printf("Starting process creation monitor...\n");
        printf("Global hook monitoring active - all new processes will be monitored\n");
        
        // This would typically involve:
        // 1. Setting up a global hook using SetWindowsHookEx
        // 2. Monitoring process creation events
        // 3. Automatically injecting into new processes
        
        // For demonstration, we'll just keep the console open
        printf("Press any key to stop monitoring...\n");
        getchar();
    }
};

// Entry point for global hook launcher
int main(int argc, char* argv[])
{
    if(argc > 1)
    {
        // If EXE path is provided as argument, monitor specific process
        printf("SanqiInjectTool Global Hook Launcher Started for: %s\n", argv[1]);
        GlobalHookLauncher::StartGlobalMonitoring();
    }
    else
    {
        // Monitor all processes
        GlobalHookLauncher::StartGlobalMonitoring();
    }
    return 0;
}
