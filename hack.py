import ctypes
global ctypes
import wmi
from win32com.client import GetObject
import sys


class Pyrate:
 
    def __init__(self):
        self.pHandle = None
        self.pid = None
        self.isProcessOpen = False
        self.process32 = None

        WMI = GetObject('winmgmts:')


    def FindProcess(self, ProcessName):
        WMI = GetObject('winmgmts:')
        p = WMI.ExecQuery('select * from Win32_Process where Name="%s"' % (ProcessName))
        pid = p[0].Properties_('ProcessId').Value  # derp, forgot the value
        #print("Process ID of %s is %s" % (ProcessName, pid))
        return pid


    def Attach(self, ProcessID):
        self.pHandle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, ProcessID)
 
    def GetProcesses(self):
        c = wmi.WMI ()
        for process in c.Win32_Process ():
            print (process.ProcessId, process.Name)
    def GetSize(self, Type):
        if Type == "i":  # Int32
            return 4
        elif Type == "f":  # float
            return 4
        elif Type == "?":  # bool
            return 1
        elif Type == "c":  # char
            return 1
        elif Type == "d":  # double
            return 8
        elif Type == "q":  # long long
            return 8
 
 
    def ReadMemNum(self, adress, type):
        buffer = (ctypes.c_byte * self.GetSize(type))()
        bytesRead = ctypes.c_ulonglong(0)
        if ctypes.windll.kernel32.ReadProcessMemory(self.pHandle, adress, buffer, len(buffer), ctypes.byref(bytesRead)):
            return (struct.unpack(type, buffer)[0])
        else:
            return -1
 
 
    def WriteMem(self, adress, Val, type):
        buffer = (ctypes.c_byte * self.GetSize(type))(*struct.pack(type, Val))
        bytesRead = ctypes.c_ulonglong(0)
        if ctypes.windll.kernel32.WriteProcessMemory(self.pHandle, adress, buffer, len(buffer), ctypes.byref(bytesRead)):
            return True
        else:
            return False
 
    def WriteByte(self, adress, Bytes):
        for i in range(0, len(Bytes)):
            buffer = (ctypes.c_byte * 1)(*[Bytes[i]])
            bytesRead = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.WriteProcessMemory(self.pHandle, adress + i, buffer, 1, ctypes.byref(bytesRead))
 
 
 
    def GetLastError(self):
        return ("err code: " + str(ctypes.windll.kernel32.GetLastError()))
 
 
    def Detach(self):
        ctypes.windll.kernel32.CloseHandle(self.pHandle)
