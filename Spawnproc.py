import ctypes

from ctypes.wintypes import DWORD,LPWSTR,LPBYTE,HANDLE,WORD

k_handle=ctypes.WinDLL("Kernel32.dll")

class STARTUPINFO(ctypes.Structure):
    _fields= [
        ("cb",DWORD),
        ("lpReserved",LPWSTR),
        ("lpDesktop",LPWSTR),
        ("lpTitle",LPWSTR),
        ("dwX",DWORD),
        ("dwY",DWORD),
        ("dwXSize",DWORD),
        ("dwYSize",DWORD),
        ("dwXCountChars",DWORD),
        ("dwYCountChars",DWORD),
        ("dwFillAttributes",DWORD),
        ("dwFlags",DWORD),
        ("wShowWindow",WORD),
        ("cbReserved2",WORD),
        ("lpReserved2",LPBYTE),
        ("hStdInput",HANDLE),
        ("hStdOutput",HANDLE),
        ("hStdError",HANDLE),
        ]

class PROCESS_INFO(ctypes.Structure):
    _fields= [
        ("hProcess",HANDLE),
        ("hTread",HANDLE),
        ("dwProcessId",DWORD),
        ("dwThreadId",DWORD),
        ]
      
lpApplicationName="C:\\Windows\\System32\\cmd.exe" 
lpCommandLine=None
lpprocessAttributes=None
lpthreadAttributes=None
bInheritHandle=False
dwCreationFlags=0x00000010
lpEnvironment=None
lpCurrentDirectory=None
lpprocessinfo=PROCESS_INFO()
lpStartupInfo=STARTUPINFO()
lpStartupInfo.wShowWindow=0x1
lpStartupInfo.dwFlags=0x1

response=k_handle.CreateProcessW(
    lpApplicationName,
    lpCommandLine,
    lpprocessAttributes,
    lpthreadAttributes,
    bInheritHandle,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    ctypes.byref(lpStartupInfo),
    ctypes.byref(lpprocessinfo))

if response==0:
    print("Process was not able to start. ErrorCode: {0}".format(k_handle.GetLastError()))
    
else:
    print("Process started")