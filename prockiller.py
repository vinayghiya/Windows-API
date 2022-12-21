import ctypes

k_handle=ctypes.WinDLL("kernel32.dll")
u_handle=ctypes.WinDLL("user32.dll")

PROCESS_ALL_ACCESS=(0x000F0000 | 0x00100000 | 0xFFF) # to get all access for like terminate open etc

lpWindowName=ctypes.c_char_p(input("Enter process to kill: ").encode("utf-8")) #encoded this string for ANSI

hWnd=u_handle.FindWindowA(None,lpWindowName) 

if hWnd==0:
    print("Error Code: {0} - Could not grab the Handle".format(k_handle.GetLastError()))
    exit(1)
    
else:
    print("Handle Grabbed")

lpdwProcessId=ctypes.c_ulong() #initial process ID object which will we pass by reference
response=u_handle.GetWindowThreadProcessId(hWnd,ctypes.byref(lpdwProcessId))

if response==0:
    print("Error Code: {0} - Could not grab the Process ID".format(k_handle.GetLastError()))
    exit(1)

else:
    print("Process ID grabbed")

dwDesiredAcess=PROCESS_ALL_ACCESS # so that we open a handle with actual priveleges 
inHeritHandle=False

hProcess=k_handle.OpenProcess(dwDesiredAcess,inHeritHandle,lpdwProcessId)

if hProcess<=0:
    print("Error Code: {0} - Could not open the process".format(k_handle.GetLastError()))
    
else:
    print("Process Opened")
    
exitcode=0x1
response=k_handle.TerminateProcess(hProcess,exitcode)

if response==0:
     print("Error Code: {0} - Could not terminate the process".format(k_handle.GetLastError()))
     
else:
    print("Process terminated successfully")