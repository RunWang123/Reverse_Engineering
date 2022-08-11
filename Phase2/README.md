# re-project-phase-2-RunWang123
Package Requirement:
pefile
re
lief
xml
python 3


Compile:
Change the folder name hardcoded in the Script to the your Target File
Use python3 to run it directly.
It will display the configuration to the console.
python3 config_extractor.py
input the absolute path of the target file. for example
File Name -->   -> C:/Users/DevilMayCry/Dropbox/CMU/Reverse_Engineering/Project/Phase2/dump.dll


Here is the sample output
--------------------------------------
File Properties:
--------------------------------------
File Name -->  C:/Users/DevilMayCry/Dropbox/CMU/Reverse_Engineering/Project/Phase2/dump.dll
Path: C:/Users/DevilMayCry/Dropbox/CMU/Reverse_Engineering/Project/Phase2/dump.dll
This is a 32-bit binary
TimeDateStamp : Wed Nov  4 10:02:44 2020 UTC
NumberOfSections : 0x8
Characteristics flags : 0x210e
--------------------------------------
Decryption Report:
--------------------------------------
Decryption Size:  1012
Start Address of Decryption:  b'\x10\x00\xb3\xc0'

Service Name Address:  b'\x10\x00\xb4('
--------------------------------------
Configuration Report:
--------------------------------------
------------------------
Service Related:
------------------------

Service :  windows系统主动防御
b'\x8c\xb4\x00\x10'

Service String Address:  b'\x10\x00\xb4\x8c'

Description :  windows系统主动防御务被禁用，计算机将无法正常运行。

Display_name :  windows系统主动防御

Service_name :  windows系统主动防御

Target Host IP :  http://localhost

Port Number:  8888
------------------------
INI Related:
------------------------

INI Key :  wolf

INI Value :  Group

INI Value :  Remark

INI File Name Address:  b'\x10\x00\xb8\xcc'

INI File Name :  \ini.ini

INI Section Name :  2021-05-30 03:43
------------------------
List All String Decoded In GBK:
------------------------
Description
OFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
ServiceDll
SYSTEM\CurrentControlSet\Services\%s\Parameters
%SystemRoot%%\System32\svchost.exe -k "%s"
inSta0\Default
reateEnvironmentBlock
userenv.dll
s\%d.bak
lugins
mware.exe
vmtoolsd.exe
VBoxService.exe
MWare
VirtualBox
Pause Break]
Shift]
CLEAR]
BACKSPACE]
DELETE]
[INSERT]
Num Lock]
[Down]
[Right]
[Left]
[PageDown]
[End]
Delete]
[PageUp]
[Home]
[Insert]
[Scroll Lock]
Print Screen]
[空格]
[WIN]
CTRL]
[ESC]
Enter]

[标题:]%s
[时间:]%d-%d-%d  %d:%d:%d

<Enter>

BackSpace>
内容:]
eShutdownPrivilege
emark
Rundll32 "%s",Uninstall
undll32 "%s",DllUpdate %s
s\shell\open\command
pplications\iexplore.exe\shell\open\command
抻没У锹阶刺!
CTXOPConntion_Class
02X-%02X-%02X-%02X-%02X-%02X
 %Y/%m/%d %X %A
YSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000
DriverDesc
%dDay %dHour %dMin
%d * %d
ind CPU infomation error
ARDWARE\DESCRIPTION\System\CentralProcessor\0
ProcessorNameString
sBadReadPtr
kernel32.dll
CoCreateInstance
CoUninitialize
CoInitialize
Ole32.dll
ininet.dll
egDeleteValueA
egDeleteKeyA
egSetValueExA
RegCreateKeyExA
egCloseKey
egEnumKeyExA
egEnumValueA
egOpenKeyExA
egQueryValueExA
CreateProcessAsUserA
SetTokenInformation
uplicateTokenEx
OpenProcessToken
DeleteService
hangeServiceConfig2A
reateServiceA
ControlService
QueryServiceStatus
CloseServiceHandle
StartServiceA
penServiceA
OpenSCManagerA
RegisterServiceCtrlHandlerA
etServiceStatus
ADVAPI32.dll
gethostname
etsockname
elect
WSAIoctl
setsockopt
closesocket
connect
ethostbyname
ocket
WSACleanup
WSAStartup
ws2_32.dll
memmove
trstr
memset
memcpy
strlen
strcmp
MSVCRT.dll
EnumWindows
endMessageA
IsWindowVisible
essageBoxA
xitWindowsEx
sprintfA
ser32.dll
Process32Next
rocess32First
CreateToolhelp32Snapshot
GetCurrentProcess
TSGetActiveConsoleSessionId
MoveFileExA
oveFileA
etSystemDirectoryA
etSystemInfo
xpandEnvironmentStringsA
etExitCodeProcess
GetVersionExA
erminateThread
etEvent
CancelIo
ResetEvent
CreateEventA
GetFileAttributesA
WaitForSingleObject
etTickCount
lstrcatA
Sleep
loseHandle
etLastError
ReleaseMutex
CreateMutexA
GetModuleFileNameA
CreateProcessA
60tray.exe
60sdexe
QQPCTray.exe
NisSrv.exe
HipsDaemon.exe
ttp://localhost
windows系统主动防御
indows系统主动防御
indows系统主动防御务被禁用，计算机将无法正常运行。
SystemRoot%\system32\
|睏CUSi鎑}(2%圷閎/猖+\鬄y莩r!A!磋秥H}E&僜3[:噖03
021-05-30 03:43
火绒安全
微软Defender
QQ管家
360杀毒
60安全卫士
etNativeSystemInfo
tlGetNtVersionNumbers
etting
d*%sMHz
HARDWARE\DESCRIPTION\System\CentralProcessor\0
c:\%s
s:%d:%s
GUpdate%s
s "%s",MainInstall
Rundll32.exe
s\%s.exe
ini.ini
GetCurrentThreadId
CloseDesktop
SetThreadDesktop
GetUserObjectInformationA
etThreadDesktop
user32.dll
OpenDesktopA
OpenInputDesktop
InternetCloseHandle
nternetReadFile
InternetOpenUrlA
MSIE 6.0
InternetOpenA
ERNEL32.dll
LookupPrivilegeValueA
djustTokenPrivileges
.?AVtype_info@@

-------------------------------  BAD STRINGS  -------------------------------
Passwords:
        None

Anti-Virus detection:
        None

Regular Expressions:
        None

Privileges:
        None

Oids:
        None

Agents:
        None

File extensions:
        None

SDDLs:
        None

GUIDs:
        None

Registry:
        None

Operating Systems:
        None

Sandbox products:
        None

SIDs:
        None

Protocols:
        None

Utilities:
        Install
        time
        VirtualBox

Keyboard keys:
        [DELETE]
        [Enter]
        [Home]
        [End]
        [Delete]
        [Insert]
        [Print Screen]
        [Scroll Lock]
        [Alt]
        [UP]
        [PageDown]
        [PageUp]
        [Shift]
        [F1]
        [F2]
        [F3]
        [F4]
        [F5]
        [F6]
        [F7]
        [F8]
        [F9]
        [F10]
        [F11]

Operating Systems:
        None

Events:
        None

Insult:
        None