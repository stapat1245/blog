---
title: TryHackMe Volatility essentials Writeup using volatility 2
date: 2025-07-10 12:00:00 +/-TTTT
tags: [tryhackme]     # TAG names should always be lowercase
author: stapat
---
# Solution 
- task 1 - thoery
- task 2 - theory
## task 3

- we have a memory dump and we have to analyse it and find the build version and date when the file was acquired
```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-1.vmem --profile=WinXPSP2x86 imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/data/symlinks/ehax/thm/dfir/Investigation-1.vmem)
                      PAE type : PAE
                           DTB : 0x2fe000L
                          KDBG : 0x80545ae0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2012-07-22 02:45:08 UTC+0000
     Image local date and time : 2012-07-21 22:45:08 -0400
```
- we get the time as 2012-07-22 02:45:08 and if we google the profiles we will get the build version too for this memdump

## task 4

- same file but now we have to find other info , first for the adobe process and its details 

```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-1.vmem --profile=WinXPSP2x86 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x823c89c8 System                    4      0     53      240 ------      0                                                              
0x822f1020 smss.exe                368      4      3       19 ------      0 2012-07-22 02:42:31 UTC+0000                                 
0x822a0598 csrss.exe               584    368      9      326      0      0 2012-07-22 02:42:32 UTC+0000                                 
0x82298700 winlogon.exe            608    368     23      519      0      0 2012-07-22 02:42:32 UTC+0000                                 
0x81e2ab28 services.exe            652    608     16      243      0      0 2012-07-22 02:42:32 UTC+0000                                 
0x81e2a3b8 lsass.exe               664    608     24      330      0      0 2012-07-22 02:42:32 UTC+0000                                 
0x82311360 svchost.exe             824    652     20      194      0      0 2012-07-22 02:42:33 UTC+0000                                 
0x81e29ab8 svchost.exe             908    652      9      226      0      0 2012-07-22 02:42:33 UTC+0000                                 
0x823001d0 svchost.exe            1004    652     64     1118      0      0 2012-07-22 02:42:33 UTC+0000                                 
0x821dfda0 svchost.exe            1056    652      5       60      0      0 2012-07-22 02:42:33 UTC+0000                                 
0x82295650 svchost.exe            1220    652     15      197      0      0 2012-07-22 02:42:35 UTC+0000                                 
0x821dea70 explorer.exe           1484   1464     17      415      0      0 2012-07-22 02:42:36 UTC+0000                                 
0x81eb17b8 spoolsv.exe            1512    652     14      113      0      0 2012-07-22 02:42:36 UTC+0000                                 
0x81e7bda0 reader_sl.exe          1640   1484      5       39      0      0 2012-07-22 02:42:36 UTC+0000                                 
0x820e8da0 alg.exe                 788    652      7      104      0      0 2012-07-22 02:43:01 UTC+0000                                 
0x821fcda0 wuauclt.exe            1136   1004      8      173      0      0 2012-07-22 02:43:46 UTC+0000                                 
0x8205bda0 wuauclt.exe            1588   1004      5      132      0      0 2012-07-22 02:44:01 UTC+0000
```
- we can see the ```reader_sl.exe``` which is the adobe reader(i got to know this too lmao) its PID and PPID(parent process ID) is given which is 1640 and PPID=1484
- for the path we use cmdline 

```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-1.vmem --profile=WinXPSP2x86 cmdline
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
System pid:      4
************************************************************************
smss.exe pid:    368
Command line : \SystemRoot\System32\smss.exe
************************************************************************
csrss.exe pid:    584
Command line : C:\WINDOWS\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16
************************************************************************
winlogon.exe pid:    608
Command line : winlogon.exe
************************************************************************
services.exe pid:    652
Command line : C:\WINDOWS\system32\services.exe
************************************************************************
lsass.exe pid:    664
Command line : C:\WINDOWS\system32\lsass.exe
************************************************************************
svchost.exe pid:    824
Command line : C:\WINDOWS\system32\svchost -k DcomLaunch
************************************************************************
svchost.exe pid:    908
Command line : C:\WINDOWS\system32\svchost -k rpcss
************************************************************************
svchost.exe pid:   1004
Command line : C:\WINDOWS\System32\svchost.exe -k netsvcs
************************************************************************
svchost.exe pid:   1056
Command line : C:\WINDOWS\system32\svchost.exe -k NetworkService
************************************************************************
svchost.exe pid:   1220
Command line : C:\WINDOWS\system32\svchost.exe -k LocalService
************************************************************************
explorer.exe pid:   1484
Command line : C:\WINDOWS\Explorer.EXE
************************************************************************
spoolsv.exe pid:   1512
Command line : C:\WINDOWS\system32\spoolsv.exe
************************************************************************
reader_sl.exe pid:   1640
Command line : "C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe" 
************************************************************************
alg.exe pid:    788
Command line : C:\WINDOWS\System32\alg.exe
************************************************************************
wuauclt.exe pid:   1136
Command line : "C:\WINDOWS\system32\wuauclt.exe" /RunStoreAsComServer Local\[3ec]SUSDSb81eb56fa3105543beb3109274ef8ec1
************************************************************************
wuauclt.exe pid:   1588
Command line : "C:\WINDOWS\system32\wuauclt.exe"
```
- ```C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe``` this is the full path

-  for the next question we use the the dlllist plugin

```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-1.vmem --profile=WinXPSP2x86 dlllist -p 1640
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
reader_sl.exe pid:   1640
Command line : "C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe" 
Service Pack 3

Base             Size  LoadCount LoadTime                       Path
---------- ---------- ---------- ------------------------------ ----
0x00400000     0xa000     0xffff                                C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe
0x7c900000    0xaf000     0xffff                                C:\WINDOWS\system32\ntdll.dll
0x7c800000    0xf6000     0xffff                                C:\WINDOWS\system32\kernel32.dll
0x7e410000    0x91000     0xffff                                C:\WINDOWS\system32\USER32.dll
0x77f10000    0x49000     0xffff                                C:\WINDOWS\system32\GDI32.dll
0x77dd0000    0x9b000     0xffff                                C:\WINDOWS\system32\ADVAPI32.dll
0x77e70000    0x92000     0xffff                                C:\WINDOWS\system32\RPCRT4.dll
0x77fe0000    0x11000     0xffff                                C:\WINDOWS\system32\Secur32.dll
0x7c9c0000   0x817000     0xffff                                C:\WINDOWS\system32\SHELL32.dll
0x77c10000    0x58000     0xffff                                C:\WINDOWS\system32\msvcrt.dll
0x77f60000    0x76000     0xffff                                C:\WINDOWS\system32\SHLWAPI.dll
0x7c420000    0x87000     0xffff                                C:\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6b128700\MSVCP80.dll
0x78130000    0x9b000     0xffff                                C:\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6b128700\MSVCR80.dll
0x773d0000   0x103000        0x1                                C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll
0x5d090000    0x9a000        0x1                                C:\WINDOWS\system32\comctl32.dll
0x5ad70000    0x38000        0x2                                C:\WINDOWS\system32\uxtheme.dll
0x71ab0000    0x17000        0x1                                C:\WINDOWS\system32\WS2_32.dll
0x71aa0000     0x8000        0x1                                C:\WINDOWS\system32\WS2HELP.dll
```
- we can see ```3``` proccesses outside 
```bash
0x7c420000    0x87000     0xffff                                C:\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6b128700\MSVCP80.dll
0x78130000    0x9b000     0xffff                                C:\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6b128700\MSVCR80.dll
0x773d0000   0x103000        0x1                                C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll
```
- for the next keyed events we can use handles plugins with the PID

```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-1.vmem --profile=WinXPSP2x86 handles -p 1640
Volatility Foundation Volatility Framework 2.6.1
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0xe10096e0   1640        0x4    0xf0003 KeyedEvent       CritSecOutOfMemoryEvent
0xe159c978   1640        0x8        0x3 Directory        KnownDlls
0x82211678   1640        0xc   0x100020 File             \Device\HarddiskVolume1\Documents and Settings\Robert
0x82210208   1640       0x10   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6b128700
0xe14916d0   1640       0x14    0xf000f Directory        Windows
0xe1c6a588   1640       0x18  0x21f0001 Port             
0x82319610   1640       0x1c  0x21f0003 Event            
0x8205a2a0   1640       0x20    0xf037f WindowStation    WinSta0
0x822f8168   1640       0x24    0xf01ff Desktop          Default
0x8205a2a0   1640       0x28    0xf037f WindowStation    WinSta0
0x82311280   1640       0x2c   0x100003 Semaphore        
0x82234dd0   1640       0x30   0x100003 Semaphore        
0xe1c042d0   1640       0x34  0x20f003f Key              MACHINE
0xe16ce308   1640       0x38    0x2000f Directory        BaseNamedObjects
0x8213d0e0   1640       0x3c   0x1f0003 Semaphore        shell.{A48F1A32-A340-11D1-BC6B-00A0C90312E1}
0xe1835648   1640       0x40  0x20f003f Key              USER\S-1-5-21-789336058-261478967-1417001333-1003
0x820d2f28   1640       0x44   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0xe1c72300   1640       0x48   0x1f0001 Port             
0xe17d3938   1640       0x4c        0x4 Section          
0x81de10c8   1640       0x50   0x1f0003 Event            
0x822924c8   1640       0x54   0x1f03ff Thread           TID 1648 PID 1640
0x821dd728   1640       0x58   0x1f0003 Event            
0x82196418   1640       0x5c   0x1f0003 Event            
0x820022e0   1640       0x60   0x1f0003 Event            
0x82002a18   1640       0x64   0x1f0003 Event            
0x822924c8   1640       0x68   0x1f03ff Thread           TID 1648 PID 1640
0x821dc270   1640       0x6c   0x100001 File             \Device\KsecDD
0xe1c5cfb8   1640       0x70       0x10 Key              USER\S-1-5-21-789336058-261478967-1417001333-1003\SOFTWARE\MICROSOFT\WSH\8149A9A8
0xe1c6c030   1640       0x74       0x18 Token            
0x81de1e68   1640       0x78   0x1f0003 Event            
0x81dd2e08   1640       0x7c   0x1f0003 IoCompletion     
0x81de3c70   1640       0x80   0x1f0003 IoCompletion     
0x81dd2e08   1640       0x84   0x1f0003 IoCompletion     
0x822fdb00   1640       0x88   0x1f0001 Mutant           XMM00000668
0x822d0d98   1640       0x8c   0x1f0003 Event            XME00000668
0xe154db20   1640       0x90       0x10 Key              USER\S-1-5-21-789336058-261478967-1417001333-1003\SOFTWARE\MICROSOFT\WSH\9DBBCFAD
0x820fd260   1640       0x94   0x1f0003 Semaphore        shell.{210A4BA0-3AEA-1069-A2D9-08002B30309D}
0x81e9d708   1640       0x98   0x1f0001 Mutant           XMR8149A9A8
0x81e1d3c0   1640       0x9c   0x1f0003 Event
```
- the answer is CritSecOutOfMemoryEvent

## task 5
- for this we can use a simple plugin malfind and analyze headers of the files usually the headers of windows executables start from "MZ"
- so in this we count the number of MZ
```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-1.vmem --profile=WinXPSP2x86 malfind
Volatility Foundation Volatility Framework 2.6.1
Process: csrss.exe Pid: 584 Address: 0x7f6f0000
Vad Tag: Vad  Protection: PAGE_EXECUTE_READWRITE
Flags: Protection: 6

0x000000007f6f0000  c8 00 00 00 91 01 00 00 ff ee ff ee 08 70 00 00   .............p..
0x000000007f6f0010  08 00 00 00 00 fe 00 00 00 00 10 00 00 20 00 00   ................
0x000000007f6f0020  00 02 00 00 00 20 00 00 8d 01 00 00 ff ef fd 7f   ................
0x000000007f6f0030  03 00 08 06 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x000000007f6f0000 c8000000         ENTER 0x0, 0x0
0x000000007f6f0004 91               XCHG ECX, EAX
0x000000007f6f0005 0100             ADD [EAX], EAX
0x000000007f6f0007 00ff             ADD BH, BH
0x000000007f6f0009 ee               OUT DX, AL
0x000000007f6f000a ff               DB 0xff
0x000000007f6f000b ee               OUT DX, AL
0x000000007f6f000c 087000           OR [EAX+0x0], DH
0x000000007f6f000f 0008             ADD [EAX], CL
0x000000007f6f0011 0000             ADD [EAX], AL
0x000000007f6f0013 0000             ADD [EAX], AL
0x000000007f6f0015 fe00             INC BYTE [EAX]
0x000000007f6f0017 0000             ADD [EAX], AL
0x000000007f6f0019 0010             ADD [EAX], DL
0x000000007f6f001b 0000             ADD [EAX], AL
0x000000007f6f001d 2000             AND [EAX], AL
0x000000007f6f001f 0000             ADD [EAX], AL
0x000000007f6f0021 0200             ADD AL, [EAX]
0x000000007f6f0023 0000             ADD [EAX], AL
0x000000007f6f0025 2000             AND [EAX], AL
0x000000007f6f0027 008d010000ff     ADD [EBP-0xffffff], CL
0x000000007f6f002d ef               OUT DX, EAX
0x000000007f6f002e fd               STD
0x000000007f6f002f 7f03             JG 0x7f6f0034
0x000000007f6f0031 0008             ADD [EAX], CL
0x000000007f6f0033 06               PUSH ES
0x000000007f6f0034 0000             ADD [EAX], AL
0x000000007f6f0036 0000             ADD [EAX], AL
0x000000007f6f0038 0000             ADD [EAX], AL
0x000000007f6f003a 0000             ADD [EAX], AL
0x000000007f6f003c 0000             ADD [EAX], AL
0x000000007f6f003e 0000             ADD [EAX], AL

Process: winlogon.exe Pid: 608 Address: 0x13410000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x0000000013410000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000013410010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000013410020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000013410030  00 00 00 00 25 00 25 00 01 00 00 00 00 00 00 00   ....%.%.........

0x0000000013410000 0000             ADD [EAX], AL
0x0000000013410002 0000             ADD [EAX], AL
0x0000000013410004 0000             ADD [EAX], AL
0x0000000013410006 0000             ADD [EAX], AL
0x0000000013410008 0000             ADD [EAX], AL
0x000000001341000a 0000             ADD [EAX], AL
0x000000001341000c 0000             ADD [EAX], AL
0x000000001341000e 0000             ADD [EAX], AL
0x0000000013410010 0000             ADD [EAX], AL
0x0000000013410012 0000             ADD [EAX], AL
0x0000000013410014 0000             ADD [EAX], AL
0x0000000013410016 0000             ADD [EAX], AL
0x0000000013410018 0000             ADD [EAX], AL
0x000000001341001a 0000             ADD [EAX], AL
0x000000001341001c 0000             ADD [EAX], AL
0x000000001341001e 0000             ADD [EAX], AL
0x0000000013410020 0000             ADD [EAX], AL
0x0000000013410022 0000             ADD [EAX], AL
0x0000000013410024 0000             ADD [EAX], AL
0x0000000013410026 0000             ADD [EAX], AL
0x0000000013410028 0000             ADD [EAX], AL
0x000000001341002a 0000             ADD [EAX], AL
0x000000001341002c 0000             ADD [EAX], AL
0x000000001341002e 0000             ADD [EAX], AL
0x0000000013410030 0000             ADD [EAX], AL
0x0000000013410032 0000             ADD [EAX], AL
0x0000000013410034 2500250001       AND EAX, 0x1002500
0x0000000013410039 0000             ADD [EAX], AL
0x000000001341003b 0000             ADD [EAX], AL
0x000000001341003d 0000             ADD [EAX], AL
0x000000001341003f 00               DB 0x0

Process: winlogon.exe Pid: 608 Address: 0xf9e0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x000000000f9e0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000000f9e0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000000f9e0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000000f9e0030  00 00 00 00 25 00 25 00 01 00 00 00 00 00 00 00   ....%.%.........

0x000000000f9e0000 0000             ADD [EAX], AL
0x000000000f9e0002 0000             ADD [EAX], AL
0x000000000f9e0004 0000             ADD [EAX], AL
0x000000000f9e0006 0000             ADD [EAX], AL
0x000000000f9e0008 0000             ADD [EAX], AL
0x000000000f9e000a 0000             ADD [EAX], AL
0x000000000f9e000c 0000             ADD [EAX], AL
0x000000000f9e000e 0000             ADD [EAX], AL
0x000000000f9e0010 0000             ADD [EAX], AL
0x000000000f9e0012 0000             ADD [EAX], AL
0x000000000f9e0014 0000             ADD [EAX], AL
0x000000000f9e0016 0000             ADD [EAX], AL
0x000000000f9e0018 0000             ADD [EAX], AL
0x000000000f9e001a 0000             ADD [EAX], AL
0x000000000f9e001c 0000             ADD [EAX], AL
0x000000000f9e001e 0000             ADD [EAX], AL
0x000000000f9e0020 0000             ADD [EAX], AL
0x000000000f9e0022 0000             ADD [EAX], AL
0x000000000f9e0024 0000             ADD [EAX], AL
0x000000000f9e0026 0000             ADD [EAX], AL
0x000000000f9e0028 0000             ADD [EAX], AL
0x000000000f9e002a 0000             ADD [EAX], AL
0x000000000f9e002c 0000             ADD [EAX], AL
0x000000000f9e002e 0000             ADD [EAX], AL
0x000000000f9e0030 0000             ADD [EAX], AL
0x000000000f9e0032 0000             ADD [EAX], AL
0x000000000f9e0034 2500250001       AND EAX, 0x1002500
0x000000000f9e0039 0000             ADD [EAX], AL
0x000000000f9e003b 0000             ADD [EAX], AL
0x000000000f9e003d 0000             ADD [EAX], AL
0x000000000f9e003f 00               DB 0x0

Process: winlogon.exe Pid: 608 Address: 0x4ee0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x0000000004ee0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000004ee0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000004ee0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000004ee0030  00 00 00 00 25 00 25 00 01 00 00 00 00 00 00 00   ....%.%.........

0x0000000004ee0000 0000             ADD [EAX], AL
0x0000000004ee0002 0000             ADD [EAX], AL
0x0000000004ee0004 0000             ADD [EAX], AL
0x0000000004ee0006 0000             ADD [EAX], AL
0x0000000004ee0008 0000             ADD [EAX], AL
0x0000000004ee000a 0000             ADD [EAX], AL
0x0000000004ee000c 0000             ADD [EAX], AL
0x0000000004ee000e 0000             ADD [EAX], AL
0x0000000004ee0010 0000             ADD [EAX], AL
0x0000000004ee0012 0000             ADD [EAX], AL
0x0000000004ee0014 0000             ADD [EAX], AL
0x0000000004ee0016 0000             ADD [EAX], AL
0x0000000004ee0018 0000             ADD [EAX], AL
0x0000000004ee001a 0000             ADD [EAX], AL
0x0000000004ee001c 0000             ADD [EAX], AL
0x0000000004ee001e 0000             ADD [EAX], AL
0x0000000004ee0020 0000             ADD [EAX], AL
0x0000000004ee0022 0000             ADD [EAX], AL
0x0000000004ee0024 0000             ADD [EAX], AL
0x0000000004ee0026 0000             ADD [EAX], AL
0x0000000004ee0028 0000             ADD [EAX], AL
0x0000000004ee002a 0000             ADD [EAX], AL
0x0000000004ee002c 0000             ADD [EAX], AL
0x0000000004ee002e 0000             ADD [EAX], AL
0x0000000004ee0030 0000             ADD [EAX], AL
0x0000000004ee0032 0000             ADD [EAX], AL
0x0000000004ee0034 2500250001       AND EAX, 0x1002500
0x0000000004ee0039 0000             ADD [EAX], AL
0x0000000004ee003b 0000             ADD [EAX], AL
0x0000000004ee003d 0000             ADD [EAX], AL
0x0000000004ee003f 00               DB 0x0

Process: winlogon.exe Pid: 608 Address: 0x554c0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x00000000554c0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x00000000554c0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x00000000554c0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x00000000554c0030  00 00 00 00 28 00 28 00 01 00 00 00 00 00 00 00   ....(.(.........

0x00000000554c0000 0000             ADD [EAX], AL
0x00000000554c0002 0000             ADD [EAX], AL
0x00000000554c0004 0000             ADD [EAX], AL
0x00000000554c0006 0000             ADD [EAX], AL
0x00000000554c0008 0000             ADD [EAX], AL
0x00000000554c000a 0000             ADD [EAX], AL
0x00000000554c000c 0000             ADD [EAX], AL
0x00000000554c000e 0000             ADD [EAX], AL
0x00000000554c0010 0000             ADD [EAX], AL
0x00000000554c0012 0000             ADD [EAX], AL
0x00000000554c0014 0000             ADD [EAX], AL
0x00000000554c0016 0000             ADD [EAX], AL
0x00000000554c0018 0000             ADD [EAX], AL
0x00000000554c001a 0000             ADD [EAX], AL
0x00000000554c001c 0000             ADD [EAX], AL
0x00000000554c001e 0000             ADD [EAX], AL
0x00000000554c0020 0000             ADD [EAX], AL
0x00000000554c0022 0000             ADD [EAX], AL
0x00000000554c0024 0000             ADD [EAX], AL
0x00000000554c0026 0000             ADD [EAX], AL
0x00000000554c0028 0000             ADD [EAX], AL
0x00000000554c002a 0000             ADD [EAX], AL
0x00000000554c002c 0000             ADD [EAX], AL
0x00000000554c002e 0000             ADD [EAX], AL
0x00000000554c0030 0000             ADD [EAX], AL
0x00000000554c0032 0000             ADD [EAX], AL
0x00000000554c0034 2800             SUB [EAX], AL
0x00000000554c0036 2800             SUB [EAX], AL
0x00000000554c0038 0100             ADD [EAX], EAX
0x00000000554c003a 0000             ADD [EAX], AL
0x00000000554c003c 0000             ADD [EAX], AL
0x00000000554c003e 0000             ADD [EAX], AL

Process: winlogon.exe Pid: 608 Address: 0x4dc40000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x000000004dc40000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000004dc40010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000004dc40020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000004dc40030  00 00 00 00 23 00 23 00 01 00 00 00 00 00 00 00   ....#.#.........

0x000000004dc40000 0000             ADD [EAX], AL
0x000000004dc40002 0000             ADD [EAX], AL
0x000000004dc40004 0000             ADD [EAX], AL
0x000000004dc40006 0000             ADD [EAX], AL
0x000000004dc40008 0000             ADD [EAX], AL
0x000000004dc4000a 0000             ADD [EAX], AL
0x000000004dc4000c 0000             ADD [EAX], AL
0x000000004dc4000e 0000             ADD [EAX], AL
0x000000004dc40010 0000             ADD [EAX], AL
0x000000004dc40012 0000             ADD [EAX], AL
0x000000004dc40014 0000             ADD [EAX], AL
0x000000004dc40016 0000             ADD [EAX], AL
0x000000004dc40018 0000             ADD [EAX], AL
0x000000004dc4001a 0000             ADD [EAX], AL
0x000000004dc4001c 0000             ADD [EAX], AL
0x000000004dc4001e 0000             ADD [EAX], AL
0x000000004dc40020 0000             ADD [EAX], AL
0x000000004dc40022 0000             ADD [EAX], AL
0x000000004dc40024 0000             ADD [EAX], AL
0x000000004dc40026 0000             ADD [EAX], AL
0x000000004dc40028 0000             ADD [EAX], AL
0x000000004dc4002a 0000             ADD [EAX], AL
0x000000004dc4002c 0000             ADD [EAX], AL
0x000000004dc4002e 0000             ADD [EAX], AL
0x000000004dc40030 0000             ADD [EAX], AL
0x000000004dc40032 0000             ADD [EAX], AL
0x000000004dc40034 2300             AND EAX, [EAX]
0x000000004dc40036 2300             AND EAX, [EAX]
0x000000004dc40038 0100             ADD [EAX], EAX
0x000000004dc4003a 0000             ADD [EAX], AL
0x000000004dc4003c 0000             ADD [EAX], AL
0x000000004dc4003e 0000             ADD [EAX], AL

Process: winlogon.exe Pid: 608 Address: 0x4c540000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x000000004c540000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000004c540010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000004c540020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000004c540030  00 00 00 00 22 00 22 00 01 00 00 00 00 00 00 00   ....".".........

0x000000004c540000 0000             ADD [EAX], AL
0x000000004c540002 0000             ADD [EAX], AL
0x000000004c540004 0000             ADD [EAX], AL
0x000000004c540006 0000             ADD [EAX], AL
0x000000004c540008 0000             ADD [EAX], AL
0x000000004c54000a 0000             ADD [EAX], AL
0x000000004c54000c 0000             ADD [EAX], AL
0x000000004c54000e 0000             ADD [EAX], AL
0x000000004c540010 0000             ADD [EAX], AL
0x000000004c540012 0000             ADD [EAX], AL
0x000000004c540014 0000             ADD [EAX], AL
0x000000004c540016 0000             ADD [EAX], AL
0x000000004c540018 0000             ADD [EAX], AL
0x000000004c54001a 0000             ADD [EAX], AL
0x000000004c54001c 0000             ADD [EAX], AL
0x000000004c54001e 0000             ADD [EAX], AL
0x000000004c540020 0000             ADD [EAX], AL
0x000000004c540022 0000             ADD [EAX], AL
0x000000004c540024 0000             ADD [EAX], AL
0x000000004c540026 0000             ADD [EAX], AL
0x000000004c540028 0000             ADD [EAX], AL
0x000000004c54002a 0000             ADD [EAX], AL
0x000000004c54002c 0000             ADD [EAX], AL
0x000000004c54002e 0000             ADD [EAX], AL
0x000000004c540030 0000             ADD [EAX], AL
0x000000004c540032 0000             ADD [EAX], AL
0x000000004c540034 2200             AND AL, [EAX]
0x000000004c540036 2200             AND AL, [EAX]
0x000000004c540038 0100             ADD [EAX], EAX
0x000000004c54003a 0000             ADD [EAX], AL
0x000000004c54003c 0000             ADD [EAX], AL
0x000000004c54003e 0000             ADD [EAX], AL

Process: winlogon.exe Pid: 608 Address: 0x5de10000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x000000005de10000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000005de10010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000005de10020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000005de10030  00 00 00 00 22 00 22 00 01 00 00 00 00 00 00 00   ....".".........

0x000000005de10000 0000             ADD [EAX], AL
0x000000005de10002 0000             ADD [EAX], AL
0x000000005de10004 0000             ADD [EAX], AL
0x000000005de10006 0000             ADD [EAX], AL
0x000000005de10008 0000             ADD [EAX], AL
0x000000005de1000a 0000             ADD [EAX], AL
0x000000005de1000c 0000             ADD [EAX], AL
0x000000005de1000e 0000             ADD [EAX], AL
0x000000005de10010 0000             ADD [EAX], AL
0x000000005de10012 0000             ADD [EAX], AL
0x000000005de10014 0000             ADD [EAX], AL
0x000000005de10016 0000             ADD [EAX], AL
0x000000005de10018 0000             ADD [EAX], AL
0x000000005de1001a 0000             ADD [EAX], AL
0x000000005de1001c 0000             ADD [EAX], AL
0x000000005de1001e 0000             ADD [EAX], AL
0x000000005de10020 0000             ADD [EAX], AL
0x000000005de10022 0000             ADD [EAX], AL
0x000000005de10024 0000             ADD [EAX], AL
0x000000005de10026 0000             ADD [EAX], AL
0x000000005de10028 0000             ADD [EAX], AL
0x000000005de1002a 0000             ADD [EAX], AL
0x000000005de1002c 0000             ADD [EAX], AL
0x000000005de1002e 0000             ADD [EAX], AL
0x000000005de10030 0000             ADD [EAX], AL
0x000000005de10032 0000             ADD [EAX], AL
0x000000005de10034 2200             AND AL, [EAX]
0x000000005de10036 2200             AND AL, [EAX]
0x000000005de10038 0100             ADD [EAX], EAX
0x000000005de1003a 0000             ADD [EAX], AL
0x000000005de1003c 0000             ADD [EAX], AL
0x000000005de1003e 0000             ADD [EAX], AL

Process: winlogon.exe Pid: 608 Address: 0x6a230000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x000000006a230000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000006a230010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000006a230020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x000000006a230030  00 00 00 00 2b 00 2b 00 01 00 00 00 00 00 00 00   ....+.+.........

0x000000006a230000 0000             ADD [EAX], AL
0x000000006a230002 0000             ADD [EAX], AL
0x000000006a230004 0000             ADD [EAX], AL
0x000000006a230006 0000             ADD [EAX], AL
0x000000006a230008 0000             ADD [EAX], AL
0x000000006a23000a 0000             ADD [EAX], AL
0x000000006a23000c 0000             ADD [EAX], AL
0x000000006a23000e 0000             ADD [EAX], AL
0x000000006a230010 0000             ADD [EAX], AL
0x000000006a230012 0000             ADD [EAX], AL
0x000000006a230014 0000             ADD [EAX], AL
0x000000006a230016 0000             ADD [EAX], AL
0x000000006a230018 0000             ADD [EAX], AL
0x000000006a23001a 0000             ADD [EAX], AL
0x000000006a23001c 0000             ADD [EAX], AL
0x000000006a23001e 0000             ADD [EAX], AL
0x000000006a230020 0000             ADD [EAX], AL
0x000000006a230022 0000             ADD [EAX], AL
0x000000006a230024 0000             ADD [EAX], AL
0x000000006a230026 0000             ADD [EAX], AL
0x000000006a230028 0000             ADD [EAX], AL
0x000000006a23002a 0000             ADD [EAX], AL
0x000000006a23002c 0000             ADD [EAX], AL
0x000000006a23002e 0000             ADD [EAX], AL
0x000000006a230030 0000             ADD [EAX], AL
0x000000006a230032 0000             ADD [EAX], AL
0x000000006a230034 2b00             SUB EAX, [EAX]
0x000000006a230036 2b00             SUB EAX, [EAX]
0x000000006a230038 0100             ADD [EAX], EAX
0x000000006a23003a 0000             ADD [EAX], AL
0x000000006a23003c 0000             ADD [EAX], AL
0x000000006a23003e 0000             ADD [EAX], AL

Process: winlogon.exe Pid: 608 Address: 0x73f40000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 4, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x0000000073f40000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000073f40010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000073f40020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000073f40030  00 00 00 00 2a 00 2a 00 01 00 00 00 00 00 00 00   ....*.*.........

0x0000000073f40000 0000             ADD [EAX], AL
0x0000000073f40002 0000             ADD [EAX], AL
0x0000000073f40004 0000             ADD [EAX], AL
0x0000000073f40006 0000             ADD [EAX], AL
0x0000000073f40008 0000             ADD [EAX], AL
0x0000000073f4000a 0000             ADD [EAX], AL
0x0000000073f4000c 0000             ADD [EAX], AL
0x0000000073f4000e 0000             ADD [EAX], AL
0x0000000073f40010 0000             ADD [EAX], AL
0x0000000073f40012 0000             ADD [EAX], AL
0x0000000073f40014 0000             ADD [EAX], AL
0x0000000073f40016 0000             ADD [EAX], AL
0x0000000073f40018 0000             ADD [EAX], AL
0x0000000073f4001a 0000             ADD [EAX], AL
0x0000000073f4001c 0000             ADD [EAX], AL
0x0000000073f4001e 0000             ADD [EAX], AL
0x0000000073f40020 0000             ADD [EAX], AL
0x0000000073f40022 0000             ADD [EAX], AL
0x0000000073f40024 0000             ADD [EAX], AL
0x0000000073f40026 0000             ADD [EAX], AL
0x0000000073f40028 0000             ADD [EAX], AL
0x0000000073f4002a 0000             ADD [EAX], AL
0x0000000073f4002c 0000             ADD [EAX], AL
0x0000000073f4002e 0000             ADD [EAX], AL
0x0000000073f40030 0000             ADD [EAX], AL
0x0000000073f40032 0000             ADD [EAX], AL
0x0000000073f40034 2a00             SUB AL, [EAX]
0x0000000073f40036 2a00             SUB AL, [EAX]
0x0000000073f40038 0100             ADD [EAX], EAX
0x0000000073f4003a 0000             ADD [EAX], AL
0x0000000073f4003c 0000             ADD [EAX], AL
0x0000000073f4003e 0000             ADD [EAX], AL

Process: explorer.exe Pid: 1484 Address: 0x1460000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 33, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x0000000001460000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x0000000001460010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x0000000001460020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000001460030  00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 00   ................

0x0000000001460000 4d               DEC EBP
0x0000000001460001 5a               POP EDX
0x0000000001460002 90               NOP
0x0000000001460003 0003             ADD [EBX], AL
0x0000000001460005 0000             ADD [EAX], AL
0x0000000001460007 000400           ADD [EAX+EAX], AL
0x000000000146000a 0000             ADD [EAX], AL
0x000000000146000c ff               DB 0xff
0x000000000146000d ff00             INC DWORD [EAX]
0x000000000146000f 00b800000000     ADD [EAX+0x0], BH
0x0000000001460015 0000             ADD [EAX], AL
0x0000000001460017 004000           ADD [EAX+0x0], AL
0x000000000146001a 0000             ADD [EAX], AL
0x000000000146001c 0000             ADD [EAX], AL
0x000000000146001e 0000             ADD [EAX], AL
0x0000000001460020 0000             ADD [EAX], AL
0x0000000001460022 0000             ADD [EAX], AL
0x0000000001460024 0000             ADD [EAX], AL
0x0000000001460026 0000             ADD [EAX], AL
0x0000000001460028 0000             ADD [EAX], AL
0x000000000146002a 0000             ADD [EAX], AL
0x000000000146002c 0000             ADD [EAX], AL
0x000000000146002e 0000             ADD [EAX], AL
0x0000000001460030 0000             ADD [EAX], AL
0x0000000001460032 0000             ADD [EAX], AL
0x0000000001460034 0000             ADD [EAX], AL
0x0000000001460036 0000             ADD [EAX], AL
0x0000000001460038 0000             ADD [EAX], AL
0x000000000146003a 0000             ADD [EAX], AL
0x000000000146003c e000             LOOPNZ 0x146003e
0x000000000146003e 0000             ADD [EAX], AL

Process: reader_sl.exe Pid: 1640 Address: 0x3d0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 33, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x00000000003d0000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x00000000003d0010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x00000000003d0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x00000000003d0030  00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 00   ................

0x00000000003d0000 4d               DEC EBP
0x00000000003d0001 5a               POP EDX
0x00000000003d0002 90               NOP
0x00000000003d0003 0003             ADD [EBX], AL
0x00000000003d0005 0000             ADD [EAX], AL
0x00000000003d0007 000400           ADD [EAX+EAX], AL
0x00000000003d000a 0000             ADD [EAX], AL
0x00000000003d000c ff               DB 0xff
0x00000000003d000d ff00             INC DWORD [EAX]
0x00000000003d000f 00b800000000     ADD [EAX+0x0], BH
0x00000000003d0015 0000             ADD [EAX], AL
0x00000000003d0017 004000           ADD [EAX+0x0], AL
0x00000000003d001a 0000             ADD [EAX], AL
0x00000000003d001c 0000             ADD [EAX], AL
0x00000000003d001e 0000             ADD [EAX], AL
0x00000000003d0020 0000             ADD [EAX], AL
0x00000000003d0022 0000             ADD [EAX], AL
0x00000000003d0024 0000             ADD [EAX], AL
0x00000000003d0026 0000             ADD [EAX], AL
0x00000000003d0028 0000             ADD [EAX], AL
0x00000000003d002a 0000             ADD [EAX], AL
0x00000000003d002c 0000             ADD [EAX], AL
0x00000000003d002e 0000             ADD [EAX], AL
0x00000000003d0030 0000             ADD [EAX], AL
0x00000000003d0032 0000             ADD [EAX], AL
0x00000000003d0034 0000             ADD [EAX], AL
0x00000000003d0036 0000             ADD [EAX], AL
0x00000000003d0038 0000             ADD [EAX], AL
0x00000000003d003a 0000             ADD [EAX], AL
0x00000000003d003c e000             LOOPNZ 0x3d003e
0x00000000003d003e 0000             ADD [EAX], AL
```
- we found two processes "reader_sl.exe" and "explorer.exe"

## task 6
- for this we use the ssdt plugin
```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-1.vmem --profile=WinXPSP2x86 ssdt | grep NtCr
Volatility Foundation Volatility Framework 2.6.1
  Entry 0x0021: 0x806389aa (NtCreateDebugObject) owned by ntoskrnl.exe
  Entry 0x0022: 0x805b3c6e (NtCreateDirectoryObject) owned by ntoskrnl.exe
  Entry 0x0023: 0x80605124 (NtCreateEvent) owned by ntoskrnl.exe
  Entry 0x0024: 0x8060d3c6 (NtCreateEventPair) owned by ntoskrnl.exe
  Entry 0x0025: 0x8056e27c (NtCreateFile) owned by ntoskrnl.exe
  Entry 0x0026: 0x8056dc5a (NtCreateIoCompletion) owned by ntoskrnl.exe
  Entry 0x0027: 0x805cb888 (NtCreateJobObject) owned by ntoskrnl.exe
  Entry 0x0028: 0x805cb5c0 (NtCreateJobSet) owned by ntoskrnl.exe
  Entry 0x0029: 0x8061a286 (NtCreateKey) owned by ntoskrnl.exe
  Entry 0x002a: 0x8056e38a (NtCreateMailslotFile) owned by ntoskrnl.exe
  Entry 0x002b: 0x8060d7be (NtCreateMutant) owned by ntoskrnl.exe
  Entry 0x002c: 0x8056e2b6 (NtCreateNamedPipeFile) owned by ntoskrnl.exe
  Entry 0x002d: 0x805a0da8 (NtCreatePagingFile) owned by ntoskrnl.exe
  Entry 0x002e: 0x8059a404 (NtCreatePort) owned by ntoskrnl.exe
  Entry 0x002f: 0x805c7420 (NtCreateProcess) owned by ntoskrnl.exe
  Entry 0x0030: 0x805c736a (NtCreateProcessEx) owned by ntoskrnl.exe
  Entry 0x0031: 0x8060dbde (NtCreateProfile) owned by ntoskrnl.exe
  Entry 0x0032: 0x805a06ec (NtCreateSection) owned by ntoskrnl.exe
  Entry 0x0033: 0x8060b15a (NtCreateSemaphore) owned by ntoskrnl.exe
  Entry 0x0034: 0x805b9594 (NtCreateSymbolicLinkObject) owned by ntoskrnl.exe
  Entry 0x0035: 0x805c7208 (NtCreateThread) owned by ntoskrnl.exe
  Entry 0x0036: 0x8060d08e (NtCreateTimer) owned by ntoskrnl.exe
  Entry 0x0037: 0x805ef3d0 (NtCreateToken) owned by ntoskrnl.exe
  Entry 0x0038: 0x8059a428 (NtCreateWaitablePort) owned by ntoskrnl.exe
  Entry 0x0117: 0x8060e632 (NtCreateKeyedEvent) owned by ntoskrnl.exe
```
-  got the answer 

## task 7

- now this has new memory dump 
- getting the basic info about the dump
```
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-2.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/data/symlinks/ehax/thm/dfir/Investigation-2.raw)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cf60L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2017-05-12 21:26:32 UTC+0000
     Image local date and time : 2017-05-13 02:56:32 +0530
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-2.raw --profile=WinXPSP2x86 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x823c8830 System                    4      0     51      244 ------      0                                                              
0x82169020 smss.exe                348      4      3       19 ------      0 2017-05-12 21:21:55 UTC+0000                                 
0x82161da0 csrss.exe               596    348     12      352      0      0 2017-05-12 21:22:00 UTC+0000                                 
0x8216e020 winlogon.exe            620    348     23      536      0      0 2017-05-12 21:22:01 UTC+0000                                 
0x821937f0 services.exe            664    620     15      265      0      0 2017-05-12 21:22:01 UTC+0000                                 
0x82191658 lsass.exe               676    620     23      353      0      0 2017-05-12 21:22:01 UTC+0000                                 
0x8221a2c0 svchost.exe             836    664     19      211      0      0 2017-05-12 21:22:02 UTC+0000                                 
0x821b5230 svchost.exe             904    664      9      227      0      0 2017-05-12 21:22:03 UTC+0000                                 
0x821af7e8 svchost.exe            1024    664     79     1366      0      0 2017-05-12 21:22:03 UTC+0000                                 
0x8203b7a8 svchost.exe            1084    664      6       72      0      0 2017-05-12 21:22:03 UTC+0000                                 
0x821bea78 svchost.exe            1152    664     10      173      0      0 2017-05-12 21:22:06 UTC+0000                                 
0x821e2da0 spoolsv.exe            1484    664     14      124      0      0 2017-05-12 21:22:09 UTC+0000                                 
0x821d9da0 explorer.exe           1636   1608     11      331      0      0 2017-05-12 21:22:10 UTC+0000                                 
0x82218da0 tasksche.exe           1940   1636      7       51      0      0 2017-05-12 21:22:14 UTC+0000                                 
0x82231da0 ctfmon.exe             1956   1636      1       86      0      0 2017-05-12 21:22:14 UTC+0000                                 
0x81fb95d8 svchost.exe             260    664      5      105      0      0 2017-05-12 21:22:18 UTC+0000                                 
0x81fde308 @WanaDecryptor@         740   1940      2       70      0      0 2017-05-12 21:22:22 UTC+0000                                 
0x81f747c0 wuauclt.exe            1768   1024      7      132      0      0 2017-05-12 21:22:52 UTC+0000                                 
0x82010020 alg.exe                 544    664      6      101      0      0 2017-05-12 21:22:55 UTC+0000                                 
0x81fea8a0 wscntfy.exe            1168   1024      1       37      0      0 2017-05-12 21:22:56 UTC+0000
```
- we get the answer of the first question and the third question and the (@WannaDecryptor@ & tasksche.exe)
- we can get the 2nd answer with cmdline
```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-2.raw --profile=WinXPSP2x86 cmdline
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
System pid:      4
************************************************************************
smss.exe pid:    348
Command line : \SystemRoot\System32\smss.exe
************************************************************************
csrss.exe pid:    596
Command line : C:\WINDOWS\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16
************************************************************************
winlogon.exe pid:    620
Command line : winlogon.exe
************************************************************************
services.exe pid:    664
Command line : C:\WINDOWS\system32\services.exe
************************************************************************
lsass.exe pid:    676
Command line : C:\WINDOWS\system32\lsass.exe
************************************************************************
svchost.exe pid:    836
Command line : C:\WINDOWS\system32\svchost -k DcomLaunch
************************************************************************
svchost.exe pid:    904
Command line : C:\WINDOWS\system32\svchost -k rpcss
************************************************************************
svchost.exe pid:   1024
Command line : C:\WINDOWS\System32\svchost.exe -k netsvcs
************************************************************************
svchost.exe pid:   1084
Command line : C:\WINDOWS\system32\svchost.exe -k NetworkService
************************************************************************
svchost.exe pid:   1152
Command line : C:\WINDOWS\system32\svchost.exe -k LocalService
************************************************************************
spoolsv.exe pid:   1484
Command line : C:\WINDOWS\system32\spoolsv.exe
************************************************************************
explorer.exe pid:   1636
Command line : C:\WINDOWS\Explorer.EXE
************************************************************************
tasksche.exe pid:   1940
Command line : "C:\Intel\ivecuqmanpnirkt615\tasksche.exe" 
************************************************************************
ctfmon.exe pid:   1956
Command line : "C:\WINDOWS\system32\ctfmon.exe" 
************************************************************************
svchost.exe pid:    260
Command line : C:\WINDOWS\system32\svchost.exe -k LocalService
************************************************************************
@WanaDecryptor@ pid:    740
Command line : @WanaDecryptor@.exe
************************************************************************
wuauclt.exe pid:   1768
Command line : "C:\WINDOWS\system32\wuauclt.exe" /RunStoreAsComServer Local\[400]SUSDS81a6658cb72fa845814e75cca9a42bf2
************************************************************************
alg.exe pid:    544
Command line : C:\WINDOWS\System32\alg.exe
************************************************************************
wscntfy.exe pid:   1168
Command line : C:\WINDOWS\system32\wscntfy.exe
```
- okay so we did not got this time , we can use dlllist plugin for more info
```bash
stapat@stapat:~/ehax/thm/dfir$ volatility -f Investigation-2.raw --profile=WinXPSP2x86 dlllist -p 740
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
@WanaDecryptor@ pid:    740
Command line : @WanaDecryptor@.exe
Service Pack 3

Base             Size  LoadCount LoadTime                       Path
---------- ---------- ---------- ------------------------------ ----
0x00400000    0x3d000     0xffff                                C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
0x7c900000    0xb2000     0xffff                                C:\WINDOWS\system32\ntdll.dll
0x7c800000    0xf6000     0xffff                                C:\WINDOWS\system32\kernel32.dll
0x73dd0000    0xf2000     0xffff                                C:\WINDOWS\system32\MFC42.DLL
0x77c10000    0x58000     0xffff                                C:\WINDOWS\system32\msvcrt.dll
0x77f10000    0x49000     0xffff                                C:\WINDOWS\system32\GDI32.dll
0x7e410000    0x91000     0xffff                                C:\WINDOWS\system32\USER32.dll
0x77dd0000    0x9b000     0xffff                                C:\WINDOWS\system32\ADVAPI32.dll
0x77e70000    0x93000     0xffff                                C:\WINDOWS\system32\RPCRT4.dll
0x77fe0000    0x11000     0xffff                                C:\WINDOWS\system32\Secur32.dll
0x7c9c0000   0x818000     0xffff                                C:\WINDOWS\system32\SHELL32.dll
0x77f60000    0x76000     0xffff                                C:\WINDOWS\system32\SHLWAPI.dll
0x773d0000   0x103000     0xffff                                C:\WINDOWS\WinSxS\X86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202\COMCTL32.dll
0x77120000    0x8b000     0xffff                                C:\WINDOWS\system32\OLEAUT32.dll
0x774e0000   0x13e000     0xffff                                C:\WINDOWS\system32\ole32.dll
0x78130000   0x134000     0xffff                                C:\WINDOWS\system32\urlmon.dll
0x3dfd0000   0x1ec000     0xffff                                C:\WINDOWS\system32\iertutil.dll
0x76080000    0x65000     0xffff                                C:\WINDOWS\system32\MSVCP60.dll
0x71ab0000    0x17000     0xffff                                C:\WINDOWS\system32\WS2_32.dll
0x71aa0000     0x8000     0xffff                                C:\WINDOWS\system32\WS2HELP.dll
0x3d930000    0xe7000     0xffff                                C:\WINDOWS\system32\WININET.dll
0x00340000     0x9000     0xffff                                C:\WINDOWS\system32\Normaliz.dll
0x76390000    0x1d000        0x4                                C:\WINDOWS\system32\IMM32.DLL
0x629c0000     0x9000        0x1                                C:\WINDOWS\system32\LPK.DLL
0x74d90000    0x6b000        0x2                                C:\WINDOWS\system32\USP10.dll
0x732e0000     0x5000        0x1                                C:\WINDOWS\system32\RICHED32.DLL
0x74e30000    0x6d000        0x1                                C:\WINDOWS\system32\RICHED20.dll
0x5ad70000    0x38000        0x3                                C:\WINDOWS\system32\uxtheme.dll
0x74720000    0x4c000        0x1                                C:\WINDOWS\system32\MSCTF.dll
0x755c0000    0x2e000        0x2                                C:\WINDOWS\system32\msctfime.ime
0x769c0000    0xb4000        0x1                                C:\WINDOWS\system32\USERENV.dll
0x00ea0000    0x29000        0x1                                C:\WINDOWS\system32\msls31.dll
```
- now we got our answer ```C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe``` 
- and just from google search we got the answer to the second last question - wannacry 
- last answer is windows.filescan(WHO TF USES WINDOWS. , AVERAGE VOLATILITY 3 L)

- THANK YOU