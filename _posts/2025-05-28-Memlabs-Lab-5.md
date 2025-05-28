---
title: Memlabs Lab 4 Writeup
date: 2025-05-28 9:00:00 +/-TTTT
tags: [memlabs]     # TAG names should always be lowercase
author: stapat
---

# Lab 5 
```
We received this memory dump from our client recently. Someone accessed his system when he was not there and he found some rather strange files being accessed. Find those files and they might be useful. I quote his exact statement,

The names were not readable. They were composed of alphabets and numbers but I wasn't able to make out what exactly it was.

Also, he noticed his most loved application that he always used crashed every time he ran it. Was it a virus?

Note-1: This challenge is composed of 3 flags. If you think 2nd flag is the end, it isn't!! :P

Note-2: There was a small mistake when making this challenge. If you find any string which has the string "L4B_3_D0n3!!" in it, please change it to "L4B_5_D0n3!!" and then proceed.

Note-3: You'll get the stage 2 flag only when you have the stage 1 flag.
```
# Solution

- looking at the image profile and the processes 

```bash
stapat@stapat:~/ehax/dfir/memlabs/lab5$ volatility -f chall.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/data/symlinks/ehax/dfir/memlabs/lab5/chall.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028460a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002847d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-12-20 03:47:57 UTC+0000
     Image local date and time : 2019-12-20 09:17:57 +0530
stapat@stapat:~/ehax/dfir/memlabs/lab5$ volatility -f chall.raw --profile=Win7SP1x64
Volatility Foundation Volatility Framework 2.6.1
ERROR   : volatility.debug    : You must specify something to do (try -h)
stapat@stapat:~/ehax/dfir/memlabs/lab5$ volatility -f chall.raw --profile=Win7SP1x64 psxview
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
------------------ -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
0x000000003eeb9880 lsass.exe               492 True   True   True     True   True  True    False    
0x000000003ec6c700 svchost.exe            1044 True   True   True     True   True  True    True     
0x000000003e81ab30 NOTEPAD.EXE            1388 True   True   True     True   True  True    False    
0x000000003fa213d0 explorer.exe           1580 True   True   True     True   True  True    False    
0x000000003ef63b30 svchost.exe             724 True   True   True     True   True  True    True     
0x000000003fdb34d0 dwm.exe                2360 True   True   True     True   True  True    False    
0x000000003fdcd8e0 taskhost.exe           1968 True   True   True     True   True  True    False    
0x000000003fce8060 WerFault.exe           2716 True   True   True     True   True  True    False    
0x000000003f6a6390 svchost.exe            1128 True   True   True     True   True  True    False    
0x000000003eee6b30 svchost.exe             588 True   True   True     True   True  True    True     
0x000000003fd97a20 WinRAR.exe             2924 True   True   True     True   True  True    False    
0x000000003fca7b30 SearchProtocol          628 True   True   True     True   True  True    True     
0x000000003ee775a0 winlogon.exe            416 True   True   True     True   True  True    True     
0x000000003e82d7a0 SearchIndexer.         1800 True   True   True     True   True  True    True     
0x000000003fef4b30 audiodg.exe             968 True   True   True     True   True  True    True     
0x000000003fcab790 conhost.exe            2612 True   True   True     True   True  True    False    
0x000000003fd27b30 dllhost.exe             668 True   True   True     True   True  True    True     
0x000000003e806890 VBoxTray.exe            528 True   True   True     True   True  True    True     
0x000000003ef4cb30 VBoxService.ex          656 True   True   True     True   True  True    True     
0x000000003e8a9b30 wmpnetwk.exe           1928 True   True   True     True   True  True    True     
0x000000003fceb060 DumpIt.exe             2208 True   True   True     True   True  True    False    
0x000000003fcfbb30 WerFault.exe            780 True   True   True     False  True  True    False    
0x000000003fa8cb30 NOTEPAD.EXE            2724 True   True   True     True   True  True    False    
0x000000003eb70b30 dwm.exe                1172 True   True   True     True   True  True    True     
0x000000003efa1240 svchost.exe             820 True   True   True     True   True  True    True     
0x000000003ee7c060 wininit.exe             428 True   True   True     True   True  True    True     
0x000000003ecc57c0 svchost.exe            2296 True   True   True     True   True  True    False    
0x000000003fd63060 SearchFilterHo         2608 True   True   True     True   True  True    True     
0x000000003ed93b30 TCPSVCS.EXE            1416 True   True   True     True   True  True    True     
0x000000003fab8060 notepad.exe            2744 True   True   True     True   True  True    False    
0x000000003efbf350 taskhost.exe           2012 True   True   True     True   True  True    True     
0x000000003efba060 svchost.exe             856 True   True   True     True   True  True    True     
0x000000003eb17b30 taskeng.exe            1140 True   True   True     True   True  True    True     
0x000000003eb98b30 explorer.exe           1396 True   True   True     True   True  True    True     
0x000000003ee6b060 psxss.exe               376 True   True   True     True   True  True    True     
0x000000003ee3e910 WmiPrvSE.exe           2572 True   True   True     True   True  True    True     
0x000000003ee7bb30 services.exe            484 True   True   True     True   True  True    False    
0x000000003fa9f060 svchost.exe            2632 True   True   True     True   True  True    True     
0x000000003ecfbb30 svchost.exe            1272 True   True   True     True   True  True    True     
0x000000003eebc4a0 lsm.exe                 500 True   True   True     True   True  True    False    
0x000000003fa5ab30 VBoxTray.exe           2144 True   True   True     True   True  True    False    
0x000000003ec1cb30 svchost.exe             340 True   True   True     True   True  True    True     
0x000000003ed775f0 svchost.exe            1372 True   True   True     True   True  True    True     
0x000000003ece1060 spoolsv.exe            1232 True   True   True     True   True  True    True     
0x000000003ea9b760 sppsvc.exe             2940 True   True   True     True   True  True    True     
0x000000003fd82060 winlogon.exe           2120 True   True   True     True   True  True    True     
0x000000003efc2b30 svchost.exe             880 True   True   True     True   True  True    True     
0x000000003f6b9040 smss.exe                248 True   True   True     True   False False   False    
0x000000003ff5f040 System                    4 True   True   True     True   False False   False    
0x000000003ee5d060 csrss.exe               368 True   True   True     True   False True    True     
0x000000003fe55b30 csrss.exe               320 True   True   True     True   False True    True     
0x000000003fd7a630 csrss.exe              1988 True   True   True     True   False True    False    
0x000000003fd02b30 NOTEPAD.EXE            2056 True   True   True     False  False True    False    
0x000000003fd05b30 WerFault.exe           2168 True   True   True     False  False True    False    
0x000000003fafd3d0 explorer.exe           1580 False  True   False    False  False False   False    
0x000000003fb36b30 VBoxTray.exe           2144 False  True   False    False  False False   False    
0x000000003fb68b30 NOTEPAD.EXE            2724 False  True   False    False  False False   False    
0x000000003fb94060 notepad.exe            2744 False  True   False    False  False False   False    
0x000000003fb7b060 svchost.exe            2632 False  True   False    False  False False   False    
0x000000003fbd93d0 explorer.exe           1580 False  True   False    False  False False   False
```

- we can see notepad.exe , NOTEPAD.EXE(most probably red herring), WinRar.exe , so now we should look for files related to these , using filescan , consoles and cmdline for a clear vision whats going on

```bash
stapat@stapat:~/ehax/dfir/memlabs/lab5$ volatility -f chall.raw --profile=Win7SP1x64 cmdline
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
System pid:      4
************************************************************************
smss.exe pid:    248
Command line : \SystemRoot\System32\smss.exe
************************************************************************
csrss.exe pid:    320
Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
************************************************************************
csrss.exe pid:    368
Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
************************************************************************
psxss.exe pid:    376
Command line : %SystemRoot%\system32\psxss.exe
************************************************************************
winlogon.exe pid:    416
Command line : winlogon.exe
************************************************************************
wininit.exe pid:    428
Command line : wininit.exe
************************************************************************
services.exe pid:    484
Command line : C:\Windows\system32\services.exe
************************************************************************
lsass.exe pid:    492
Command line : C:\Windows\system32\lsass.exe
************************************************************************
lsm.exe pid:    500
Command line : C:\Windows\system32\lsm.exe
************************************************************************
svchost.exe pid:    588
Command line : C:\Windows\system32\svchost.exe -k DcomLaunch
************************************************************************
VBoxService.ex pid:    656
Command line : C:\Windows\System32\VBoxService.exe
************************************************************************
svchost.exe pid:    724
Command line : C:\Windows\system32\svchost.exe -k RPCSS
************************************************************************
svchost.exe pid:    820
Command line : C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
************************************************************************
svchost.exe pid:    856
Command line : C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
************************************************************************
svchost.exe pid:    880
Command line : C:\Windows\system32\svchost.exe -k netsvcs
************************************************************************
audiodg.exe pid:    968
Command line : C:\Windows\system32\AUDIODG.EXE 0x2a8
************************************************************************
svchost.exe pid:    340
Command line : C:\Windows\system32\svchost.exe -k LocalService
************************************************************************
svchost.exe pid:   1044
Command line : C:\Windows\system32\svchost.exe -k NetworkService
************************************************************************
spoolsv.exe pid:   1232
Command line : C:\Windows\System32\spoolsv.exe
************************************************************************
svchost.exe pid:   1272
Command line : C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
************************************************************************
svchost.exe pid:   1372
Command line : C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation
************************************************************************
TCPSVCS.EXE pid:   1416
Command line : C:\Windows\System32\tcpsvcs.exe
************************************************************************
taskhost.exe pid:   2012
Command line : "taskhost.exe"
************************************************************************
taskeng.exe pid:   1140
Command line : taskeng.exe {1CE5BA55-4ED9-45CF-89C9-63EFFA573860}
************************************************************************
dwm.exe pid:   1172
Command line : "C:\Windows\system32\Dwm.exe"
************************************************************************
explorer.exe pid:   1396
Command line : C:\Windows\Explorer.EXE
************************************************************************
VBoxTray.exe pid:    528
Command line : "C:\Windows\System32\VBoxTray.exe" 
************************************************************************
SearchIndexer. pid:   1800
Command line : C:\Windows\system32\SearchIndexer.exe /Embedding
************************************************************************
wmpnetwk.exe pid:   1928
Command line : "C:\Program Files\Windows Media Player\wmpnetwk.exe"
************************************************************************
svchost.exe pid:   2296
Command line : C:\Windows\System32\svchost.exe -k LocalServicePeerNet
************************************************************************
WmiPrvSE.exe pid:   2572
Command line : C:\Windows\system32\wbem\wmiprvse.exe
************************************************************************
sppsvc.exe pid:   2940
Command line : C:\Windows\system32\sppsvc.exe
************************************************************************
svchost.exe pid:   1128
Command line : C:\Windows\System32\svchost.exe -k secsvcs
************************************************************************
dllhost.exe pid:    668
Command line : C:\Windows\system32\DllHost.exe /Processid:{76D0CB12-7604-4048-B83C-1005C7DDC503}
************************************************************************
SearchFilterHo pid:   2608
Command line : "C:\Windows\system32\SearchFilterHost.exe" 0 504 508 516 65536 512 
************************************************************************
SearchProtocol pid:    628
Command line : "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe3_ Global\UsGthrCtrlFltPipeMssGthrPipe3 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" 
************************************************************************
csrss.exe pid:   1988
Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
************************************************************************
winlogon.exe pid:   2120
Command line : winlogon.exe
************************************************************************
taskhost.exe pid:   1968
Command line : "taskhost.exe"
************************************************************************
dwm.exe pid:   2360
Command line : "C:\Windows\system32\Dwm.exe"
************************************************************************
explorer.exe pid:   1580
Command line : C:\Windows\Explorer.EXE
************************************************************************
VBoxTray.exe pid:   2144
Command line : "C:\Windows\System32\VBoxTray.exe" 
************************************************************************
WinRAR.exe pid:   2924
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\SmartNet\Documents\SW1wb3J0YW50.rar"
************************************************************************
notepad.exe pid:   2744
Command line : "C:\Windows\system32\notepad.exe" 
************************************************************************
DumpIt.exe pid:   2208
Command line : "C:\Users\SmartNet\Downloads\DumpIt\DumpIt.exe" 
************************************************************************
conhost.exe pid:   2612
Command line : \??\C:\Windows\system32\conhost.exe
************************************************************************
NOTEPAD.EXE pid:   2724
Command line : "C:\Users\SmartNet\Videos\NOTEPAD.EXE" 
************************************************************************
svchost.exe pid:   2632
Command line : C:\Windows\System32\svchost.exe -k WerSvcGroup
************************************************************************
WerFault.exe pid:   2716
Command line : C:\Windows\SysWOW64\WerFault.exe -u -p 2724 -s 156
************************************************************************
NOTEPAD.EXE pid:   1388
************************************************************************
WerFault.exe pid:    780
Command line : C:\Windows\SysWOW64\WerFault.exe -u -p 1388 -s 156
************************************************************************
NOTEPAD.EXE pid:   2056
************************************************************************
WerFault.exe pid:   2168
```

- we can see that ```SW1wb3J0YW50.rar``` , dumping the file 

```bash
stapat@stapat:~/ehax/dfir/memlabs/lab5$ volatility -f chall.raw --profile=Win7SP1x64 filescan | grep SW1wb3J0YW50
Volatility Foundation Volatility Framework 2.6.1
0x000000003eed56f0      1      0 R--r-- \Device\HarddiskVolume2\Users\SmartNet\Documents\SW1wb3J0YW50.rar
stapat@stapat:~/ehax/dfir/memlabs/lab5$ volatility -f chall.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003eed56f0 -D .
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3eed56f0   None   \Device\HarddiskVolume2\Users\SmartNet\Documents\SW1wb3J0YW50.rar
stapat@stapat:~/ehax/dfir/memlabs/lab5$ ls
chall.raw  file.None.0xfffffa80010b44f0.dat  README.md  t.rar
stapat@stapat:~/ehax/dfir/memlabs/lab5$ mv file.None.0xfffffa80010b44f0.dat SW1wb3J0YW50.rar
stapat@stapat:~/ehax/dfir/memlabs/lab5$ unrar e SW1wb3J0YW50.rar 

UNRAR 7.00 freeware      Copyright (c) 1993-2024 Alexander Roshal


Extracting from SW1wb3J0YW50.rar

Enter password (will not be echoed) for Stage2.png:
```
- we need a password ans it should be the flag for the first stage , so tried finding more files opened in IE history 

```bash
stapat@stapat:~/ehax/dfir/memlabs/lab5$ volatility -f chall.raw --profile=Win7SP1x64 iehistory
Volatility Foundation Volatility Framework 2.6.1
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5000
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Documents/Important.rar
Last modified: 2019-12-11 14:37:23 UTC+0000
Last accessed: 2019-12-11 14:37:23 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xbc
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5100
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Downloads/SW1wb3J0YW50.rar
Last modified: 2019-12-11 10:03:48 UTC+0000
Last accessed: 2019-12-11 10:03:48 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xc0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5200
Record length: 0x100
Location: Visited: Alissa Simpson@https://notifier.rarlab.com/?language=English&source=RARLAB&landingpage=first&version=580&architecture=64
Last modified: 2019-12-11 10:03:52 UTC+0000
Last accessed: 2019-12-11 10:03:52 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xec
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5300
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/stAg3_5.txt
Last modified: 2019-12-11 10:04:00 UTC+0000
Last accessed: 2019-12-11 10:04:00 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5400
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/Password.png
Last modified: 2019-12-14 10:37:41 UTC+0000
Last accessed: 2019-12-14 10:37:41 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb8
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5500
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/SmartNet/Documents/New%20Text%20Document.txt
Last modified: 2019-12-16 13:47:13 UTC+0000
Last accessed: 2019-12-16 13:47:13 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xc0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5600
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/SmartNet/Secrets/Hidden.kdbx
Last modified: 2019-12-14 10:37:56 UTC+0000
Last accessed: 2019-12-14 10:37:56 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5700
Record length: 0x100
Location: Visited: Alissa Simpson@file:///Z:/MemLabs-Files/Lab-2/Hidden.kdbx
Last modified: 2019-12-18 14:58:14 UTC+0000
Last accessed: 2019-12-18 14:58:14 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5800
Record length: 0x100
Location: Visited: Alissa Simpson@file:///Z:/MemLabs-Files/Lab-2/Password.png
Last modified: 2019-12-18 14:58:20 UTC+0000
Last accessed: 2019-12-18 14:58:20 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5900
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfM19EMG4zXyEhfQ.bmp
Last modified: 2019-12-19 08:35:18 UTC+0000
Last accessed: 2019-12-19 08:35:18 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xec
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5a00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 03:46:09 UTC+0000
Last accessed: 2019-12-20 03:46:09 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xec
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5b00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/SmartNet/SW1wb3J0YW50.rar
Last modified: 2019-12-19 08:36:16 UTC+0000
Last accessed: 2019-12-19 08:36:16 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5c00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Windows/AppPatch/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 03:46:37 UTC+0000
Last accessed: 2019-12-20 03:46:37 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xdc
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x2955000
Record length: 0x100
Location: :2019122020191221: Alissa Simpson@file:///C:/Windows/AppPatch/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 09:16:37 UTC+0000
Last accessed: 2019-12-20 03:46:37 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x2955100
Record length: 0x100
Location: :2019122020191221: Alissa Simpson@:Host: Computer
Last modified: 2019-12-20 09:14:56 UTC+0000
Last accessed: 2019-12-20 03:44:56 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x2955200
Record length: 0x100
Location: :2019122020191221: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 09:16:09 UTC+0000
Last accessed: 2019-12-20 03:46:09 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1396 explorer.exe
Cache type "DEST" at 0x635910f
Last modified: 2019-12-20 09:16:37 UTC+0000
Last accessed: 2019-12-20 03:46:38 UTC+0000
URL: Alissa Simpson@file:///C:/Windows/AppPatch/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2a56000
Record length: 0x200
Location: https://www.google.com/favicon.ico
Last modified: 2019-10-22 18:30:00 UTC+0000
Last accessed: 2019-12-04 14:16:44 UTC+0000
File Offset: 0x200, Data Offset: 0x8c, Data Length: 0x9c
File: favicon[1].ico
Data: HTTP/1.1 200 OK
Content-Type: image/x-icon
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Alt-Svc: quic=":443"; ma=2592000; v="46,43",h3-Q050=":443"; ma=2592000,h3-Q049=":443"; ma=2592000,h3-Q048=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000
Content-Length: 5430

~U:smartnet

**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2a56400
Record length: 0x200
Location: https://www.google.com/chrome/static/images/favicons/favicon.ico
Last modified: 2019-10-18 02:00:00 UTC+0000
Last accessed: 2019-12-04 14:16:59 UTC+0000
File Offset: 0x200, Data Offset: 0xac, Data Length: 0xbc
File: favicon[1].ico
Data: HTTP/1.1 200 OK
Content-Type: image/x-icon
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Alt-Svc: quic=":443"; ma=2592000; v="46,43",h3-Q050=":443"; ma=2592000,h3-Q049=":443"; ma=2592000,h3-Q048=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000
Transfer-Encoding: chunked

~U:smartnet

**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2a56600
Record length: 0x300
Location: https://www.mozilla.org/media/img/favicons/firefox/favicon.4e526382d5a6.ico
Last modified: 2019-10-16 17:22:15 UTC+0000
Last accessed: 2019-12-04 14:18:20 UTC+0000
File Offset: 0x300, Data Offset: 0xb4, Data Length: 0xd0
File: favicon.4e526382d5a6[1].ico
Data: HTTP/1.1 200 OK
Content-Type: image/vnd.microsoft.icon
Transfer-Encoding: chunked
x-amz-id-2: yRbxwWBXVXF1bHKOt1Ae4Hju0c8N0q2+LxAchVJrYZfeUlYro//PxtLkXWvAtseYsZmBAzChLaQ=
x-amz-request-id: D8C8A4FFF3645840
ETag: W/"4e526382d5a683fe91e5538a96219d2f"
x-amz-version-id: Q7ITXNp95t8zXhFqJ.iRoB58Uan_svG9
CF-Cache-Status: HIT
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
CF-RAY: 53fe8c3039f5d593-BOM

~U:smartnet

**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2a56900
Record length: 0x300
Location: https://www.mozilla.org/media/img/favicons/firefox/browser/favicon.f093404c0135.ico
Last modified: 2019-10-21 21:07:07 UTC+0000
Last accessed: 2019-12-04 14:18:31 UTC+0000
File Offset: 0x300, Data Offset: 0xbc, Data Length: 0xd8
File: favicon.f093404c0135[1].ico
Data: HTTP/1.1 200 OK
Content-Type: image/vnd.microsoft.icon
Transfer-Encoding: chunked
x-amz-id-2: Q5lypBQhXDvM01MvvBTQYV6VxRkmXkrdUvwl9ErWEjNnOeFa03akSTikk1uA9aVLlaIW7Qu2XEw=
x-amz-request-id: AB91BDFD108A152D
ETag: W/"f093404c01359cad9d0f2fb514b64281"
x-amz-version-id: y1ioJqr2FXnlb4oTjkjTrjx6a2Lx...L
CF-Cache-Status: HIT
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
CF-RAY: 53fe8c700aaad593-BOM

~U:smartnet

**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5000
Record length: 0x100
Location: Visited: SmartNet@http://www.msn.com/?ocid=iehp
Last modified: 2019-12-04 14:16:13 UTC+0000
Last accessed: 2019-12-04 14:16:13 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x98
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5100
Record length: 0x100
Location: Visited: SmartNet@http://static-global-s-msn-com.akamaized.net/hp-neu/sc/2b/a5ea21.ico
Last modified: 2019-12-04 14:16:27 UTC+0000
Last accessed: 2019-12-04 14:16:27 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xc0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5200
Record length: 0x100
Location: Visited: SmartNet@http://go.microsoft.com/fwlink/?LinkId=69157
Last modified: 2019-12-04 14:16:13 UTC+0000
Last accessed: 2019-12-04 14:16:13 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xa8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5300
Record length: 0x100
Location: Visited: SmartNet@https://support.microsoft.com/internet-explorer
Last modified: 2019-12-04 14:16:30 UTC+0000
Last accessed: 2019-12-04 14:16:30 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5400
Record length: 0x100
Location: Visited: SmartNet@https://ieonline.microsoft.com/favicon.ico
Last modified: 2019-12-04 14:16:32 UTC+0000
Last accessed: 2019-12-04 14:16:32 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xa8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5500
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/Desktop/St4g3$1.bat.txt
Last modified: 2019-12-11 08:59:53 UTC+0000
Last accessed: 2019-12-11 08:59:53 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5680
Record length: 0x180
Location: Visited: SmartNet@http://www.msn.com/en-in/?ocid=iehp
Last modified: 2019-12-10 06:14:40 UTC+0000
Last accessed: 2019-12-10 06:14:40 UTC+0000
File Offset: 0x180, Data Offset: 0x0, Data Length: 0xa0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5800
Record length: 0x180
Location: Visited: SmartNet@https://www.google.com/url?esrc=s&frm=1&q=&rct=j&sa=U&url=https://www.mozilla.org/en-US/firefox/&ved=2ahUKEwjPutGLnZzmAhWGzTgGHR8iCQYQFjAAegQIABAB&usg=AOvVaw2J-e0RAWen1CLuXRm460yz
Last modified: 2019-12-04 14:18:16 UTC+0000
Last accessed: 2019-12-04 14:18:16 UTC+0000
File Offset: 0x180, Data Offset: 0x0, Data Length: 0x130
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5980
Record length: 0x180
Location: Visited: SmartNet@https://www.google.com/chrome
Last modified: 2019-12-04 14:16:59 UTC+0000
Last accessed: 2019-12-04 14:16:59 UTC+0000
File Offset: 0x180, Data Offset: 0x0, Data Length: 0x98
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5b00
Record length: 0x100
Location: Visited: SmartNet@http://www.bing.com/search?format=rss&q=Firefox+quantum&FORM=IE8SRC
Last modified: 2019-12-04 14:17:12 UTC+0000
Last accessed: 2019-12-04 14:17:12 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xc0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5c00
Record length: 0x100
Location: Visited: SmartNet@http://www.bing.com/search?q=Firefox+quantum&FORM=IE8SRC
Last modified: 2019-12-04 14:17:15 UTC+0000
Last accessed: 2019-12-04 14:17:15 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb4
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5d00
Record length: 0x100
Location: Visited: SmartNet@http://www.bing.com/favicon.ico
Last modified: 2019-12-04 14:17:12 UTC+0000
Last accessed: 2019-12-04 14:17:12 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x9c
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab5e00
Record length: 0x100
Location: Visited: SmartNet@http://www.bing.com/search?q=Firefox+quantum&FORM=IE8SRC
Last modified: 2019-12-10 06:14:40 UTC+0000
Last accessed: 2019-12-10 06:14:40 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb4
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6000
Record length: 0x200
Location: Visited: SmartNet@https://www.mozilla.org/en-US/firefox/new
Last modified: 2019-12-10 06:14:40 UTC+0000
Last accessed: 2019-12-10 06:14:40 UTC+0000
File Offset: 0x200, Data Offset: 0x0, Data Length: 0xa4
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6200
Record length: 0x200
Location: Visited: SmartNet@https://www.mozilla.org/en-US/firefox/download/thanks
Last modified: 2019-12-10 06:14:39 UTC+0000
Last accessed: 2019-12-10 06:14:39 UTC+0000
File Offset: 0x200, Data Offset: 0x0, Data Length: 0xb0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6400
Record length: 0x200
Location: Visited: SmartNet@https://www.google.com/url?esrc=s&frm=1&q=&rct=j&sa=U&url=https://blog.mozilla.org/firefox/quantum-performance-test/&ved=2ahUKEwjPutGLnZzmAhWGzTgGHR8iCQYQFjACegQIBhAB&usg=AOvVaw3XO7APxPDXR-bDT-ByfMkZ
Last modified: 2019-12-04 14:18:09 UTC+0000
Last accessed: 2019-12-04 14:18:09 UTC+0000
File Offset: 0x200, Data Offset: 0x0, Data Length: 0x144
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6600
Record length: 0x180
Location: Visited: SmartNet@https://www.google.com/url?esrc=s&frm=1&q=&rct=j&sa=U&url=https://www.google.com/chrome/&ved=2ahUKEwi3g__rnJzmAhUSwTgGHSEdCKwQFjAAegQIAhAB&usg=AOvVaw0W4n46XRBG6D5uYcO0mSfE
Last modified: 2019-12-10 06:14:40 UTC+0000
Last accessed: 2019-12-10 06:14:40 UTC+0000
File Offset: 0x180, Data Offset: 0x0, Data Length: 0x128
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6780
Record length: 0x200
Location: Visited: SmartNet@https://www.google.com/search?hl=en-IN&source=hp&biw=&bih=&q=Google+Chrome+Download&iflsig=AAP1E1EAAAAAXefThwUYJlS4SDPu4Rm53s1SWhG-ZbO0&gbv=2
Last modified: 2019-12-10 06:14:40 UTC+0000
Last accessed: 2019-12-10 06:14:40 UTC+0000
File Offset: 0x200, Data Offset: 0x0, Data Length: 0x108
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6980
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/Desktop/St4g3$1.txt
Last modified: 2019-12-11 09:01:25 UTC+0000
Last accessed: 2019-12-11 09:01:25 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xa8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6a80
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/Desktop/st4G3$$1.txt
Last modified: 2019-12-11 09:02:13 UTC+0000
Last accessed: 2019-12-11 09:02:13 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6b80
Record length: 0x200
Location: Visited: SmartNet@https://www.mozilla.org/en-US/firefox
Last modified: 2019-12-10 06:14:40 UTC+0000
Last accessed: 2019-12-10 06:14:40 UTC+0000
File Offset: 0x200, Data Offset: 0x0, Data Length: 0xa0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6d80
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/Secrets/Hidden.kdbx
Last modified: 2019-12-14 10:26:25 UTC+0000
Last accessed: 2019-12-14 10:26:25 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xa8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6e80
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/Documents/SW1wb3J0YW50.rar
Last modified: 2019-12-19 13:25:57 UTC+0000
Last accessed: 2019-12-19 13:25:57 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab6f80
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/SW1wb3J0YW50.rar
Last modified: 2019-12-19 11:07:52 UTC+0000
Last accessed: 2019-12-19 11:07:52 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xa8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab7080
Record length: 0x100
Location: Visited: SmartNet@https://notifier.rarlab.com/?language=English&source=RARLAB&landingpage=first&version=580&architecture=64
Last modified: 2019-12-19 08:36:59 UTC+0000
Last accessed: 2019-12-19 08:36:59 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xe4
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab7180
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/Documents/New%20Text%20Document.txt
Last modified: 2019-12-19 08:37:10 UTC+0000
Last accessed: 2019-12-19 08:37:10 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab7280
Record length: 0x100
Location: Visited: SmartNet@file:///C:/Users/SmartNet/Documents/SW1wb3J0YW50.rar
Last modified: 2019-12-20 03:47:13 UTC+0000
Last accessed: 2019-12-20 03:47:13 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab7400
Record length: 0x100
Location: Visited: SmartNet@https://download-installer.cdn.mozilla.net/pub/firefox/releases/71.0/win32/en-US/Firefox%20Installer.exe
Last modified: 2019-12-04 14:18:50 UTC+0000
Last accessed: 2019-12-04 14:18:50 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xe4
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab7500
Record length: 0x100
Location: Visited: SmartNet@https://download-installer.cdn.mozilla.net/pub/firefox/releases/71.0/win32/en-US/Firefox%20Setup%2071.0.exe
Last modified: 2019-12-04 14:24:28 UTC+0000
Last accessed: 2019-12-04 14:24:28 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xe8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab7600
Record length: 0x100
Location: Visited: SmartNet@https://download-installer.cdn.mozilla.net/pub/firefox/releases/71.0/win32/en-US/Firefox%20Setup%2071.0.exe
Last modified: 2019-12-04 14:23:16 UTC+0000
Last accessed: 2019-12-04 14:23:16 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xe8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x2ab7700
Record length: 0x200
Location: Visited: SmartNet@https://www.mozilla.org/en-US/firefox/installer-help/?channel=release&installer_lang=en-US
Last modified: 2019-12-04 14:20:51 UTC+0000
Last accessed: 2019-12-04 14:20:51 UTC+0000
File Offset: 0x200, Data Offset: 0x0, Data Length: 0xd8
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x4a35000
Record length: 0x100
Location: :2019122020191221: SmartNet@file:///C:/Users/SmartNet/Documents/SW1wb3J0YW50.rar
Last modified: 2019-12-20 09:17:13 UTC+0000
Last accessed: 2019-12-20 03:47:13 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1580 explorer.exe
Cache type "URL " at 0x4a35100
Record length: 0x100
Location: :2019122020191221: SmartNet@:Host: Computer
Last modified: 2019-12-20 09:17:13 UTC+0000
Last accessed: 2019-12-20 03:47:13 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
```

- there are many interesting files but there is a file with a big name (Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfM19EMG4zXyEhfQ.bmp) , that seems like base64 , trying decoding it we get

- we get the flag for first stage

```
flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_3_D0n3_!!}
```



- using this(flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}) as password to unrar the zip we get

![flag](https://raw.githubusercontent.com/stapat1245/memlabs/refs/heads/main/lab5/resources/Stage2.png)
