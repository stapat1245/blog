---
title: Memlabs Lab 1 Writeup
date: 2025-05-26 12:00:00 +/-TTTT
tags: [memlabs]     # TAG names should always be lowercase
author: stapat
---

# Lab 1
### challenge description
```
My sister’s computer crashed. We were very fortunate to recover this memory dump. Your job is get all her important files from the system. From what we remember, we suddenly saw a black window pop up with some thing being executed. When the crash happened, she was trying to draw something. Thats all we remember from the time of crash.
```
## solution
we have the memory dump and we run the basic command as we see a memory dump 

```volatility -f memory.raw image info```
```
stapat@stapat:~/ehax/dfir/lab1$ volatility -f lab1.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/data/symlinks/ehax/dfir/lab1/lab1.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028100a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002811d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-12-11 14:38:00 UTC+0000
     Image local date and time : 2019-12-11 20:08:00 +0530
```
it suggests that it's profile is Win7SP1x64 so we check the processes running
```
stapat@stapat:~/ehax/dfir/lab1$ volatility -f lab1.raw --profile=Win7SP1x64 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa8000ca0040 System                    4      0     80      570 ------      0 2019-12-11 13:41:25 UTC+0000                                 
0xfffffa800148f040 smss.exe                248      4      3       37 ------      0 2019-12-11 13:41:25 UTC+0000                                 
0xfffffa800154f740 csrss.exe               320    312      9      457      0      0 2019-12-11 13:41:32 UTC+0000                                 
0xfffffa8000ca81e0 csrss.exe               368    360      7      199      1      0 2019-12-11 13:41:33 UTC+0000                                 
0xfffffa8001c45060 psxss.exe               376    248     18      786      0      0 2019-12-11 13:41:33 UTC+0000                                 
0xfffffa8001c5f060 winlogon.exe            416    360      4      118      1      0 2019-12-11 13:41:34 UTC+0000                                 
0xfffffa8001c5f630 wininit.exe             424    312      3       75      0      0 2019-12-11 13:41:34 UTC+0000                                 
0xfffffa8001c98530 services.exe            484    424     13      219      0      0 2019-12-11 13:41:35 UTC+0000                                 
0xfffffa8001ca0580 lsass.exe               492    424      9      764      0      0 2019-12-11 13:41:35 UTC+0000                                 
0xfffffa8001ca4b30 lsm.exe                 500    424     11      185      0      0 2019-12-11 13:41:35 UTC+0000                                 
0xfffffa8001cf4b30 svchost.exe             588    484     11      358      0      0 2019-12-11 13:41:39 UTC+0000                                 
0xfffffa8001d327c0 VBoxService.ex          652    484     13      137      0      0 2019-12-11 13:41:40 UTC+0000                                 
0xfffffa8001d49b30 svchost.exe             720    484      8      279      0      0 2019-12-11 13:41:41 UTC+0000                                 
0xfffffa8001d8c420 svchost.exe             816    484     23      569      0      0 2019-12-11 13:41:42 UTC+0000                                 
0xfffffa8001da5b30 svchost.exe             852    484     28      542      0      0 2019-12-11 13:41:43 UTC+0000                                 
0xfffffa8001da96c0 svchost.exe             876    484     32      941      0      0 2019-12-11 13:41:43 UTC+0000                                 
0xfffffa8001e1bb30 svchost.exe             472    484     19      476      0      0 2019-12-11 13:41:47 UTC+0000                                 
0xfffffa8001e50b30 svchost.exe            1044    484     14      366      0      0 2019-12-11 13:41:48 UTC+0000                                 
0xfffffa8001eba230 spoolsv.exe            1208    484     13      282      0      0 2019-12-11 13:41:51 UTC+0000                                 
0xfffffa8001eda060 svchost.exe            1248    484     19      313      0      0 2019-12-11 13:41:52 UTC+0000                                 
0xfffffa8001f58890 svchost.exe            1372    484     22      295      0      0 2019-12-11 13:41:54 UTC+0000                                 
0xfffffa8001f91b30 TCPSVCS.EXE            1416    484      4       97      0      0 2019-12-11 13:41:55 UTC+0000                                 
0xfffffa8000d3c400 sppsvc.exe             1508    484      4      141      0      0 2019-12-11 14:16:06 UTC+0000                                 
0xfffffa8001c38580 svchost.exe             948    484     13      322      0      0 2019-12-11 14:16:07 UTC+0000                                 
0xfffffa8002170630 wmpnetwk.exe           1856    484     16      451      0      0 2019-12-11 14:16:08 UTC+0000                                 
0xfffffa8001d376f0 SearchIndexer.          480    484     14      701      0      0 2019-12-11 14:16:09 UTC+0000                                 
0xfffffa8001eb47f0 taskhost.exe            296    484      8      151      1      0 2019-12-11 14:32:24 UTC+0000                                 
0xfffffa8001dfa910 dwm.exe                1988    852      5       72      1      0 2019-12-11 14:32:25 UTC+0000                                 
0xfffffa8002046960 explorer.exe            604   2016     33      927      1      0 2019-12-11 14:32:25 UTC+0000                                 
0xfffffa80021c75d0 VBoxTray.exe           1844    604     11      140      1      0 2019-12-11 14:32:35 UTC+0000                                 
0xfffffa80021da060 audiodg.exe            2064    816      6      131      0      0 2019-12-11 14:32:37 UTC+0000                                 
0xfffffa80022199e0 svchost.exe            2368    484      9      365      0      0 2019-12-11 14:32:51 UTC+0000                                 
0xfffffa8002222780 cmd.exe                1984    604      1       21      1      0 2019-12-11 14:34:54 UTC+0000                                 
0xfffffa8002227140 conhost.exe            2692    368      2       50      1      0 2019-12-11 14:34:54 UTC+0000                                 
0xfffffa80022bab30 mspaint.exe            2424    604      6      128      1      0 2019-12-11 14:35:14 UTC+0000                                 
0xfffffa8000eac770 svchost.exe            2660    484      6      100      0      0 2019-12-11 14:35:14 UTC+0000                                 
0xfffffa8001e68060 csrss.exe              2760   2680      7      172      2      0 2019-12-11 14:37:05 UTC+0000                                 
0xfffffa8000ecbb30 winlogon.exe           2808   2680      4      119      2      0 2019-12-11 14:37:05 UTC+0000                                 
0xfffffa8000f3aab0 taskhost.exe           2908    484      9      158      2      0 2019-12-11 14:37:13 UTC+0000                                 
0xfffffa8000f4db30 dwm.exe                3004    852      5       72      2      0 2019-12-11 14:37:14 UTC+0000                                 
0xfffffa8000f4c670 explorer.exe           2504   3000     34      825      2      0 2019-12-11 14:37:14 UTC+0000                                 
0xfffffa8000f9a4e0 VBoxTray.exe           2304   2504     14      144      2      0 2019-12-11 14:37:14 UTC+0000                                 
0xfffffa8000fff630 SearchProtocol         2524    480      7      226      2      0 2019-12-11 14:37:21 UTC+0000                                 
0xfffffa8000ecea60 SearchFilterHo         1720    480      5       90      0      0 2019-12-11 14:37:21 UTC+0000                                 
0xfffffa8001010b30 WinRAR.exe             1512   2504      6      207      2      0 2019-12-11 14:37:23 UTC+0000                                 
0xfffffa8001020b30 SearchProtocol         2868    480      8      279      0      0 2019-12-11 14:37:23 UTC+0000                                 
0xfffffa8001048060 DumpIt.exe              796    604      2       45      1      1 2019-12-11 14:37:54 UTC+0000                                 
0xfffffa800104a780 conhost.exe            2260    368      2       50      1      0 2019-12-11 14:37:54 UTC+0000
```
we see WinRAR.exe , mspaint.exe and cmd.exe

so cmd.exe must be the black screen she saw when her screen died
so we run the consoles command to see the cmd.exe  output
```
stapat@stapat:~/ehax/dfir/lab1$ volatility -f lab1.raw --profile=Win7SP1x64 consoles
Volatility Foundation Volatility Framework 2.6.1
**************************************************
ConsoleProcess: conhost.exe Pid: 2692
Console: 0xff756200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: C:\Windows\system32\cmd.exe - St4G3$1
AttachedProcess: cmd.exe Pid: 1984 Handle: 0x60
----
CommandHistory: 0x1fe9c0 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 1 LastAdded: 0 LastDisplayed: 0
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
Cmd #0 at 0x1de3c0: St4G3$1
----
Screen 0x1e0f70 X:80 Y:300
Dump:
Microsoft Windows [Version 6.1.7601]                                            
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.                 
                                                                                
C:\Users\SmartNet>St4G3$1                                                       
ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=                                        
Press any key to continue . . .                                                 
**************************************************
ConsoleProcess: conhost.exe Pid: 2260
Console: 0xff756200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: C:\Users\SmartNet\Downloads\DumpIt\DumpIt.exe
Title: C:\Users\SmartNet\Downloads\DumpIt\DumpIt.exe
AttachedProcess: DumpIt.exe Pid: 796 Handle: 0x60
----
CommandHistory: 0x38ea90 Application: DumpIt.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
----
Screen 0x371050 X:80 Y:300
Dump:
  DumpIt - v1.3.2.20110401 - One click memory memory dumper                     
  Copyright (c) 2007 - 2011, Matthieu Suiche <http://www.msuiche.net>           
  Copyright (c) 2010 - 2011, MoonSols <http://www.moonsols.com>                 
                                                                                
                                                                                
    Address space size:        1073676288 bytes (   1023 Mb)                    
    Free space size:          24185389056 bytes (  23064 Mb)                    
                                                                                
    * Destination = \??\C:\Users\SmartNet\Downloads\DumpIt\SMARTNET-PC-20191211-
143755.raw                                                                      
                                                                                
    --> Are you sure you want to continue? [y/n] y                              
    + Processing...                              
```
we can see a command named St4G3$1 run and give a output of 
```
ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=
```
after decoding this we got the flag 1
```
flag{th1s_1s_th3_1st_st4g3!!}
```
### flag 2
for the flag 2 we dumped the process 2424 (mspaint.exe) by
```volatility -f lab1.raw --profile=Win7SP1x64 memdump -p 2424 -D mspaint/```
we have 2424.dmp 
```
stapat@stapat:~/ehax/dfir/lab1/mspaint$ file 2424.dmp 
2424.dmp: data
```
making the data file .data and opening it with gimp gives us something , after 2-3 hours of adjusting its height and width ( at the end seeing another writeup) we get the flag flipped , so flipping it gives us the flag.
```height= ~10000 width= ~1250```
![flippedflag](https://raw.githubusercontent.com/stapat1245/memlabs/refs/heads/main/lab1/resources/image.png)
![flag](https://raw.githubusercontent.com/stapat1245/memlabs/refs/heads/main/lab1/resources/flag2.png)

```
flag 2 = flag{Good_Boy_good_girl}
```
### flag 3
we have the winrar.exe process and we got the Important.rar opened in the cmdline output
![cmdline](https://raw.githubusercontent.com/stapat1245/memlabs/refs/heads/main/lab1/resources/cmdline.png)
extracting the file with dumpfiles plugin
but we need to have the physical offset for this 
so for physical offset in the memory dump we use the filescan plugin
```
stapat@stapat:~/ehax/dfir/lab1$ volatility -f lab1.raw --profile=Win7SP1x64 filescan | grep Imp
Volatility Foundation Volatility Framework 2.6.1
0x000000003ea56710      2      0 R--r-d \Device\HarddiskVolume2\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask
0x000000003ed08a60      2      0 R--r-d \Device\HarddiskVolume2\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
0x000000003f6dbbc0      2      0 R--r-d \Device\HarddiskVolume2\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\Consolidator
0x000000003fa3ebc0      1      0 R--r-- \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
0x000000003fac3bc0      1      0 R--r-- \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
0x000000003fb48bc0      1      0 R--r-- \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
```
we can use any offset 
```bash
stapat@stapat:~/ehax/dfir/lab1$ volatility -f lab1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fb48bc0 -D .
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fb48bc0   None   \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
```
now we have ```file.None.0xfffffa8001034450.dat```

making this Important.rar and unraring it via  ```unrar e Important.rar```
```bash
stapat@stapat:~/ehax/dfir/lab1$ unrar e imp.rar 

UNRAR 7.00 freeware      Copyright (c) 1993-2024 Alexander Roshal

Archive comment:
Password is NTLM hash(in uppercase) of Alissa's account passwd.


Extracting from imp.rar

Enter password (will not be echoed) for flag3.png:
```
using the hashdump plugin we get the password hashes
```bash
stapat@stapat:~/ehax/dfir/lab1$ volatility -f lab1.raw --profile=Win7SP1x64 hashdump
Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SmartNet:1001:aad3b435b51404eeaad3b435b51404ee:4943abb39473a6f32c11301f4987e7e0:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:f0fc3d257814e08fea06e63c5762ebd5:::
Alissa Simpson:1003:aad3b435b51404eeaad3b435b51404ee:f4ff64c8baac57d22f22edc681055ba6:::
```
the second one after ":" is the ntlm hash
```bash
stapat@stapat:~/ehax/dfir/lab1$ unrar e imp.rar

UNRAR 7.00 freeware      Copyright (c) 1993-2024 Alexander Roshal

Archive comment:
Password is NTLM hash(in uppercase) of Alissa's account passwd.


Extracting from imp.rar

Enter password (will not be echoed) for flag3.png: 

The specified password is incorrect.
Enter password (will not be echoed) for flag3.png: 

Extracting  flag3.png                                                 OK 
All OK
```
we got the flag 3 as well
![flag3](https://raw.githubusercontent.com/stapat1245/memlabs/refs/heads/main/lab1/resources/flag3.png)

## Flags
```
flag1= flag{th1s_1s_th3_1st_st4g3!!}
flag2= flag{Good_Boy_good_girl}
flag3= flag{w3ll_3rd_stage_was_easy}
```