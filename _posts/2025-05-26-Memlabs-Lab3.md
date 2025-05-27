---
title: Memlabs Lab 3 Writeup
date: 2025-05-25 12:00:00 +/-TTTT
tags: [memlabs]     # TAG names should always be lowercase
author: stapat
---
# memlabs lab 3

The Evil's Den
```
A malicious script encrypted a very secret piece of information I had on my system. Can you recover the information for me please?

Note-1: This challenge is composed of only 1 flag. The flag split into 2 parts.

Note-2: You'll need the first half of the flag to get the second.

You will need this additional tool to solve the challenge
```

- as a forensics guy i know steghide can be used on images(jpgs) , so we will be working on some jpgs
- [challenge file](https://mega.nz/file/2ohlTAzL#1T5iGzhUWdn88zS1yrDJA06yUouZxC-VstzXFSRuzVg)

# Solution
- finding the profile
```bash
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/data/symlinks/ehax/dfir/memlabs/lab3/chall.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82742c68L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82743d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2018-09-30 09:47:54 UTC+0000
     Image local date and time : 2018-09-30 15:17:54 +0530
```
- image profile is Win7SP1x86 , now looking at the running processes
```bash
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 psxview
Volatility Foundation Volatility Framework 2.6.1
Offset(P)  Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
---------- -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
0x3d769d00 SearchIndexer.         1184 True   False  True     True   True  True    True     
0x3da4a800 spoolsv.exe            1340 True   False  True     True   True  True    True     
0x3de1d7e0 taskhost.exe           4816 True   False  True     True   True  True    True     
0x3da1bcb0 svchost.exe            1236 True   False  True     True   True  True    True     
0x3d392030 LogonUI.exe             876 True   False  True     True   True  True    True     
0x3d7d4b28 lsm.exe                 500 True   False  True     True   True  True    False    
0x3de9d890 explorer.exe           5300 True   False  True     True   True  True    True     
0x3d437498 conhost.exe            3176 True   False  True     True   True  True    True     
0x3d46fa18 svchost.exe             904 True   False  True     True   True  True    True     
0x37e92d28 msiexec.exe            1016 True   False  True     True   True  True    True     
0x3da93030 svchost.exe            1516 True   False  True     True   True  True    True     
0x3de3d3c0 notepad.exe            3432 True   False  True     True   True  True    True     
0x3da5b030 svchost.exe            1368 True   False  True     True   True  True    True     
0x3d45ad28 svchost.exe             800 True   False  True     True   True  True    True     
0x3d41d030 svchost.exe             712 True   False  True     True   True  True    True     
0x18350170 dwm.exe                3028 True   False  True     True   True  True    True     
0x3d7a6d28 winlogon.exe            424 True   False  True     True   True  True    True     
0x3dd00ab8 dllhost.exe            1008 True   False  True     True   True  True    True     
0x3d467d28 svchost.exe             852 True   False  True     True   True  True    True     
0x3d46b030 svchost.exe             880 True   False  True     True   True  True    True     
0x3e5bba40 SearchProtocol         5748 True   False  True     True   True  True    True     
0x3d35cae0 sppsvc.exe              292 True   False  True     True   True  True    True     
0x01823970 notepad.exe            3736 True   False  True     True   True  True    True     
0x3de89800 audiodg.exe            5996 True   False  True     True   True  True    True     
0x3df4e348 svchost.exe             588 True   False  True     True   True  True    False    
0x3d7cdbd0 services.exe            484 True   False  True     True   True  True    False    
0x3d3cdd28 VBoxTray.exe           3064 True   False  True     True   True  True    True     
0x3d7d0658 lsass.exe               492 True   False  True     True   True  True    False    
0x3da8e860 svchost.exe            1488 True   False  True     True   True  True    True     
0x3d4ad628 DumpIt.exe             4116 True   False  True     True   True  True    True     
0x3d4f6768 SearchFilterHo         4036 True   False  True     True   True  True    True     
0x3d34bbf0 svchost.exe             440 True   False  True     True   True  True    False    
0x3d777d28 wininit.exe             388 True   False  True     True   True  True    True     
0x3d415d28 VBoxService.ex          648 True   False  True     True   True  True    False    
0x101b69f0 TrustedInstall         4724 True   False  True     True   True  True    True     
0x3d777868 wuauclt.exe            5644 True   False  True     True   True  True    True     
0x3df51b98 smss.exe                260 True   False  True     True   False False   False    
0x3d776030 csrss.exe               380 True   False  True     True   False True    True     
0x3d758030 csrss.exe               340 True   False  True     True   False True    True     
0x3d4d1338 ???I2P	??2???     81...0 False  False  False    True   False False   False    -
0x3e7b3c60 System                    4 True   False  True     True   False False   False    
0x303188a8 msiexec.exe            5652 True   False  False    True   False True    False    2018-09-30 09:41:17 UTC+0000
```
- we can see 2 notepad.exe , which suggests there are 2 files open , looking for some command line commands 
```bash
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 cmdline
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
System pid:      4
************************************************************************
smss.exe pid:    260
Command line : \SystemRoot\System32\smss.exe
************************************************************************
csrss.exe pid:    340
Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
************************************************************************
csrss.exe pid:    380
Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
************************************************************************
wininit.exe pid:    388
Command line : wininit.exe
************************************************************************
winlogon.exe pid:    424
Command line : winlogon.exe
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
VBoxService.ex pid:    648
Command line : C:\Windows\System32\VBoxService.exe
************************************************************************
svchost.exe pid:    712
Command line : C:\Windows\system32\svchost.exe -k RPCSS
************************************************************************
svchost.exe pid:    800
Command line : C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
************************************************************************
svchost.exe pid:    852
Command line : C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
************************************************************************
svchost.exe pid:    880
Command line : C:\Windows\system32\svchost.exe -k LocalService
************************************************************************
svchost.exe pid:    904
Command line : C:\Windows\system32\svchost.exe -k netsvcs
************************************************************************
svchost.exe pid:   1236
Command line : C:\Windows\system32\svchost.exe -k NetworkService
************************************************************************
spoolsv.exe pid:   1340
Command line : C:\Windows\System32\spoolsv.exe
************************************************************************
svchost.exe pid:   1368
Command line : C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
************************************************************************
svchost.exe pid:   1488
Command line : C:\Windows\System32\svchost.exe -k utcsvc
************************************************************************
svchost.exe pid:   1516
Command line : C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation
************************************************************************
LogonUI.exe pid:    876
Command line : "LogonUI.exe" /flags:0x1
************************************************************************
sppsvc.exe pid:    292
Command line : C:\Windows\system32\sppsvc.exe
************************************************************************
svchost.exe pid:    440
Command line : C:\Windows\System32\svchost.exe -k secsvcs
************************************************************************
SearchIndexer. pid:   1184
Command line : C:\Windows\system32\SearchIndexer.exe /Embedding
************************************************************************
taskhost.exe pid:   4816
Command line : "taskhost.exe"
************************************************************************
dwm.exe pid:   3028
Command line : "C:\Windows\system32\Dwm.exe"
************************************************************************
explorer.exe pid:   5300
Command line : C:\Windows\Explorer.EXE
************************************************************************
VBoxTray.exe pid:   3064
Command line : "C:\Windows\System32\VBoxTray.exe" 
************************************************************************
wuauclt.exe pid:   5644
Command line : "C:\Windows\system32\wuauclt.exe"
************************************************************************
msiexec.exe pid:   1016
Command line : C:\Windows\system32\msiexec.exe /V
************************************************************************
msiexec.exe pid:   5652
************************************************************************
TrustedInstall pid:   4724
Command line : C:\Windows\servicing\TrustedInstaller.exe
************************************************************************
audiodg.exe pid:   5996
Command line : C:\Windows\system32\AUDIODG.EXE 0x830
************************************************************************
SearchProtocol pid:   5748
Command line : "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe7_ Global\UsGthrCtrlFltPipeMssGthrPipe7 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" 
************************************************************************
DumpIt.exe pid:   4116
Command line : "C:\Users\hello\Desktop\DumpIt\DumpIt.exe" 
************************************************************************
conhost.exe pid:   3176
Command line : \??\C:\Windows\system32\conhost.exe "-578845771-1540166818332419906-659764396-174055078882731463-1164958248-211768531
************************************************************************
dllhost.exe pid:   1008
Command line : C:\Windows\system32\DllHost.exe /Processid:{76D0CB12-7604-4048-B83C-1005C7DDC503}
************************************************************************
SearchFilterHo pid:   4036
Command line : "C:\Windows\system32\SearchFilterHost.exe" 0 512 516 524 65536 520 
************************************************************************
notepad.exe pid:   3736
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\evilscript.py
************************************************************************
notepad.exe pid:   3432
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\vip.txt
```
- we can see vip.txt and eviscript.py , which the description suggests , now extracting the files but for that we need 
```bash
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 filescan | grep vip.txt
Volatility Foundation Volatility Framework 2.6.1
0x000000003e727e50      8      0 -W-rw- \Device\HarddiskVolume2\Users\hello\Desktop\vip.txt
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 filescan | grep evilscript.py
Volatility Foundation Volatility Framework 2.6.1
0x000000003de1b5f0      8      0 R--rw- \Device\HarddiskVolume2\Users\hello\Desktop\evilscript.py.py
0x000000003e727490      2      0 RW-rw- \Device\HarddiskVolume2\Users\hello\AppData\Roaming\Microsoft\Windows\Recent\evilscript.py.lnk
```
- dumping them
```bash
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 dumpfiles -Q 0x000000003e727e50 -D .
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3e727e50   None   \Device\HarddiskVolume2\Users\hello\Desktop\vip.txt
stapat@stapat:~/ehax/dfir/memlabs/lab3$ ls
chall.raw  file.None.0x83e52420.dat  README.md  rev.py
stapat@stapat:~/ehax/dfir/memlabs/lab3$ mv file.None.0x83e52420.dat vip.txt
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 dumpfiles -Q 0x000000003de1b5f0 -D .
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3de1b5f0   None   \Device\HarddiskVolume2\Users\hello\Desktop\evilscript.py.py
stapat@stapat:~/ehax/dfir/memlabs/lab3$ mv file.None.0xbc2b6af0.dat evilscript.py
```
- the vip.txt contains ```am1gd2V4M20wXGs3b2U=```
and the evilscript.py 
```python
import sys
import string
def xor(s):

	a = ''.join(chr(ord(i)^3) for i in s)
	return a
def encoder(x):
	
	return x.encode("base64")
if __name__ == "__main__":

	f = open("C:\\Users\\hello\\Desktop\\vip.txt", "w")

	arr = sys.argv[1]

	arr = encoder(xor(arr))

	f.write(arr)

	f.close()
```

- we can see that that it first xored it and then base64'd it

```python
import base64

txt= 'am1gd2V4M20wXGs3b2U='
xor=base64.b64decode(txt).decode()
flag =''.join(chr(ord(i)^3) for i in xor)
print(flag)
```

- output =```inctf{0n3_h4lf```
- now for the second part we need a image so scanning all the images present in the memory dump , we need only jpgs as steghide only works on jpgs , but we scan for all if we want to have a deeper look.

```bash
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 filescan | grep ".jpeg"
Volatility Foundation Volatility Framework 2.6.1
0x0000000004f34148      2      0 RW---- \Device\HarddiskVolume2\Users\hello\Desktop\suspision1.jpeg
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 dumpfiles -Q 0x0000000004f34148 -D .]
Volatility Foundation Volatility Framework 2.6.1
ERROR   : volatility.debug    : .] is not a directory
stapat@stapat:~/ehax/dfir/memlabs/lab3$ volatility -f chall.raw --profile=Win7SP1x86 dumpfiles -Q 0x0000000004f34148 -D .
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x04f34148   None   \Device\HarddiskVolume2\Users\hello\Desktop\suspision1.jpeg
stapat@stapat:~/ehax/dfir/memlabs/lab3$ ls
chall.raw  evilscript.py  file.None.0x843fcf38.dat  README.md  rev.py  vip.txt
stapat@stapat:~/ehax/dfir/memlabs/lab3$ mv file.None.0x843fcf38.dat suspision.jpep
stapat@stapat:~/ehax/dfir/memlabs/lab3$ mv suspision.jpep suspision.jpeg
stapat@stapat:~/ehax/dfir/memlabs/lab3$ ls
chall.raw  evilscript.py  README.md  rev.py  suspision.jpeg  vip.txt
stapat@stapat:~/ehax/dfir/memlabs/lab3$ xdg-open suspision.jpeg 
```
![suspision.jpeg](../assets/img/memlabs/lab3/suspision.jpeg)
- using steghide(as suggested in question with passphrase the half flag)

```bash
stapat@stapat:~/ehax/dfir/memlabs/lab3/resources$ steghide extract -sf suspision.jpeg -v
Enter passphrase: 
reading stego file "suspision.jpeg"... done
extracting data... done
checking crc32 checksum... ok
writing extracted data to "secret text"... done
stapat@stapat:~/ehax/dfir/memlabs/lab3/resources$ ls
'secret text'   suspision.jpeg
stapat@stapat:~/ehax/dfir/memlabs/lab3/resources$ cd ..
stapat@stapat:~/ehax/dfir/memlabs/lab3$ ls
 chall.raw   evilscript.py   README.md   resources   rev.py  'secret text'   vip.txt
stapat@stapat:~/ehax/dfir/memlabs/lab3$ cat secret\ text 
_1s_n0t_3n0ugh}
```

- the full flag is ```inctf{0n3_h4lf_1s_n0t_3n0ugh}```