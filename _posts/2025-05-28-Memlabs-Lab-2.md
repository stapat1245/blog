---
title: Memlabs Lab 2 Writeup
date: 2025-05-25 12:00:00 +/-TTTT
tags: [memlabs]     # TAG names should always be lowercase
author: stapat
---
# Solution lab 2
challenge description - 
```
One of the clients of our company, lost the access to his system due to an unknown error. He is supposedly a very popular "environmental" activist. As a part of the investigation, he told us that his go to applications are browsers, his password managers etc. We hope that you can dig into this memory dump and find his important stuff and give it back to us.
```
- we can infer about enviroment variables and some password manager and browser
- first getting some basic idea about the memory dump
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
 
### flag 1
- checking the enviroment variables


flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}
flag{oK_So_Now_St4g3_3_is_DoNE}