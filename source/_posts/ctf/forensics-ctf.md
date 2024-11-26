title: Some forensics challenge writeup
date: 2024-10-31 23:30:04
categories:
  - [CTF, Forensics]
tags:
  - forensics
  - memory dump
  - image disk
---

## 10/31/2024: [the-registrar](https://imaginaryctf.org/ArchivedChallenges/58)

> by lolmenow
> **Description**: Just carved this memory dump from the scarecrow's PC! Apparently he told me that his programs on **startup** was acting weird while trying to *register* his new **software**.

Following the clue, I try to find the hive file storing registry:
![image](/assets/forensics-ctf/forensics-ctf-20243010-01.png)
Then dump this file at offset `0xb183c10b83e0`:
![image](/assets/forensics-ctf/forensics-ctf-20243010-02.png)
Open this .dat file using [Registry Explorer](https://ericzimmerman.github.io/#!index.md), startup programs is registered at `[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]`, go there and get the base32 string:
![image](/assets/forensics-ctf/forensics-ctf-20243010-03.png)
Decode this base32 string and reverse to get the flag:
![image](/assets/forensics-ctf/forensics-ctf-20243010-04.png)
Flag: `ictf{tH3_rEg1STry_i5_T0O_c0OL_foR_YOu!}`

## 10/31/2024: [the-partraditionalist](https://imaginaryctf.org/ArchivedChallenges/58)

> by lolmenow
> **Description**: The forensics department over at ictf needs help recovering the flag from this image disk file!

The challenge give me a file, lets check it:
![image](/assets/forensics-ctf/forensics-ctf-20243010-05.png)
Check some first line, I notice this image disk file has been corrupted:
![image](/assets/forensics-ctf/forensics-ctf-20243010-06.png)
So I use **testdisk** tool to explore it (I run under sudo mode). Select `partition table type = None`
Result should be like this when use select `[ Analyse ]`:
![image](/assets/forensics-ctf/forensics-ctf-20243010-07.png)
After exploring for a time, I found there are 3 files in **Software** partition:
![image](/assets/forensics-ctf/forensics-ctf-20243010-08.png)
Select all files and copy it to another location.
Check these files, I know it use GPG to encrypt message:
![image](/assets/forensics-ctf/forensics-ctf-20243010-09.png)
Importing this private key to decrypt message and get the flag:
![image](/assets/forensics-ctf/forensics-ctf-20243010-10.png)
Flag: `ictf{SH0Uld_i_aDd_my_L1NkeDiN_t0_tHE_6pg_Em4!L??}`

