---
title: Fileless Attack
published: 2025-03-04
description: ''
image: ''
tags: [Malware, Fileless]
category: 'Research'
draft: true
lang: ''
---

<!-- markdownlint-disable MD013 -->

A fileless attack is a type of attack that does not rely on executable files to perform malicious functionality. Instead, the malicious payload is not loaded into memory from disk but rather executed directly in memory through a series of fileless techniques. It fully leverages system memory, system services, legitimate binaries, and trusted applications to carry out the attack.

#  Taxonomy of fileless attack

Here is a brief of fileless attacks that will be discussed below:
![Taxonomy of fileless attack](/src/assets/images/posts/fileless-attack/01.png)

## 1. Memory-based fileless attack

Memory-based fileless attacks refer to attacks where the attacker *runs malicious code only in memory without writing to disk*. Then, after gaining access to the target environment through system vulnerabilities, the attacker can directly execute the malicious payload in memory without leaving any traces on the disk. Attackers can use various techniques to achieve memory-based fileless attacks, such as malicious PE injection or executing PowerShell script code.

### 1.1. Vulnerability exploitation

Vulnerability exploitation is a highly potent fileless attack, with zero-day attacks representing the most formidable approach. When a target host system has vulnerabilities, attackers can remotely intrude the system through vulnerability exploitation and execute malicious code directly in memory without needing the file released.
> A prominent example is the `WannaCry` ransomware, which exploited an SMB (Server Message Block) vulnerability named EternalBlue part of the Microsoft security bulletin [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010). WannaCry infiltrates systems through the EternalBlue vulnerability and propagates within the local network using this exploit. Once it gains privileges on the target host, it sends a payload, which has been XOR encrypted, to be executed in the memory of the target machine. During the initial stage of this attack, no malicious PE files are released onto the disk, and all operations are conducted in memory.

### 1.2. Memory resident malware

Memory resident malware resides entirely in the system’s main memory without touching the file systems. Therefore, it typically does not leave any visible traces in the system’s files.
> Typical example of memory-based malware is `SQL Slammer` worm, this was 376 bytes in size, perfectly fitting into a single network packet, allowing it to spread rapidly upon launch. It exploited a vulnerability in Microsoft’s SQL server by sending formatted requests to UDP port 1434, causing infected routers to start sending this malicious code to random IP addresses, resulting in DDOS attacks.

Memory resident malware typically exploits vulnerabilities for initial intrusion and continues to reside only in memory once inside the system. However, due to the volatile nature of memory, memory resident malware cannot achieve persistence, and restarting the computer will render it ineffective.

### 1.3. Process injection

Process injection executes arbitrary code within the address space of a separate active process to access the process’s memory and system/network resources. To improve the stealthiness of an attack, attackers may inject malicious code into a legitimate process in the operating system to evade detection. Because process injection hides the execution of malicious code within a legitimate process and allows launching payloads within the running process’s memory space without putting any malicious code on the disk, it can evade detection by some security products. PE injection, reflective DLL injection, and process hollowing are three typical fileless process injection techniques.

## 2. Service-based fileless attack

The Windows platform has a range of services or characteristics that can be exploited by attackers, with the most known being the registry and the scheduled tasks, often utilized for fileless persistence.

### 2.1. Registry resident attack

The registry is a system-defined database in which applications and system components store and retrieve configuration data. Storing malicious scripts in the Windows registry is one of the most popular fileless loading entries.
> `Poweliks` heavily utilizes the registry mechanism of Windows for malicious activities.
> ![Poweliks](/src/assets/images/posts/fileless-attack/02.png)
> Poweliks first embeds malicious JavaScript code into the registry, first writing a piece of JavaScript code to a registry entry, which will call rundll32.exe to read and execute the JavaScript code stored in the registry key value. It then writes another piece of JavaScript code, which releases an encrypted PowerShell script that subsequently loads a malicious DLL and is stored as an encrypted string in the registry.

### 2.2. Scheduled task

Windows Scheduled Tasks, also known as Task Scheduler, is a builtin Windows feature that allows users to schedule and automate the
execution of various tasks or programs on their computers. This technique is widely employed by current attackers and red teams for achieving persistence and lateral movement. Attackers can create scheduled tasks using `schtasks.exe` or utilize .NET wrappers and `netapi32` library for task creation.
> A RAT like `Agent Tesla` achieves persistence by creating scheduled tasks, as exemplified by the following command:
>
> ```cmd
> schtasks.exe /Create /TN "UpdatesxjZWstBWrIuw" /XML "C:Users\xx\AppDataLocal\Temp\tmp1718.tmp"
> ```
>
Recent attack cases ([Microsoft Incident Response and Microsoft Threat Intelligence, 2022](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)) have shown that attackers store the essential parameters required by malicious scheduled tasks in the registry, ensuring they continue to run even after system reboots.

### 2.3. ADS attack

Alternate Data Streams (ADS) is a unique feature of NTFS file systems introduced with Windows NT 3.1 in the early 1990s to provide compatibility between Windows NT servers and Macintosh clients, which use Hierarchical File System (HFS). Typically, a file has only one default data stream that stores the main content of the file. However, ADS allows multiple data streams to be added to a file, enabling it to store more data. Thus, attackers can use ADS to store various types of files, including audio, video, images, and malicious code such as viruses, trojans, and ransomware. Furthermore, due to the hidden nature of alternate data streams, users cannot detect them using directory listing commands. The most significant advantage of this approach is that it does not affect the file size, making it difficult for ordinary users to detect.
> Here is an example of ADS attack:
>
> ```cmd
> type putty.exe > host.txt:putty.exe
> wmic process call create c:\ty\host.txt:putty.exe
> ```

## 3. LotL-based fileless attack

Living-off-the-Land (LotL) attack has become increasingly popular as a fileless attack technique in recent years. Recent studies have shown that LotL techniques are widely used, especially in APT attacks, with a prevalence rate of 26.26% in APT malware samples using LotL attacks.
> **A Living-off-the-Land (LotL)** attack is a type of attack in that attackers carry out malicious activities leveraging pre-installed and post-installed binaries within a system. The objects exploited in such attacks encompass documents, scripts, and LoLBins.

### 3.1. LoLBins-based attack

The binary files used for LotL attacks are called LoLBins (Living off the Land Binaries). By leveraging these binaries, attackers can conduct information gathering, credential dumping, persistence, and lateral movement without leaving any binary files on the disk. LoLBins-based attack has become very popular in recent years. Attackers can hide their malicious activities from many legitimate processes using legitimate tools in the system.
> The `Lazarus` group often uses `mshta.exe`, `wmic.exe`, `schtasks.exe`, etc., for lateral movement, proxy execution, and payload loading.
>
> `Petya` loads a malicious DLL through `rundll32.exe` to execute malicious logic, `PsExec.exe` and `wmic.exe` to perform lateral movement and remote execution. It also uses `wevtutil.exe` to hide traces by deleting system logs and creating scheduled tasks using `schtasks.exe` for persistence.

The LoLBins can be divided into two categories: the *binary pre-installed* by the system and the *binary post-installed* with a legal signature by users. The pre-installed binaries are system programs that existed in the System32 folder in the Windows system by default and can be directly called through the command line, such as `mshta.exe`, `bitsadmin.exe`, `wmic.exe`, etc. User post-installed binaries are those applications with legal signatures installed by users on the system later, such as `Word`, `Excel`, and `PowerPoint` in the office suite and `PsExec` of Sysinternals.
The table below show some common LoLBins and their common purposes:
![LoLBins](/src/assets/images/posts/fileless-attack/03.png)

### 3.2. Document-based attack

Attackers often trigger malicious macros embedded in Office documents (such as MS Word, MS Excel, or MS PowerPoint) through Office vulnerabilities or phishing emails. Attackers can write malicious macros to gain access, compromise the system, or bypass other security controls.
> For example, attackers can use macros to access C2 servers and download malicious files to execute malicious functions locally. Attackers can also use macros to decrypt and release the PowerShell script and then call and execute it to achieve other malicious purposes.

Malicious PDF files generally fall into three categories: *JavaScript-based*, *ActionScript-based*, and *file embedding*. Adobe PDF readers come equipped with a JavaScript interpreter, allowing JavaScript to run within PDFs, providing attackers with a larger attack surface. Additionally, attackers may exploit AcroForms to craft malicious ActionScript. AcroForms is a scripting technology used in PDF creation, designed to add useful interactive features to standard PDF documents. Attackers can also embed malicious files within PDFs. These embedded files can be PE files or malicious Office documents. When a victim opens the PDF, the embedded file is released and executed.
> To execute malicious code embedded in the PDF, attackers may also construct specially crafted PDF documents to exploit vulnerabilities in specific PDF readers. For instance, they can exploit vulnerabilities like Use After Free in Adobe Acrobat and Reader by calling the addAnnot function via JavaScript, triggering the vulnerability ([CVE-2017-11254, CheckPoint](https://advisories.checkpoint.com/advisory/cpai-2017-0662/))

Even though the malicious document files exploited by attackers are not binary files themselves, the execution of these documents relies on the underlying binary software.
> For example, opening a .doc document requires the `winword.exe`, and opening a .pdf document requires `acrobat.exe` (Adobe’s PDF reader). The execution of documents relies on these binary executables. When attackers exploit document macros or vulnerabilities, they are effectively leveraging the features provided by these binaries to conduct their attacks.

### 3.3. Script-based attack

Attackers can use built-in scripting language interpreters in Windows, such as PowerShell, VBScript, and JavaScript, to load corresponding payload scripts remotely and execute them in memory without any script file landing. Script attacks are often combined with other attack techniques, such as registry resident attacks, malicious document attacks, registry resident attacks.
In recent years, more and more attack reports have shown that PowerShell is widely used in various types of network attacks, such as APT attacks, ransomware attacks, and general cybercrime, with attackers using PowerShell malicious scripts to carry out attacks.

# Reference

Liu, S., Peng, G., Zeng, H., & Fu, J. (2024). A survey on the evolution of fileless attacks and detection techniques. Computers & Security, 137, 103653.
