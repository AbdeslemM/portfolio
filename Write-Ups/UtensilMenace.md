# 🚨 UtensilMenace Investigation

---

## 🎯 Objective
Conduct a digital forensics investigation on a Windows system to analyze a suspicious executable downloaded by the CEO’s son and determine whether it is malicious, along with identifying attacker activity and persistence mechanisms.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** UtensilMenace  
- **Environment:** Windows  
- **Difficulty:** Easy  
- **OS:** Windows  
- **Category:** Digital Forensics  

---

## 📖 Scenario
You have been tasked with investigating the PC belonging to the CEO of your company.  

He mentioned that he created an account for his son on this machine, and that his son downloaded a game. However, the game never launched, raising suspicion that it may actually be malware.  

Your task is to analyze the system, identify what happened, and determine whether malicious activity took place.

---

## 🛠️ Tools Used
- Browser Artifacts  
- Zimmerman Tools  
- Event Logs  

---

## 🔎 Investigation Overview
The investigation focused on analyzing user activity, executable files, and system artifacts to determine whether the downloaded game was malicious.

The analysis included reviewing logon activity, file execution history, registry changes, and persistence mechanisms. By correlating different artifacts, it was possible to reconstruct the attacker’s behavior and identify how the system was compromised.

---

## Lab Discovery

In this lab, we are analyzing a Windows system belonging to the CEO. The main focus is on the user account created for his son and any suspicious activity related to downloaded files and executed programs.

The investigation will involve tracking file execution, identifying downloaded content, and analyzing system changes caused by potential malware.

---

## 🔍 Investigation Process

---

In most cases when using Zimmerman Tools, I start by parsing all event logs, as well as the `$MFT` and `$J`, to prepare them for the investigation.

### Commands used for parsing:

.\EvtxeCmd\EvtxECmd.exe -d "C:\Users\BTLOTest\Desktop\Artefacts\UtensilMenace\C\Windows\System32\winevt\Logs" --csv logs --csvf ALL-Logs.csv

.\MFTECmd.exe -f "C:\Users\BTLOTest\Desktop\Artefacts\UtensilMenace\C\`$MFT" --csv MFT --csvf Mft.csv

.\MFTECmd.exe -f "C:\Users\BTLOTest\Desktop\Artefacts\UtensilMenace\C\`$Extend\`$J" --csv J --csvf J.csv

After that, I open all these CSV files in Timeline Explorer.

---

### Q1) What was the last logon time of the CEO's son?

For the first question, it is clear that we need to check Windows Event Logs. The main Event ID to look for is **4624 (successful logon)**.

Since the user is **myson**, I filtered the logs and identified the last logon time.

<img width="1560" height="820" alt="UtensilMenace-Q1" src="https://github.com/user-attachments/assets/78c04c28-1093-43b3-ae37-d0c4c8357a8a" />


**Answer ==> 2025-04-27 07:44:04**



---

### Q2) What is the full path of the executable file for the suspicious game?

For this question, I first checked the browser history to identify downloaded files. I found that the downloaded game was called **FeedingFrenzy**.

Then, I searched for this name in the MFT to get the full path of the executable.

**Answer ==> C:\Users\myson\Desktop\Games\tmp\vmware\release\Feeding_Frenzy_Win_Preinstalled_EN\Game Files\FeedingFrenzy.exe**

<img width="1560" height="566" alt="UtensilMenace-Q2" src="https://github.com/user-attachments/assets/e67ed70d-f652-4ad9-a2a5-e5d4e366f9bd" />


---

### Q3) What is the SHA1 hash of the executable file found earlier?

To get the file hash, I noticed that the executable was not directly available in the artifacts (possibly deleted by the system or antivirus, which is common in digital forensics).

So, I parsed the **Amcache**, which stores information about executed files.

Command used:

.\AmcacheParser.exe -f "C:\Users\BTLOTest\Desktop\Artefacts\UtensilMenace\C\Windows\AppCompat\Programs\Amcache.hve" --csv Amcache --csvf Amcache.csv

Then I checked:

`Amcache_UnassociatedFileEntries.csv`

From there, I found the SHA1 hash.

**Answer ==> 9a8755180de66a990af80cfc0e32dc0f7cb25643**

<img width="1560" height="820" alt="UtensilMenace-Q3" src="https://github.com/user-attachments/assets/f4e67a57-0f22-4cb4-a926-4bc9980e45cb" />


---

### Q4 & Q5) Download URL and previous suspicious binary

For these two questions, I needed to analyze the browser history, since both are related to downloaded files.

The browser artifacts are located at:

C:\Users\BTLOTest\Desktop\Artefacts\UtensilMenace\C\Users\myson\AppData\Local\Microsoft\Edge\User Data\Default

I opened the **History** database using DB Browser for SQLite.

From there, I was able to retrieve both the download URL and the previously downloaded suspicious binary along with its associated IP address.

Q4) The CEO said that his son downloaded the game as a ZIP file from a website. What is the URL of that website?

**Answer ==> http://freegamebychicken.wowza/release/FeedingFrenzy.zip**

<img width="1546" height="807" alt="UtensilMenace-Q4" src="https://github.com/user-attachments/assets/5468c51c-60a9-438d-b034-44ad95055f1f" />



Q5) There was one suspicious binary downloaded and executed two days prior to this incident. What is the full path of this file and what is the IP address associated with it?(2 points)

**Answer ==> C:\Users\myson\Downloads\reverse.exe, 192.168.189.129**

<img width="1546" height="812" alt="UtensilMenace-Q5" src="https://github.com/user-attachments/assets/33825c29-d1a0-48f9-9b78-df87798f2b4f" />




### Q6) How many times was the masqueraded game executed and what is the last execution time?

To answer this, I usually rely on **Prefetch** files, but in this case, since the registry artifacts are available, I decided to check **UserAssist**.

UserAssist provides information about program execution, including run counts and last execution times. From there, I was able to determine how many times the executable was launched and the last time it was executed.

**Answer ==> 3, 2025-04-27 07:26:15**

<img width="1547" height="810" alt="UtensilMenace-Q6" src="https://github.com/user-attachments/assets/15da05c2-f1dc-4823-9cab-e03228ba1d8c" />

---

### Q7) What is the second executable run by the threat actor?

For this question, I looked into **Prefetch** files to identify executables that could be used for information gathering.

It was clear that **ipconfig.exe** was executed, which is commonly used to retrieve network configuration details.

**Answer ==> ipconfig.exe**

<img width="1548" height="808" alt="UtensilMenace-Q7" src="https://github.com/user-attachments/assets/1b0a4d53-6aeb-4513-bb96-02af8658008a" />


---

### Q8 – Q11) Privilege Abuse and Binary Replacement

After identifying that the attacker executed **whoami.exe**, I reviewed the results to understand what privileges were available.

From there, I found that the attacker had access to **SeRestorePrivilege**, which allows a user to restore files and directories while bypassing normal file permissions. This privilege is highly sensitive and can be abused to modify protected system files.

To understand how this privilege was used, I pivoted to the **USN Journal ($J)** and looked for file system activity around the same timeframe.

I observed that **Utilman.exe** was renamed to **utilman.old**, which is a strong indicator of binary replacement. Shortly after, **cmd.exe** appeared in its place.
This is a well-known privilege escalation technique often referred to as "Sticky Keys / Utilman backdoor" abuse.
This confirms that the attacker replaced the original accessibility binary with a command prompt.

This technique allows the attacker to launch a command prompt with **SYSTEM privileges** directly from the Windows logon screen using the Ease of Access feature (Windows + U), effectively bypassing authentication.

This behavior maps to the MITRE ATT&CK technique:

**T1546.008 – Accessibility Features**

<img width="1550" height="808" alt="UtensilMenace-Q9-Q10" src="https://github.com/user-attachments/assets/d07d202c-097c-4cfc-acdd-11a2f4bab1c6" />


---

### Answers

**Q8 ==> SeRestorePrivilege**

**Q9 ==> Utilman.exe, utilman.old**

**Q10 ==> cmd.exe**

**Q11 ==> T1546.008**

---

### Q12) Which key combination does the threat actor need to press and which protocol is used?

For this question, there was no direct artifact clearly stating the key combination. However, based on prior knowledge and experience, when **Utilman.exe** is replaced with **cmd.exe**, it can be triggered using the **Ease of Access shortcut (Windows + U)** at the logon screen.

Additionally, I observed an **RDP connection** from the previously identified malicious IP:

2025-04-27 07:30:54 → RDP server accepted a new TCP connection from 192.168.189.129

This confirms that the attacker accessed the system remotely using RDP and likely used this technique to gain SYSTEM-level access.
""" While there is no direct artifact for the key combination, replacing Utilman.exe enables execution via Windows + U at the logon screen.
Combined with the observed RDP connection, this confirms remote exploitation using this technique."""

**Answer ==> Windows + U, RDP**

---

### Q13 & Q14) Registry Persistence

To identify persistence, I looked into common registry run keys, specifically:

`Microsoft\Windows\CurrentVersion\Run`

This location is often abused by attackers to execute malicious programs at system startup.

By analyzing this path, I found a suspicious entry that was added by the attacker, along with its timestamp.
""" Run keys are commonly abused because they execute automatically when the user logs in, making them a simple but effective persistence mechanism."""

**Answer ==> 2025-04-27 07:38:07**

**Answer ==> DoraExplorer, C:\Windows\exploer.exe**


<img width="1548" height="811" alt="UtensilMenace-Q13-Q14" src="https://github.com/user-attachments/assets/73baa745-0e57-4f0c-a658-c6782eb5d66c" />


---

### Q15) When did the malicious file first appear and what was its original name?

For this question, I analyzed the **USN Journal ($J)** to track file activity.

I focused on the appearance of the suspicious file **exploer.exe** (note the typo, which is often used for masquerading). By correlating this with MFT data, I was able to identify when the file first appeared and its original name.
"""The misspelling “exploer.exe” is a classic masquerading technique used to evade casual detection."""

**Answer ==> 2025-04-27 07:35:01, FeedingFrenzy.exe**

<img width="1547" height="812" alt="UtensilMenace-Q15" src="https://github.com/user-attachments/assets/7a606dcf-5f56-41f4-9d12-f51a90949d32" />


---

### Q16 & Q17) Persistence via Services

For the final part, there are two ways to identify the persistence mechanism:

1. **Event Logs**
   - Event ID **7045** (Service Installed)
   - This shows when a new service is created and what executable it points to

<img width="1544" height="812" alt="UtensilMenace-Q16-Q17-Op2" src="https://github.com/user-attachments/assets/34b36ec4-c943-45f8-9579-6266e59527c2" />



2. **Registry Analysis**
   - Path: `ControlSet001\Services\`
   - This contains all services along with their configurations and timestamps

<img width="1548" height="806" alt="UtensilMenace-Q16-Q17" src="https://github.com/user-attachments/assets/b95abf7f-adde-4834-848d-4ab9667d9cdd" />




By analyzing both, I identified the malicious service and when it was executed.

**Answer ==> WindowsUpdateHarder**

**Answer ==> 2025-04-27 07:39:14**



Conclusion
---
From this investigation, I was able to reconstruct the full attack chain initiated by a seemingly harmless game download.

The analysis revealed that the downloaded executable was malicious and used as an entry point to execute additional payloads. The attacker performed reconnaissance using native system tools, abused privileges such as SeRestorePrivilege, and replaced critical system binaries to gain SYSTEM-level access.

Persistence was established through both registry run keys and a malicious service, ensuring continued access to the system. Additionally, evidence of RDP activity suggests the attacker remotely interacted with the machine after initial compromise.

This investigation highlights how attackers can leverage legitimate Windows features and weak monitoring to escalate privileges, maintain persistence, and evade detection. It also emphasizes the importance of analyzing multiple artifacts (logs, registry, MFT, and browser data) to fully understand attacker behavior.
---


<img width="879" height="819" alt="UtensilMenace" src="https://github.com/user-attachments/assets/a0b8407a-d1ed-46ed-b032-5da0ee84a88c" />

