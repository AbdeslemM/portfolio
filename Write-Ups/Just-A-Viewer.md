# 🚨 Just a Viewer Investigation

---

## 🎯 Objective
Analyze Windows Event Logs to identify attacker activity, reverse shell execution, persistence mechanisms, and process migration performed after the installation of a malicious PDF reader application.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** Just a Viewer  
- **Environment:** Windows  
- **Difficulty:** Medium  
- **Category:** DFIR / Windows Event Log Analysis  

---

## 📖 Scenario
While away from headquarters, an old friend named Bob asked for help after suspecting his computer had been fully compromised shortly after installing a new PDF viewing program.

The only evidence available for the investigation was a collection of Windows Event Logs.

The objective of this investigation is to analyze the logs, reconstruct attacker activity, and identify evidence of compromise using Windows event analysis and MITRE ATT&CK techniques.

---

## 🛠️ Tools Used
- EvtxECmd  
- Timeline Explorer  
- MITRE ATT&CK Mapping  

---

## 🔍 Investigation Setup

For this investigation, the provided Windows Event Logs were parsed using:

```powershell id="h8rw6v"
.\EvtxECmd.exe -d "C:\Users\BTLOTest\Desktop\Investigation\Logs\" --csv Logs.csv
```

After parsing the logs, the generated CSV output was opened using:

Timeline Explorer

to investigate Sysmon and Windows event activity.

---
Q1) A PDF Reader Program was installed in the system. Can you determine the date when it was installed, as well as the name of the program?

To identify installed applications, I investigated:

MsiInstaller Event ID 1033

which records successful Windows Installer application installations.

Since the scenario referenced a PDF reader application, I searched for well-known PDF reader software and identified the following installation event:

2024-05-03 15:16:54

The installed application identified was:

Adobe Reader

The installation date in the required format is:

05/03/2024

<img width="1546" height="839" alt="Just-A-Viewer-Q1" src="https://github.com/user-attachments/assets/0ed50921-b145-48ea-b1c8-8a15452abaf4" />

***Answer ==> 05/03/2024, Adobe Reader***
---

## Q2) The attacker used DLL hijacking to establish a reverse shell; the attacker then migrated to another process. Can you identify the name of the target program to which the attacker migrated and provide the SourceProcessGuid associated with this process?

For this question, I had to decide between investigating:

- Process Creation (`Event ID 1`)
- CreateRemoteThread (`Event ID 8`)

Since DLL hijacking and process migration activity are commonly associated with remote thread creation, I focused on:

```text id="6bc8m9"
Sysmon Event ID 8
```
After filtering the logs and reviewing the timeline shortly after the malicious PDF reader installation, I identified suspicious activity occurring at:

2024-05-03 15:26:18

The event showed:

SourceImage: C:\Windows\SysWOW64\rundll32.exe

which was highly suspicious considering rundll32.exe is commonly abused during DLL hijacking activity.

The attacker then migrated into the following legitimate process:

putty

with the associated:

SourceProcessGuid

being:

06639772-00b4-6635-d401-000000000600

This activity strongly suggests the attacker used DLL hijacking to establish a reverse shell and then migrated into another trusted process to blend in with legitimate activity.

<img width="1550" height="836" alt="Just-A-Viewer-Q2" src="https://github.com/user-attachments/assets/567cf434-0d96-4bb4-bbf9-15aaf0ad54d0" />

***Answer ==> putty, 06639772-00b4-6635-d401-000000000600***

---
## Q3) Can you determine the IP address, port number, and the exact date and time the connection was established for the reverse shell associated with the previously identified program?

For this question, I investigated:

```text id="m5c4sx"
Sysmon Event ID 3
```
which corresponds to:

Network Connections

I filtered the logs using the previously identified:

SourceProcessGuid
06639772-00b4-6635-d401-000000000600

This revealed the reverse shell connection established by the compromised process.

The destination IP and port identified were:

172.18.55.132:443

with the exact connection timestamp:

2024-05-03 15:20:20.623

This activity maps closely to:

MITRE ATT&CK T1071 - Application Layer Protocol

since the attacker established communication over a commonly used port to blend in with legitimate traffic.

<img width="1548" height="839" alt="Just-A-Viewer-Q3" src="https://github.com/user-attachments/assets/ec0c5c40-3232-41d5-9555-c6a705f316dd" />

***Answer ==> 172.18.55.132:443, 2024-05-03 15:20:20.623***

---
Q4) The attacker executed a specific command to collect information about Bob. Can you identify the exact command used by the attacker within this process?

Since attackers commonly execute reconnaissance commands immediately after gaining access, I searched for:

whoami

within:

Sysmon Event ID 1

(Process Creation)

While reviewing the timeline, I identified the following command executed at:

2024-05-03 15:27:50

The exact command executed by the attacker was:

whoami -all

This command allows the attacker to enumerate:

Current user information
Group memberships
Privileges
Security identifiers (SIDs)

which helps the attacker understand the privilege level of the compromised account.

This activity maps to:

MITRE ATT&CK T1033 - System Owner/User Discovery

<img width="1545" height="840" alt="Just-A-Viewer-Q4" src="https://github.com/user-attachments/assets/fc921b55-a2fd-425d-b76e-8236f52dd6ff" />

***Answer ==> whoami -all***

---
Q5) After gathering information about the victim, the attacker migrated to a different process. Can you identify the new process into which the attacker injected?

For this question, I again investigated:

Sysmon Event ID 8

which corresponds to:

CreateRemoteThread

This event is commonly associated with:

MITRE ATT&CK T1055 - Process Injection

By correlating the timeline after the reconnaissance activity, I identified another suspicious remote thread creation event occurring at:

2024-05-03 15:36:16.371

The attacker migrated into the following process:

explorer.exe

This likely helped the attacker blend malicious activity into a legitimate and trusted Windows process.

<img width="1549" height="869" alt="Just-A-Viewer-Q5" src="https://github.com/user-attachments/assets/03734a89-2404-46ff-9ac4-1bde4c075893" />

***Answer ==> explorer.exe***
---

## Q6) The attacker bypassed Windows User Account Control (UAC) by altering a specific registry key. Could you provide the Security Identifier (SID) of the affected user account and the exact name of the registry key that the attacker modified?

For this question, I investigated:

```text id="m1s4pj"
Sysmon Event ID 13
```
which corresponds to:

Registry Value Set

Since the question referenced:

UAC bypass

I searched for suspicious PowerShell commands commonly associated with registry-based UAC bypass techniques.

During the investigation, I identified the following suspicious command executed at:

2024-05-03 15:47:49.043
C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe -nop -w hidden -c "IEX (Get-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name ttMvYgaA).ttMvYgaA"

This command is highly suspicious because attackers commonly abuse:

HKCU:\Software\Classes\ms-settings\shell\open\command

to bypass:

Windows User Account Control (UAC)

using the well-known:

fodhelper.exe

UAC bypass technique.

The modified registry value name identified was:

ttMvYgaA

and the affected user SID was:

S-1-5-21-334338966-2847233334-3795763244-1001

This activity maps closely to:

MITRE ATT&CK T1548.002 - Bypass User Account Control

<img width="1551" height="841" alt="Just-A-Viewer-Q6" src="https://github.com/user-attachments/assets/da6c8aba-fce3-47e9-80a4-49fce6c321fc" />

***Answer ==> S-1-5-21-334338966-2847233334-3795763244-1001, ttMvYgaA***
---

Q7) The attacker successfully escalated privileges using an impersonation technique. Can you identify the specific command that was executed during this process?

For this question, I investigated:

Sysmon Event ID 1

(Process Creation)

and reviewed suspicious commands executed shortly after the previously identified UAC bypass activity.

At:

2024-05-03 15:48:18.031

I identified the following suspicious command:

cmd.exe /c echo tcjzyy > \\.\pipe\tcjzyy

This activity is suspicious because attackers commonly use:

Named Pipes

during token impersonation and privilege escalation activity to communicate between processes and impersonate elevated privileges.

This behavior maps to:

MITRE ATT&CK T1134 - Access Token Manipulation

<img width="1552" height="841" alt="Just-A-Viewer-Q7" src="https://github.com/user-attachments/assets/27cc93ee-c3c4-44a1-8254-b13f2d07b7fa" />

***Answer ==> cmd.exe /c echo tcjzyy > \.\pipe\tcjzyy***

---

Q8) After successfully executing a privilege escalation attack, the attacker generated a script for a persistence mechanism and stored it in a designated location. Could you identify the name and the programming language of this script file?

For this question, I moved to investigating:

Sysmon Event ID 11

(File Creation)

Since the question referenced a persistence script, I searched for common scripting extensions frequently abused by attackers, including:

.ps1
.vbs
.bat

While reviewing the events, I identified the following file creation event at:

2024-05-03 16:03:56.808

The script file identified was:

ZbWgrkz.vbs

Since the extension is:

.vbs

the scripting language used is:

VBScript

This activity maps to:

MITRE ATT&CK T1547 - Boot or Logon Autostart Execution

because the attacker prepared the script for persistence after privilege escalation.

<img width="1548" height="840" alt="Just-A-Viewer-Q8" src="https://github.com/user-attachments/assets/e3033129-ceda-42e8-a9d3-0d5372f2afe3" />

***Answer ==> ZbWgrkz.vbs, VBScript***
---

Q9) To establish persistence, the attacker modified a specific registry entry. Could you identify the name of the registry key that was created and altered?

For this question, I again investigated:

Sysmon Event ID 13

which records:

Registry Value Set

Since attackers commonly use:

CurrentVersion\Run

registry keys for persistence, I searched for:

CurrentVersion\\Run

within the logs.

At:

2024-05-03 16:03:57.168

I identified the suspicious registry modification.

The created registry key name was:

S4mb0H4ck

This persistence mechanism ensures the malicious payload executes automatically whenever the user logs in.

This activity maps to:

MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder

<img width="1548" height="837" alt="Just-A-Viewer-Q9" src="https://github.com/user-attachments/assets/377a5db4-4285-403d-ab64-f2cab826fda8" />

***Answer ==> S4mb0H4ck***

---
Q10) Once the attacker achieved persistence, an executable was dropped. This executable will create a reverse shell as soon as the system reboots and the user logs in. Locate the executable and determine its MD5 hash.

For this question, I investigated:

Sysmon Event ID 11

(File Creation)

Since the question referenced a dropped executable, I filtered for executable files created under suspicious user-controlled locations such as:

\Users\Bob\AppData\Local\Temp\

While reviewing the timeline, I identified the following executable creation event at:

2024-05-03 16:07:01

The dropped executable was:

winupdate.exe

After searching for the file in the logs, I identified its MD5 hash:

6A524C3ACA8E5A5E1D0B5E7523CDB88D

The logs also revealed:

OriginalFileName: ab.exe

which is commonly associated with:

Azorult

a well-known information-stealing malware family.

This activity maps closely to:

MITRE ATT&CK T1059 - Command and Scripting Interpreter

as well as persistence-related attacker activity.

<img width="1545" height="839" alt="Just-A-Viewer-Q10" src="https://github.com/user-attachments/assets/b3329003-8c1e-4234-900a-0815261e6012" />

***Answer ==> winupdate.exe, 6A524C3ACA8E5A5E1D0B5E7523CDB88D***

---
## Conclusion

This investigation revealed a full compromise that started shortly after the installation of a malicious PDF reader application. By analyzing Windows Event Logs and Sysmon telemetry, I was able to trace the attacker’s activity from the initial reverse shell connection to privilege escalation, persistence, and malware deployment.

Throughout the investigation, multiple attacker techniques were identified, including DLL hijacking, UAC bypass, process migration, registry-based persistence, and malicious payload execution. The attacker ultimately deployed an Azorult-related executable capable of re-establishing access after system reboot.

Overall, this lab provided valuable hands-on experience in Windows event log analysis, Sysmon investigation, timeline correlation, and mapping attacker behavior to MITRE ATT&CK techniques.

---

<img width="887" height="822" alt="Just-A-Viewer-Done" src="https://github.com/user-attachments/assets/fd67bd58-1754-4aad-ad5d-00ec165c5a54" />
