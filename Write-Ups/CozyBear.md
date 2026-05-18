# 🚨 Cozy Bear Investigation

---

## 🎯 Objective
Conduct a threat hunting and incident investigation using ELK and Sysmon logs to identify malicious activity associated with the user account `pbeesly`, determine the nature of the compromise, and uncover indicators of compromise related to the attacker’s actions.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** Cozy Bear   
- **Difficulty:** Hard  
- **OS:** Linux
- **Category:** Threat Hunting / DFIR  

---

## 📖 Scenario
At precisely 2:15 PM, an alert linked to the user account `pbeesly` triggered inside the TechGuard Solutions SOC environment.

The account had already been under observation after the user reported opening a suspicious email that caused a strange black screen to briefly appear on their system. What initially appeared to be a phishing incident quickly escalated into a larger investigation once security monitoring systems began generating alerts tied to the same account.

The SOC team launched a threat hunting investigation using ELK and Sysmon logs to determine whether the user workstation had been compromised and identify the attacker’s activity within the environment.

---

## 🛠️ Tools Used
- ELK Stack  
- Sysmon Logs  
- OSINT  
- Hash Analysis  

---

## 🔎 Investigation Overview
The investigation focuses on analyzing Sysmon events and activity logs associated with the `pbeesly` account to uncover malicious processes, suspicious binaries, and attacker activity on the system.

By correlating Sysmon process activity, hashes, timestamps, and process metadata, it becomes possible to reconstruct the attacker’s actions and identify the malware involved in the compromise.

---

## Lab Setup

Before starting the investigation, the ELK environment was configured as follows:

1. Launch ELK
2. Open Mozilla Firefox and browse to:

```text
localhost:5601
```
Open the menu and navigate to:
Discover
Adjust the timeframe:
Select Absolute
Set the timeframe between:
Jan 10, 2019
Jan 10, 2024
Confirm the dataset contains:
195,952 hits
🔍 Investigation Process

The investigation began by filtering events associated with the suspicious user account:

DMEVALS\pbeesly

From there, Sysmon logs and process creation events were analyzed to identify suspicious binaries and malicious execution activity tied to the compromise.
---
Q1) How many activity related log hits are associated with “pbeesly” user?

To begin the investigation, I filtered the logs using the following user account:

DMEVALS\pbeesly

After applying the filter inside ELK, the dataset revealed:

790

activity-related log hits associated with the user.

<img width="1891" height="768" alt="CozyBear-Q1" src="https://github.com/user-attachments/assets/5ffa4e2e-211f-4a3f-907d-a6b97eba627e" />

***Answer ==> 790***
---

Q2) Can you identify the name of the malicious binary downloaded?

After filtering for the pbeesly user, I sorted the events chronologically to review the earliest suspicious activity related to the compromise.

During the investigation, I noticed the following suspicious file path:

C:\ProgramData\victim\â\u20ac®cod.3aka3.scr

The unusual filename and .scr extension immediately stood out as suspicious.

To confirm whether the file was malicious, I performed OSINT analysis using its SHA-256 hash:

0df38a55d940f498478eb03683c94d4584236e100125b526a67650ba54df4ae4

The results identified the binary as belonging to the:

PUPYRAT

malware family.

<img width="1894" height="820" alt="CozyBear-Q2-p1" src="https://github.com/user-attachments/assets/c3d87af4-6759-47ca-bc33-d9e510da1946" />


<img width="1901" height="920" alt="CozyBear-Q2-p2" src="https://github.com/user-attachments/assets/54504ef1-2c00-4178-98f9-0c142e00b21f" />


***Answer ==> â\u20ac®cod.3aka3.scr***
---

Q3) What is the binary’s ProcessGuid?

While reviewing the Sysmon events associated with the malicious binary, one event revealed the process metadata, including the ProcessGuid value.

The following event contained the required information:

UtcTime: 2020-05-02 02:55:59.631

ProcessGuid: {47ab858c-e13c-5eac-a903-000000000400}

This ProcessGuid uniquely identifies the malicious process execution within the Sysmon logs.

<img width="1894" height="820" alt="CozyBear-Q2-Q3" src="https://github.com/user-attachments/assets/a483afbc-32d6-445f-933d-28c6c42a44ee" />


***Answer ==> {47ab858c-e13c-5eac-a903-000000000400}***

---
## Q4) What IP address and Port does the victim machine communicate with after the binary executes?

To identify any network communication established by the malicious binary, I filtered the Sysmon logs using:

- The malicious binary name
- `EventID: 3`

Sysmon Event ID 3 corresponds to:

```text id="33r2ij"
Network Connection
```
This allowed me to identify outbound communication initiated by the malicious process.

The following values were observed in the event details:

DestinationIp: 192.168.0.5

DestinationPort: 1234

This confirmed that the compromised host established communication with a remote endpoint after execution of the malware.

***Answer ==> 192.168.0.5,1234***

Q5) Can you identify the exact timestamp that this communication happened?

While reviewing the same Sysmon Event ID 3 network connection event associated with the malicious binary, I identified the exact timestamp of the communication.

The event occurred at:

May 1, 2020 @ 22:56:00.000

This timestamp corresponds to the moment the compromised host communicated with the remote endpoint.

***Answer ==> May 1, 2020 @ 22:56:00.000***

<img width="1893" height="772" alt="CozyBear-Q4-Q5" src="https://github.com/user-attachments/assets/a6077b32-8403-44cd-b91e-02dfcb95edca" />

---
Q6) Hunting for Defense Evasion, after a malicious binary was discovered from doing Q1-5 hunt, can you identify the next binary that was launched? Include the full path.

After identifying the initial malicious binary and associated communication, I continued hunting for potential defense evasion activity.

To do this, I pivoted from the original malicious process and reviewed subsequent process creation events using:

EventID: 1

Sysmon Event ID 1 corresponds to:

Process Creation

While reviewing the process activity associated with the malicious binary’s directory and timeline, I identified the following suspicious process execution:

CommandLine: C:\windows\system32\sdclt.exe

The binary identified was:

C:\Windows\System32\sdclt.exe

This binary is commonly abused for UAC bypass and defense evasion techniques.

<img width="1896" height="775" alt="CozyBear-Q6" src="https://github.com/user-attachments/assets/14437a4e-a7d0-4d2d-a54b-fe03e2abb6c7" />


***Answer ==> C:\Windows\System32\sdclt.exe***
---
Q7) What is the name of the child process created by this binary? Include the full path.

To identify child processes spawned by sdclt.exe, I filtered the Sysmon logs using:

ParentImage: *sdclt.exe*

EventID: 1

This revealed a process creation event showing the following command line:

"C:\Windows\System32\control.exe"

The associated child process created by sdclt.exe was:

C:\Windows\System32\control.exe

<img width="1894" height="775" alt="CozyBear-Q7" src="https://github.com/user-attachments/assets/aa4425bd-f18a-4cf5-9763-8b9f457e67de" />


***Answer ==> C:\Windows\System32\control.exe***
---

Q8) What is the original name of the binary?

To continue the investigation, I pivoted to processes spawned by:

control.exe

using the following filter:

ParentImage: *control.exe*

During the analysis, the process metadata revealed the original binary name as:

powershell.exe

This indicated that PowerShell was ultimately executed during the attack chain.

<img width="1893" height="778" alt="CozyBear-Q8" src="https://github.com/user-attachments/assets/b4f3d07d-927c-45d9-8f2d-18d2635acd57" />

****Answer ==> powershell.exe****
---

Q9) What is the file that contains the hidden payload?

While analyzing the PowerShell execution activity from the previous question, I noticed references to a suspicious image file located in the Downloads directory:

C:\Users\pbeesly\Downloads\monkey.png

Since attackers commonly hide payloads inside image files using steganography or embedded content techniques, this file strongly appeared to contain the hidden payload used during execution.

***Answer ==> monkey.png***

Q10) What is the .NET framework class used to execute the payload?

To continue investigating the hidden payload execution, I filtered the PowerShell command activity associated with monkey.png.

During the analysis, I identified the following PowerShell snippet:

$g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png'

This revealed the .NET framework class used during the payload execution process:

System.Drawing.Bitmap

***Answer ==> System.Drawing.Bitmap***

Q11) After the hidden payload was executed, what process/binary was created?

While reviewing the same execution chain associated with the hidden payload, I identified the following process creation event:

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe

This indicated that the payload execution ultimately spawned:

csc.exe

The csc.exe binary is the Microsoft C# compiler and is commonly abused by attackers to compile and execute malicious code dynamically.

***Answer ==> csc.exe***

Q12) What is the associated CommandLine for this binary?

During the same process creation event for csc.exe, I identified the full command line used during execution:

"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline"

From this command, the associated command line file identified was:

qkbkqqbs.commandline

****Answer ==> qkbkqqbs.commandline****

<img width="1892" height="766" alt="CozyBear-Q9-Q10-Q11-Q12" src="https://github.com/user-attachments/assets/cd6c0d41-8ab3-4eae-9ab0-a81f326f9894" />

---
Q13) Hunting for Privilege Escalation, what elevation type was gained by the threat actor? What type of user?

To investigate possible privilege escalation activity, I continued analyzing the events associated with:

csc.exe

While reviewing the Sysmon process metadata, I identified the following token elevation value:

%%1937

This TokenElevationType value indicates that the process was executed with elevated privileges.

Additionally, the context of the execution and associated privileged operations strongly suggested the attacker successfully obtained:

administrator

level access on the compromised host.

<img width="1894" height="773" alt="CozyBear-Q13" src="https://github.com/user-attachments/assets/4945e83e-8297-4d1a-ab90-526cf80a9ded" />

***Answer ==> %%1937,administrator***
---

Q14) Hunting for Indicator Removal, at what exact time does the threat actor delete its indicator from the registry?

To investigate indicator removal activity, I searched for registry modification events using:

EventID: 12

Sysmon Event ID 12 corresponds to registry object creation and deletion activity.

I specifically filtered for:

*shell\open\command*

This registry location is commonly abused during UAC bypass and persistence techniques, especially involving binaries such as:

sdclt.exe

Attackers often create or modify keys within this path to hijack execution flow and launch malicious payloads with elevated privileges.

Later, once the malicious activity is complete, attackers frequently remove these registry entries to cover their tracks and reduce forensic evidence left on the system.

The registry deletion activity occurred at:

May 1, 2020 @ 22:59:15.000

<img width="1894" height="779" alt="CozyBear-Q14" src="https://github.com/user-attachments/assets/630dcff0-0a69-46fa-a10f-6f71f5946912" />

***Answer ==> May 1, 2020 @ 22:59:15.000***
---

---

## Q15) Hunting for Persistence, in what location does the threat actor add the malicious binary to survive reboot?

Since one of the most common persistence techniques used by attackers involves the Windows Startup folder, I decided to investigate file creation activity related to startup persistence locations.

To do this, I filtered the logs using:

```text id="x1x8cf"
EventID: 11 AND TargetFilename:*StartUp*
```
Sysmon Event ID 11 corresponds to:

File Create

During the investigation, I identified the following event:

May 1, 2020 @ 23:04:23.000

TargetFilename: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk

Image: C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe

This confirmed that the attacker established persistence through the Windows Startup folder.

The persistence location identified was:

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\

***Answer ==> C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\***

Q16) What is the associated binary responsible for the execution and the file dropped at this particular location?

The same Sysmon Event ID 11 event used in the previous question also revealed:

The binary responsible for creating the persistence mechanism
The file dropped into the Startup folder

From the event details:

Image: C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe

and:

TargetFilename: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk

I identified:

The responsible binary:
powershell.exe
The dropped persistence file:
hostui.lnk

***Answer ==> powershell.exe, hostui.lnk***

<img width="1895" height="770" alt="CozyBear-Q15-Q16" src="https://github.com/user-attachments/assets/beec71d3-dade-4ed8-aa4f-fd73a299a5fd" />
---

Q17) According to threat intelligence team, this particular threat actor leverages Windows Service to maintain persistence. Identify the binaries added as a service.

To investigate service-based persistence mechanisms, I searched for Windows service installation events using:

EventID: 7045

Windows Event ID 7045 corresponds to:

A new service was installed in the system

While reviewing these events, I identified two suspicious binaries registered as services by the attacker:

javamtsup.exe

and:

PSEXESVC.exe

These binaries were leveraged by the threat actor to maintain persistence and potentially facilitate remote execution or lateral movement.

<img width="1892" height="766" alt="CozyBear-Q17png" src="https://github.com/user-attachments/assets/d302ec50-4103-424d-ad93-3ad8a1b392b1" />

***Answer ==> javamtsup.exe, PSEXESVC.exe***
---

## Conclusion

This investigation demonstrated how a single malicious file execution quickly escalated into a multi-stage compromise involving command-and-control communication, privilege escalation, persistence, and defense evasion techniques.

Through analysis of Sysmon and Windows event logs in ELK, I was able to follow the attacker’s activity step-by-step, beginning with the malicious `.scr` file and continuing through PowerShell execution, hidden payload delivery, registry modifications, Startup folder persistence, and malicious service creation.

The attacker relied heavily on legitimate Windows binaries and native system functionality to avoid detection and maintain access on the compromised machine.

One of the most interesting parts of the investigation was identifying how the payload was hidden inside an image file and later executed through PowerShell and the .NET framework.

Overall, this lab provided a great hands-on example of real-world threat hunting and how multiple attacker techniques can be correlated through proper log analysis and event investigation.

---
<img width="881" height="820" alt="CozyBear1-Done" src="https://github.com/user-attachments/assets/1d0b1afc-70ea-4014-8df3-b6d5f4d0e4be" />
