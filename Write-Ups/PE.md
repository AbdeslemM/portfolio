# 🚨 PE Investigation

---

## 🎯 Objective
Analyze Sysmon and osquery logs from a compromised Windows endpoint to identify attacker activity, persistence mechanisms, and post-exploitation techniques.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** PE  
- **Difficulty:** Easy
- **OS:** Linux
- **Category:** Threat Hunting / Log Analysis  

---

## 📖 Scenario
Sysmon logs were collected from a compromised Windows endpoint, but not all attacker activity was fully captured.

Fortunately, the `osqueryd` service was enabled on the host and retained valuable endpoint telemetry that could be correlated with Sysmon events.

The objective of this investigation was to analyze both Sysmon and osquery logs to identify malicious activity, attacker persistence, and post-exploitation behavior.

---

## 🛠️ Tools Used
- ELK  
- Sysmon Logs  
- osquery  
- MITRE ATT&CK Mapping  

---

## 🔍 Investigation Setup

If Kibana was inaccessible while navigating to:

```text id="m4q0kn"
localhost:5601
```
the following services needed to be started:

sudo systemctl start kibana
sudo systemctl start logstash
sudo systemctl start elasticsearch

---
Q1) What is the first suspicious script file used by the attacker?

For the first questions, I initially focused on:

Sysmon Event ID 1

which corresponds to:

Process Creation

However, there were over:

732 events

making manual review difficult.

I first searched for common malicious script extensions such as:

.ps1
.cmd
.bat

but nothing immediately suspicious appeared.

I then pivoted to a very common attacker download location:

AppData\\Local\\Temp

This quickly revealed a suspicious command containing the malicious script name.

The identified script was:

gCz4p.wsf

***Answer ==> gCz4p.wsf***

Q2) What is the process by which the attacker downloaded it?

From the same suspicious command identified previously, I was able to determine the process responsible for downloading the malicious script.

The process identified was:

bitsadmin.exe

bitsadmin.exe is a legitimate Windows utility often abused by attackers for stealthy file downloads.

***Answer ==> bitsadmin.exe***

Q3) What is the attackers's IP used for the download?

The same command line also revealed the remote IP address used by the attacker during the download activity.

The identified IP was:

192.168.1.14

***Answer ==> 192.168.1.14***

<img width="1895" height="763" alt="PE-Q1-Q2-Q3" src="https://github.com/user-attachments/assets/ab7e4921-5161-4b08-ace8-d238a3b06812" />

---

Q4) List the process used in the order of execution of the script file after downloading.

To answer this question, I filtered specifically for:

gCz4p.wsf

and displayed only the command line process executions using:

Event_EventData_CommandLine

This revealed the sequence of processes involved in executing the malicious script:

cmd.exe
wscript.exe
rundll32.exe

These processes were observed executing in sequence after the script download.

<img width="1896" height="769" alt="PE-Q4" src="https://github.com/user-attachments/assets/50ad1e0b-c017-4f47-b641-82e3074fa68d" />

***Answer ==> cmd.exe, wscript.exe, rundll32.exe***

---

Q5) What is the new user added by the attacker?

For this question, I pivoted to analyzing:

osquery

Using the following filter:

name:users AND action:added

I identified a newly created user account added during the compromise.

The username added by the attacker was:

btlo

Observed at:

Jun 24, 2021 @ 18:22:32.000

<img width="1896" height="767" alt="PE-Q5" src="https://github.com/user-attachments/assets/b2c3d0ab-2589-465f-a564-a1c0aa62ffdc" />

***Answer ==> btlo***
---

Q6) What is the registry key data added by the attacker?

To identify persistence-related registry modifications, I searched osquery results using:

HKCU_Run AND added

This revealed a suspicious Run registry key modification:

C:\Windows\system32\mshta.exe C:\Users\IEUser\AppData\Roaming\KUTGPKDRCB.hta

The attacker configured:

mshta.exe

to automatically execute a malicious HTA payload at user logon, providing persistence on the compromised host.

<img width="1899" height="768" alt="PE-Q6-Q8" src="https://github.com/user-attachments/assets/9718ff39-e9d4-452e-8a6f-fa12d9f21c7c" />

***Answer ==> C:\Windows\system32\mshta.exe C:\Users\IEUser\AppData\Roaming\KUTGPKDRCB.hta***

---

# Q7) Other than the above 2 persistent techniques, what is the one other technique used by the attacker as per MITRE ATT&CK.

From the previous questions, we already identified multiple persistence mechanisms used by the attacker, including:

- Registry Run Keys / Startup Folder  
- HTA execution through `mshta.exe`

which map to common MITRE ATT&CK persistence techniques.

For this question, I investigated possible additional persistence activity related to:

```text id="y4ec2z"
Scheduled Tasks
```
which corresponds to:

MITRE ATT&CK T1053

While reviewing the logs, I noticed multiple executions and references related to scheduled task activity, including artifacts associated with:

schtasks.exe

and scheduled task entries observed in osquery results.

Although I could not fully confirm a clearly malicious scheduled task directly tied to the attacker payload, the evidence strongly suggested possible scheduled task usage during the compromise, which is why this technique aligns with:

T1053

<img width="1898" height="765" alt="PE-Q7" src="https://github.com/user-attachments/assets/fdbe1a49-b398-4242-b15f-65a068da6933" />

***Answer ==> T1053***
---
## Q8) Do you know the name of this post exploitation tool?

Based on the attacker activity observed during the investigation, including:

- HTA payload execution
- `mshta.exe` abuse
- Registry Run Key persistence
- Script-based payload delivery

the behavior strongly matched the well-known post-exploitation framework:

```text id="3s1n5v"
koadic
```
Koadic is a Windows post-exploitation framework that commonly relies on:

mshta.exe
HTA payloads
Script execution
Persistence mechanisms

which aligns closely with the activity identified throughout the investigation.

***Answer ==> koadic***

---
Conclusion

This investigation demonstrated how combining Sysmon and osquery telemetry can help uncover attacker activity even when some logs are missing.

By analyzing process creation events, registry modifications, persistence mechanisms, and osquery results, I was able to identify the malicious script execution chain, attacker-created user account, persistence activity, and the post-exploitation framework used during the compromise.

Overall, this lab provided solid hands-on experience with endpoint log analysis and threat hunting using both Sysmon and osquery data.
----

<img width="880" height="826" alt="PE-Done" src="https://github.com/user-attachments/assets/5538ca6a-4531-4898-8889-6515ef766672" />

