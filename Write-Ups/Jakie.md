# 🚨 Jakie Investigation

---

## 🎯 Objective
Conduct a forensic investigation using NTFS artifacts, primarily the `$MFT` and `$UsnJrnl`, to identify evidence of unauthorized data access, downloads, file handling activity, and potential data exfiltration performed by an insider.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** Jakie   
- **Difficulty:** Medium  
- **OS:** Windows  
- **Category:** Digital Forensics / NTFS Analysis  

---

## 📖 Scenario
Jakie, a software tester assigned to a healthcare project, was responsible for testing applications and generating compliance reports for the customer.

During the testing process, Jakie discovered sensitive information including patient personal details, pharmacy contacts, and customer performance reports. Instead of responsibly reporting the findings, Jakie copied confidential files to a USB device and attempted to install a portable operating system with the intention of selling the stolen healthcare records on the dark web.

Fortunately, the internal security team detected suspicious activity involving the installation of an unapproved virtual machine and initiated an investigation before the exfiltration process could be completed.

Although Jakie attempted to wipe the downloaded files after being caught, investigators recovered NTFS forensic artifacts to reconstruct the activity and identify supporting evidence related to the data breach.

---

## 🛠️ Tools Used
- EZTools  
---

## 🔎 Investigation Overview
The investigation focuses on analyzing NTFS forensic artifacts to identify downloaded files, deleted evidence, user activity, and suspicious handling of healthcare-related documents.

By correlating `$MFT` and `$UsnJrnl` artifacts, it becomes possible to reconstruct the sequence of events and recover evidence of unauthorized file activity despite attempts to wipe the data.

---

## 🔍 Investigation Process

For this lab, I started by parsing the NTFS artifacts using EZTools, specifically focusing on:

- `$MFT`
- `$UsnJrnl ($J)`

### Commands used for parsing:

```powershell
.\MFTECmd.exe -f "C:\Users\BTLOTest\Desktop\Evidence\F\`$MFT" --csv MFT.csv
.\MFTECmd.exe -f "C:\Users\BTLOTest\Desktop\Evidence\F\`$Extend\`$J" --csv J.csv
```
After parsing the artifacts, I opened the generated CSV outputs using:

Timeline Explorer

to analyze timestamps, file activity, ADS entries, and deleted records.

Q1) Submit the EntryNumber of $MFT file from the provided $MFT Evidence.

The first question was straightforward.

While reviewing the parsed $MFT entries, it was clear that the $MFT file itself had the following corresponding EntryNumber:

0

<img width="1545" height="844" alt="Jakie-Q1" src="https://github.com/user-attachments/assets/f931d059-3831-43a6-9e3a-3365bd4f00cf" />

***Answer ==> 0***
---
Q2) Jakie was working on testing a Healthcare related project. Submit the fullpaths with filenames of the two archived project files downloaded from the web. [Hint: Alternate data stream zone identifier]

The hint pointed directly toward:

Zone.Identifier

which is an Alternate Data Stream (ADS) automatically added by Windows to files downloaded from the internet.

To identify suspicious downloads, I searched the parsed $MFT entries for:

Zone.Identifier
Archive extensions such as:
.zip
.7z
.rar
.iso

Since ZIP files are the most common archive format, I started filtering for .zip entries associated with Zone.Identifier.

This revealed the following downloaded archive files:

C:\Users\jakie\Documents\Patient-Information-Management-API-main.zip

and:

C:\Users\jakie\Documents\Hospital-Management-System-master.zip

These files were downloaded from the web and retained the associated Zone Identifier ADS entries.

<img width="1548" height="841" alt="Jakie-Q2" src="https://github.com/user-attachments/assets/f2d6c78a-d57e-473c-ad41-995bb4655d94" />

***Answer ==> C:\Users\jakie\Documents\Patient-Information-Management-API-main.zip, C:\Users\jakie\Documents\Hospital-Management-System-master.zip***
---
Q3) Testing is performed to meet the requirements of a healthcare-specific compliance framework. Submit the name of this framework.

Since the scenario involved handling healthcare-related information and patient data, the most relevant compliance framework associated with healthcare environments is:

HIPAA

HIPAA stands for:

Health Insurance Portability and Accountability Act

It is a well-known healthcare compliance framework focused on protecting sensitive patient and medical information.

***Answer ==> HIPAA***
---

## Q4) Submit the windows username found which is related to the reported incident.

This question was straightforward since the scenario itself already referenced the user:

```text id="3v0n9f"
jakie
```
Additionally, multiple filesystem paths throughout the evidence confirmed the associated Windows user profile, such as:

C:\Users\jakie

***Answer ==> jakie***
---
Q5) What is the IDE observed on the user's machine?

While reviewing the user’s Desktop directory:

F:\Users\jakie\Desktop

I identified the following file:

Eclipse IDE for Java Developers - 2022-06

This clearly indicated that the Integrated Development Environment (IDE) installed or used on the system was:

Eclipse

<img width="1550" height="842" alt="Jakie-Q5" src="https://github.com/user-attachments/assets/13065ce4-da07-4441-834c-54aeb4c76078" />

***Answer ==> Eclipse***
---
Q6) What is the widely-used communication/collaboration platform used by Jakie for work purposes?

There were multiple possible ways to identify this application.

One approach would be reviewing Prefetch artifacts for executed applications. However, in this investigation, I decided to inspect the user’s AppData directories instead.

While reviewing:

F:\Users\jakie\AppData\

I identified the following executable path:

F:\Users\jakie\AppData\Local\slack\slack.exe

This confirmed that the collaboration platform used by Jakie was:

Slack

<img width="1551" height="837" alt="Jakie-Q6" src="https://github.com/user-attachments/assets/2e7edf58-2502-409e-8366-ca1f923984b0" />

***Answer ==> slack***
---
Q7) The person of interest accessed a network share to install whitelisted software. Submit the Drive Name.

To investigate recently accessed resources, I reviewed the Windows Recent Items directory:

F:\Users\jakie\AppData\Roaming\Microsoft\Windows\Recent

While examining the .lnk shortcut files, I identified the following entry:

ApprovedTools.lnk

This indicated that the user accessed a network share or mapped drive named:

ApprovedTools

<img width="1548" height="841" alt="Jakie-Q7" src="https://github.com/user-attachments/assets/a1fff9e9-86cc-4303-a473-e7c241eebf22" />

***Answer ==> ApprovedTools***
---
Q8) Submit the MACB timestamps of the testing report created by Jakie - "HealthProjectTestReportv1.doc" in chronological order.

For this question, I searched the parsed $MFT entries for the following file:

HealthProjectTestReportv1.doc

From the associated artifact entry, I extracted the MACB timestamps.

MACB represents:

M → Modified
A → Accessed
C → Metadata Changed
B → Birth/Created

The timestamps identified for the file were:

2022-07-04 10:07:59

2022-07-04 10:07:59

2022-07-04 10:27:39

2022-07-04 10:04:39

<img width="1548" height="838" alt="Jakie-Q8" src="https://github.com/user-attachments/assets/d95971b5-71d7-4c96-a785-b2eb0061ca97" />

****Answer ==> 2022-07-04 10:07:59, 2022-07-04 10:07:59, 2022-07-04 10:27:39, 2022-07-04 10:04:39***
---
Q9) As part of the breach, two sensitive excel files were downloaded by the user. Provide the filenames.

To answer this question, I pivoted to analyzing the $UsnJrnl ($J) artifact.

Since the scenario mentioned sensitive Excel files being downloaded, I filtered for:

Excel extensions:
.xls
.xlsx
File creation activity

This helped reduce unrelated entries and focus specifically on newly created spreadsheet files.

During the investigation, I identified the following sensitive files:

Patient_PII_Confidential.xls

and:

PharmaList.xlsx

These filenames strongly matched the healthcare-related sensitive information described in the scenario.

<img width="1545" height="840" alt="Jakie-Q9" src="https://github.com/user-attachments/assets/1442658a-9002-4ca7-b4ac-1ff6dba2d824" />

***Answer ==> Patient_PII_Confidential.xls, PharmaList.xlsx***
---
Q10) The two files from the previous question were later renamed. What are the renamed filenames?

To identify the renamed versions of the sensitive Excel files, I continued analyzing the $UsnJrnl ($J) entries.

This time, I filtered for:

Rename

related update reasons associated with the previously identified files.

The investigation revealed that the attacker renamed the files to:

HealthCareProject1.xls

and:

HealthCareProject2.xlsx

This was likely an attempt to disguise the confidential files as legitimate project-related documents.

<img width="1548" height="835" alt="Jakie-Q10" src="https://github.com/user-attachments/assets/1a0e6a6f-1c8c-48a7-8815-0d0ef46d0a83" />

***Answer ==> HealthCareProject1.xls, HealthCareProject2.xlsx***
---

---

## Q11) A customer company's report was also downloaded by Jakie. Submit the filename.ext of the report.

To investigate additional downloaded documents related to the breach, I continued analyzing the `$UsnJrnl ($J)` entries.

Since the scenario mentioned a customer company report, I filtered for:

- PDF files (`.pdf`)
- Rename-related activity

During the analysis, I identified the following suspicious PDF document:

```text id="t5cx5q"
Care4Humans_HealthCare_AnnualExecutiveReport2021.pdf
```
This file matched the description of a sensitive customer report downloaded by Jakie.
***Answer ==> Care4Humans_HealthCare_AnnualExecutiveReport2021.pdf***
Q12) The file from the previous question was later renamed. What is the renamed filename?

Using the same $UsnJrnl ($J) analysis approach, I continued reviewing rename operations associated with the previously identified PDF document.

The investigation revealed that the report file was later renamed to:

HealthCareProject1.pdf

This appears to have been an attempt to disguise the sensitive report as a normal project-related file.

***Answer ==> HealthCareProject1.pdf***

Q13) Submit the MFT Entry number of the above report document which was deleted.

While reviewing the metadata associated with the renamed PDF file inside the parsed $MFT, I identified the corresponding MFT Entry Number tied to the deleted report document.

It is important to note that the question specifically refers to the actual document itself and not the associated .lnk shortcut file.

The Entry Number identified was:

114925

***Answer ==> 114925***

<img width="1550" height="838" alt="Jakie-Q11-Q12-Q13" src="https://github.com/user-attachments/assets/defdda98-9768-4a7f-8a37-1d0ac7db07cc" />

---
Q14) The report file was later wiped and overwritten. Submit the name of the file which overwritten the above report document.

Since the report document had been overwritten after deletion, I pivoted using the same MFT Entry Number identified in the previous question:

114925

Searching for entries associated with this MFT record revealed another file occupying the same entry.

The file identified was:

f_0000b8

This indicates that the original report file entry had been overwritten by this new file after wiping activity occurred.

<img width="1550" height="839" alt="Jakie-Q14" src="https://github.com/user-attachments/assets/e40f6956-2736-4b54-b512-eb1429110e45" />

****Answer ==> f_0000b8***
---
Q15) Submit the name of the portable OS downloaded to access illegal marketplaces with the intent to sell the acquired data.

Based on the scenario, it was clear the attacker intended to access dark web marketplaces.

One of the most commonly used privacy-focused operating systems for accessing the dark web is:

Tails OS

To investigate this further, I searched for operating system image extensions such as:

.img

During the analysis, I identified the following downloaded file:

tails-amd64-5.1.1.img

This confirmed the portable operating system downloaded by Jakie.

<img width="1547" height="838" alt="Jakie-Q15" src="https://github.com/user-attachments/assets/3b6759a0-6d0c-448f-805e-51a7f5e2c25d" />

***Answer ==> tails-amd64-5.1.1.img***
---

Q16) Jakie tried to install the above OS as a virtual machine. What is the name given to the VM?

To investigate the virtual machine activity, I searched for artifacts related to virtualization software.

During the analysis, I identified evidence indicating the use of:

VirtualBox

Since VirtualBox commonly uses:

.vdi

files to store virtual machine disks, I filtered for .vdi-related entries and associated VM artifacts.

This revealed the name assigned to the virtual machine:

heads4rtesting

<img width="1545" height="835" alt="Jakie-Q16" src="https://github.com/user-attachments/assets/e3f1cada-aa09-4165-a03a-d923632d7560" />

***Answer ==> heads4rtesting***
---

Q17) What is the name of the tool used to wipe the downloaded files?

To identify the wiping utility used by Jakie, I reviewed the $UsnJrnl ($J) entries and filtered for executable files (.exe) around the timeline of the incident.

During the analysis, I identified the execution of:

sdelete.exe

SDelete is a well-known Microsoft Sysinternals utility commonly used for:

Secure deletion
Data wiping
Preventing file recovery

This activity maps closely to:

MITRE ATT&CK T1070 - Indicator Removal on Host

where attackers or insiders attempt to remove forensic evidence from the system.

<img width="1550" height="839" alt="Jakie-Q17" src="https://github.com/user-attachments/assets/f26eead1-289b-43ef-b6b2-e24f3b044e6f" />

***Answer ==> sdelete.exe***
---
Q18) The person of interest copied the sensitive files to his USB drive. Submit DriveLetter:USBName

To investigate possible USB activity, I analyzed .lnk shortcut artifacts within the $UsnJrnl ($J) entries.

While reviewing the linked removable media activity, I identified the following USB device information:

E:jakieTheKing

This confirmed the drive letter and USB device name used to copy the sensitive files.

<img width="1552" height="840" alt="Jakie-Q18" src="https://github.com/user-attachments/assets/a3e44620-c1ca-49e4-ac14-bf41dbf81c75" />

***Answer ==> E:jakieTheKing***

---
Conclusion

This investigation demonstrated how NTFS forensic artifacts can provide strong evidence of insider threats and unauthorized handling of sensitive data, even after attempts to delete or wipe evidence.

By analyzing $MFT, $UsnJrnl, ADS entries, shortcut files, and filesystem metadata, I was able to reconstruct Jakie’s activity from downloading healthcare-related project files to renaming, wiping, and transferring confidential documents to external media.

The investigation also revealed attempts to cover tracks using secure deletion tools and preparations to use a privacy-focused operating system for illegal activity on the dark web.

Overall, this lab was an excellent example of how NTFS artifacts can expose file handling behavior, deletion attempts, USB usage, and insider data theft activity during forensic investigations.
---

<img width="886" height="821" alt="Jakie-Done" src="https://github.com/user-attachments/assets/cd702789-d334-43ce-b925-fa5ffddd4d17" />
