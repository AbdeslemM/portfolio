# 🚨 Take a LAP Investigation

---

## 🎯 Objective
Conduct a forensic investigation of a Windows Active Directory environment to identify unauthorized access, analyze user accounts, review security policies, and uncover actions performed by a disgruntled administrator.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** Take a LAP  
- **Environment:** Windows Active Directory  
- **Difficulty:** Medium  
- **OS:** Windows  
- **Category:** Digital Forensics  

---

## 📖 Scenario
The Track and Field Company recently implemented a new program to improve password rotation across their environment using Microsoft LAPS.  

However, one administrator, unhappy about not being selected to manage this system, began accessing information beyond his authorization.  

As part of the investigation, we must analyze the Active Directory environment to gather intelligence about users, organizational structure, security policies, and identify any suspicious or unauthorized activity carried out by this administrator.

---

## 🛠️ Tools Used
- FTK Imager  
- AD Explorer  

---

🔎 Investigation Overview
The investigation began by examining the provided forensic data to understand the system and Active Directory environment. The focus was on identifying domain structure, user configurations, and security policies.

The analysis then moved toward reviewing Group Policy Objects and password management mechanisms, particularly focusing on how local administrator passwords are handled. Special attention was given to identifying any misuse of privileges or unauthorized access performed by the disgruntled administrator.

---

## Lab Discovery

For this lab, we are provided with only one disk image to analyze:

`71289f71-0000-0000-0000-501f00000000.vhdx`

So the investigation will mainly focus on exploring this disk to gather system details and analyze the Active Directory environment.
<img width="1550" height="842" alt="Take-A-Lap-Discovery" src="https://github.com/user-attachments/assets/66a70817-c084-4ce5-a46e-dd72ea8e252a" />


## Investigation submission
Great, so the first thing I’m going to do is add the evidence item to FTK Imager to start analyzing it.

Then we start with the questions.

The first one is about the hostname. I usually go directly to the registry using this path:
`\Windows\System32\config\SYSTEM`

Normally, when using Registry Explorer, I would navigate to:
`ControlSet001\Control\ComputerName\ComputerName`

But this time, since we are only using FTK Imager, I used the normal search to find the hostname.

Using this method, I was able to get the hostname, and also the forest root domain name for Q2 from the same search, as shown below.

---

## Q1) What is the hostname of the machine?
**Answer ==> WIN-ALN64CF5HR5**

## Q2) What is the forest root domain name?
**Answer ==> lab.BTLO.com**
<img width="1560" height="854" alt="Take-A-Lap-Q1-Q2" src="https://github.com/user-attachments/assets/65412692-51db-49ea-9937-4bcfc85717f5" />

Now to move to Q3, I think we are going to need to use AD Explorer to get some information.

While navigating on the Desktop of the Administrator, I found a snapshot of Active Directory that we need to export first:
`ActiveDirectoryBackup_DONOTDELETE.dat`

This is the file we are going to use with AD Explorer, so we load it into the tool.

After loading it, we can explore the Active Directory structure, and we find the Organizational Units as shown below.

---

## Q3) Name all the non-default Organizational Units (OUs) that a domain administrator created. List the OUs in alphabetical order

**Answer ==> Administrators, Employees, Servers, Workstations**
<img width="1560" height="782" alt="Take-A-Lap-Q3" src="https://github.com/user-attachments/assets/10bd22eb-1f0e-4f22-9862-ca3871891e09" />

---

## Q4) Which Active Directory attribute contains a range of flags to define the properties of a user object?

For Q4, I had to do some research. Based on the articles I read, the attribute that defines these properties is:

**Answer ==> userAccountControl**
<img width="916" height="458" alt="Take-A-Lap-Q4" src="https://github.com/user-attachments/assets/3b5ccefc-edba-47bd-be96-32477e676e55" />


---

## Q5 – Password Never Expires

To identify which user has their password set to never expire, I examined the `userAccountControl` attribute within the Active Directory database (`ntds.dit`)/

The `userAccountControl` attribute is a bitmask that stores multiple account properties as flags. One of these flags is:

0x10000 → Password never expires

I located the following entry:

Kyla Cornell → userAccountControl = 66048

Converting the value to hexadecimal:

66048 = 0x10200

This value includes the 0x10000 flag, confirming that the password is set to never expire.

**Answer:  
Kyla Cornell, 0x10200**
<img width="1560" height="546" alt="Take-A-Lap-Q5" src="https://github.com/user-attachments/assets/986fecc3-b120-40ac-bfe8-7c93f9ad405b" />

---

## Q6 – Account Disabled

To determine which user account is disabled, I again analyzed the `userAccountControl` attribute.

The relevant flag is:

0x0002 → Account disabled

I found the following entry:

Regina Kirk → userAccountControl = 514

Converting to hexadecimal:

514 = 0x202

This value contains the 0x0002 flag, indicating that the account is disabled.

**Answer:  
Regina Kirk, 0x202**
<img width="1560" height="551" alt="Take-A-Lap-Q6" src="https://github.com/user-attachments/assets/0c0c3b99-463b-4d55-bc4a-e383687576bf" />

---

## Q7) What is the Common Name of the user whose username does not match the convention firstname.lastname?

For Q7, it is much easier. We just need to compare the given naming convention with the employee account names (or User Principal Names).

The only account that does not match the convention is **roy.nix**, which corresponds to the user:

**Answer ==> Royce Nixon**
<img width="1562" height="552" alt="Take-A-Lap-Q7" src="https://github.com/user-attachments/assets/03143f0c-20d2-4f74-8b09-691c756679e0" />

## Q8) What are the Display Names of the two Group Policy Objects (GPOs) that were created by a domain administrator?

Now for Q8, I had to look into system policies to identify the GPOs.

Under those GUIDs, there are actually four GPOs, but the question does not ask for the default ones that are already set. It asks for the ones created by the administrator.

These are the four GPOs:
LAPSSettings, PasswordEnforcement, Default Domain Policy, Default Domain Controller Policy

This means the two relevant ones are:

CN={099039F7-F8A8-4290-B3D2-ACDA4DAFEA44} → LAPSSettings  
CN={B5C53324-3ABD-472F-934F-0CD0C635452F} → PasswordEnforcement  

**Answer ==> LAPSSettings, PasswordEnforcement**
<img width="1563" height="852" alt="Take-A-Lap-Q8" src="https://github.com/user-attachments/assets/56733feb-c7ac-4652-99b3-543775c77c20" />
<img width="1560" height="852" alt="Take-A-Lap-Q8-1" src="https://github.com/user-attachments/assets/5e8b6790-607a-49d8-8ab6-b92fb2148f54" />
---

## Q9) What are the names of the policy settings being enabled in the first GPO?

For Q9, we need to locate the report GPO file of the first one, **LAPSSettings**.

Under the user `kibeth.admin` on the Desktop, I found a file that contains most of the information about this GPO, as shown below:

`kibeth.admin\Desktop\{C7C87C1D-5529-495A-BD5A-1C86E435BC4B}`

From this report file, we can identify the enabled policy settings.

**Answer ==> Enable local admin password management, Name of administrator account to manage, Password Settings**
<img width="1566" height="856" alt="Take-A-Lap-Q9" src="https://github.com/user-attachments/assets/8654c55c-79f9-4812-bc12-1279d7014546" />

---

## Q10) What are the Maximum Password Age, Minimum Password Age, Minimum Password Length, and Password History Size in the second GPO?

For Q10, I explored the following path:

`{8F50E244-ED60-40CF-8B4B-C1A05E51D4D0}\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit`

In this path, I found a file called `GptTmpl.inf`, which contains the password policy settings:

- MinimumPasswordAge = 37  
- MaximumPasswordAge = 71  
- MinimumPasswordLength = 14  
- PasswordHistorySize = 12  

**Answer ==> 71, 37, 14, 12**
<img width="1563" height="503" alt="Take-A-Lap-Q10" src="https://github.com/user-attachments/assets/0633401c-4990-41c9-b6b4-e3cfc91647ca" />
---

## Q11) What is the name of the Microsoft program that allows for regular rotation of local administrator passwords?

For Q11, this requires basic knowledge of Active Directory. The Microsoft program used for managing and rotating local administrator passwords is:

**Answer ==> LAPS**
---

## Q12) What is the name of the Allowed Principals whose members are allowed to view the passwords from the previous question?

For Q12, I found the answer by looking at the Active Directory snapshot under the Users container.

The most obvious group was **LAPSViewers**, which is responsible for viewing the local administrator passwords.

I also noticed that one administrator was not part of this group, which leads to the next question.

Here is what I found:

Object: CN=LAPSViewers,CN=Users,DC=lab,DC=BTLO,DC=com  
Members:  
CN=Boring Admin,OU=Administrators,DC=lab,DC=BTLO,DC=com  
CN=Kibeth TheAdmin,OU=Administrators,DC=lab,DC=BTLO,DC=com  

To Confirm i had to Look on PowerShell command history and I found that LAPSViewers principals are allowed to view LAPS passwords from "Workstations" and "Servers"

**Answer ==> LAPSViewers**

<img width="1563" height="855" alt="Take-A-Lap-Q12-Q13" src="https://github.com/user-attachments/assets/8f35ebad-ee72-42ec-a079-2f03575d15f0" />
<img width="1550" height="842" alt="Take-A-Lap-Q12-R" src="https://github.com/user-attachments/assets/68129190-1d43-41ce-ac9f-bfcb0a27551c" />

---

## Q13) What is the Common Name of the administrator who is not in the group from the previous question?

From the previous findings, the administrator who is not part of the **LAPSViewers** group is:

**Answer ==> William Turnstiles**

---

## Q14) What account and group did the administrator from the previous question determine are the Extended Rights Holders for the Workstations OU?

For Q14, I needed to dig deeper into what the user William had accessed.

In the following path:
`william.turnstiles\AppData\Local\Microsoft\Windows`

I found a file called `runninglaps.txt`, which contains the information needed to answer this question:

ObjectDN                                      ExtendedRightHolders  
--------                                      --------------------  
OU=Workstations,DC=lab,DC=BTLO,DC=com         {NT AUTHORITY\SYSTEM, LAB\Domain Admins, LAB\LAPSViewers}  

**Answer ==> NT AUTHORITY\SYSTEM, LAB\Domain Admins, LAB\LAPSViewers**
<img width="1564" height="855" alt="Take-A-Lap-Q14" src="https://github.com/user-attachments/assets/f942473c-9a9f-4043-959d-86256efdee84" />

---

## Q15) What are the local administrator passwords for the company’s workstations?

For Q15, I needed to look at the Active Directory snapshot and identify which objects represent workstations.

I found two workstations:

Object: CN=ADMIN-WORKSTATION,OU=Workstations,DC=lab,DC=BTLO,DC=com  
Attribute: ms-Mcs-AdmPwd  
Value: -Tn*N}Q&%/_a#>L  

Object: CN=WORKSTATION1,OU=Workstations,DC=lab,DC=BTLO,DC=com  
Attribute: ms-Mcs-AdmPwd  
Value: DxTX.@)D[):w-#$  

**Answer ==> -Tn*N}Q&%/_a#>L, DxTX.@)D[):w-#$**
<img width="1564" height="854" alt="Take-A-Lap-Q15" src="https://github.com/user-attachments/assets/8f15c03c-fe16-4019-8559-0bf96583a0cf" />
<img width="1563" height="855" alt="Take-A-Lap-Q15-1" src="https://github.com/user-attachments/assets/6bbdc500-1358-44c5-8f8f-c3474223983b" />

---

## Q16) LAPS does not store a password’s expiration time in a normal date format. Looking at the company’s servers, what are the first six digits of the default timestamp LAPS uses to show when these local administrator passwords will expire?

For the last question, I looked at the Active Directory snapshot under the Servers OU.

I found two servers, so I focused on the first one:

Object: CN=SKYPE-SERVER,OU=Servers,DC=lab,DC=BTLO,DC=com  
Attribute: ms-Mcs-AdmPwdExpirationTime  
Value: 9/24/2024 12:38:57 PM  

The LAPS expiration time is stored in the `ms-Mcs-AdmPwdExpirationTime` attribute using the Windows FILETIME format, which represents the number of 100-nanosecond intervals since January 1, 1601 (UTC).

After identifying the expiration timestamp and converting it to FILETIME format, the resulting value started with **133716**. The first six digits were extracted as required.

**Answer ==> 133716**

Website used for conversion:  
https://toolbox.souus.com/filetime-ldap-timestamp-converter/

<img width="1564" height="855" alt="Take-A-Lap-Q16" src="https://github.com/user-attachments/assets/4ade256b-26ac-4f5d-9a64-6c7e402da8d7" />
<img width="1834" height="755" alt="Take-A-Lap-Q16-1" src="https://github.com/user-attachments/assets/9c736577-2e36-4b2c-b61a-7450217c8df5" />

## Conclusion

From this investigation, I was able to analyze the Active Directory environment and understand how the company manages its systems and security policies.

The analysis showed how LAPS is used to handle local administrator passwords, including who has access to them and how they are stored. I also identified accounts with misconfigurations, such as passwords that never expire and disabled users.

In addition, I tracked the actions of a disgruntled administrator who accessed sensitive information, including password data and extended rights within the environment.

This shows how important it is to properly control access and monitor user activity to prevent misuse of privileges.

<img width="877" height="841" alt="Take-A-Lap-Completion" src="https://github.com/user-attachments/assets/bd2f37f5-a50e-4414-9650-96ff7f7bda03" />
