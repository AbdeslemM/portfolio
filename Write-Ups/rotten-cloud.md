# 🚨 Rotten Cloud Investigation

## 🎯 Objective
Investigate Zeta-9’s hybrid cloud environment using Splunk to determine whether a threat actor has pivoted into the infrastructure.

## 🧾 Lab Details
- Platform: Blue Team Labs Online (BTLO)
- Event: Trick or Threat 2025
- Environment: Splunk Cloud
- Difficulty: Medium
- OS: Linux
## Category: INCIDENT RESPONSE
---
## 📖 Scenario
Zeta-9 Corporation operates a hybrid cloud infrastructure supporting its Quantum Research Division, where highly sensitive data is stored across secure cloud environments. Authorized personnel access this data through a web-based research portal that serves as the primary interface for ongoing projects. Following the breach, C.R.I.S.I.S must extend their investigation into Zeta-9’s cloud environment — analyzing activity, identifying signs of lateral movement, and determining whether the threat actor has already pivoted into the cloud infrastructure. Time is critical; stopping them before they move deeper into the network may be the only way to contain the damage.
---

## 🛠️ Tools Used
- Splunk
- CyberChef
---

## 🔎 Investigation Overview
The investigation began by analyzing AWS CloudTrail logs within the Splunk environment to identify any suspicious activity. The goal was to trace the attacker's actions from initial access through potential lateral movement within the cloud infrastructure.

The analysis focused on identifying anomalous IP addresses, unusual API calls, access to sensitive resources, and any indicators of cross-cloud activity. By correlating multiple log sources, it was possible to reconstruct the attacker’s behavior and determine the extent of the compromise.


## Lab Discovery
So we first start to login into Splunk to start Our investigation, With indexing all we are provided with 4028 events Only which is not too much and make our investigation less harder that we can focus better while we dont see so noise events in this part.
seeing multiple host and source can probably reveal multiple Cloud enviremont (AWS, AZure..).
<img width="1888" height="599" alt="Lab discovery" src="https://github.com/user-attachments/assets/95714660-a6f7-48fb-8617-939d831aed0b" />



## Investigation submission
Q1) Analyze the AWS CloudTrail logs and identify the attacker's IP address. Note that legitimate users were working remotely from India
I started by analyzing the AWS CloudTrail logs to identify the attacker’s IP address. Since the lab mentioned that legitimate users were working remotely from India, I focused on any source IPs that did not match that pattern.

To do this, I used the following Splunk query:

`index=* source="AWSCloudTrail.json" | sort _time`

While reviewing the `sourceIPAddress` field, I found two values. One appeared to be a domain name, and the other was an IP address, which looked like the attacker’s source IP. I then checked this IP with OSINT to confirm whether it was suspicious.

<img width="1888" height="599" alt="FindingAIPQ1" src="https://github.com/user-attachments/assets/daa5ce95-8155-4b3c-ab46-2c4b8a8d6a6f" />

After checking the location, it was clear that this IP did not match the expected behavior of legitimate users, since they were working remotely from India and this IP was coming from the USA.


<img width="1888" height="599" alt="OSINTonIP" src="https://github.com/user-attachments/assets/6e17ed7c-5271-41ec-8f98-41d95f96232b" />




**Answer ==> 172.235.129.221**



## Q2) The attacker performed reconnaissance on EC2 instances. What specific API call/EventName was generated during this reconnaissance activity? 

Now that we have the attacker’s IP, we need to use this filter:

`index=* source="AWSCloudTrail.json" sourceIPAddress="172.235.129.221" | sort _time`

While sorting this, there were actually three events/AWS API calls. Among those API calls, only one corresponded to the first phase, which was reconnaissance: **DescribeInstances**
<img width="1888" height="599" alt="Q2related" src="https://github.com/user-attachments/assets/9457fcbb-0b13-4fce-930d-04a11699b88d" />
<img width="1906" height="614" alt="AWsApiCallQ2" src="https://github.com/user-attachments/assets/616612dc-779e-49a8-9745-d6d76e43eaa2" />



**Answer ==> DescribeInstances**

## Q3) After gathering information about EC2 instances, the attacker attempted to find instance passwords to establish connections. Identify the secretID that contained the Windows instance password 

The second event name is **GetSecretValue**, which is used to retrieve stored secrets like credentials — highly sensitive.
<img width="1888" height="599" alt="SecretID-Q3" src="https://github.com/user-attachments/assets/af937955-4187-4ede-822c-18df17640f13" />

**Answer ==> zeta9/windows/admin-password**


## Q4) The attacker discovered and targeted S3 buckets to download sensitive data. Find how many unique S3 buckets were targeted as well as the total files that were downloaded from all buckets.


Now we need to look at the third and last event name, which is **GetObject** (S3). We specifically need to use this query to get the correct number of unique S3 buckets and the total downloaded files from those buckets:

`index=* source="AWSCloudTrail.json" sourceIPAddress="172.235.129.221" eventName=GetObject | sort _time | table eventTime,requestParameters.bucketName,requestParameters.key`
<img width="1900" height="418" alt="BucketsAndFilesQ4" src="https://github.com/user-attachments/assets/3aefaab3-841e-44b3-b65e-ad218ece667c" />


**Answer ==> 3, 5**


## Q5) Through analysis of the compromised EC2 instance's browsing history, the attacker found traces leading to a secret web portal used by restricted individuals. Using cross-correlation with other log sources, identify the URL of this secret portal. 

The first thing that came to my mind after knowing we needed the URL for this one was that it would be better to switch and look at HTTP logs using this filter:

`index=* sourcetype=AppServiceHTTPLogs | sort _time`

The first event in Splunk clearly shows a URL.
<img width="1282" height="598" alt="URLQ5" src="https://github.com/user-attachments/assets/3dacbd1b-a98e-4f8b-a7a6-bd125ef0d1f8" />


**Answer ==> zeta9-research-portal.azurewebsites.net**



## Q6) The attacker pivoted to another cloud environment by exploiting a vulnerability. Provide the complete command used for this cross-cloud activity (6 points)

Using those HTTP logs, we got multiple events, so we needed to use the attacker’s IP to reduce the number of events and get a better look at the command.

Filter: `index=* sourcetype=AppServiceHTTPLogs CIp="172.235.129.221" | sort _time`
<img width="1630" height="548" alt="Command" src="https://github.com/user-attachments/assets/8088b9eb-9957-40c3-af92-b94d846bb27f" />

We found a suspicious command, but first we needed to decode it using CyberChef URL decode, and then we got the exact command used.
<img width="1528" height="430" alt="decodedCommandQ6" src="https://github.com/user-attachments/assets/36f04b66-df9a-4ea7-91b9-dcb931030614" />

**Answer ==> curl -H secret:4ebc6d54-f421-4321-81c4-fd9e29d28a0f 'http://169.254.130.3:8081/msi/token?api-version=2017-09-01&resource=https://management.azure.com/'**


## Q7) After gaining access to the Azure environment, the attacker was able to list and access data from cloud storage services. Identify the name of the specific storage blob container that was targeted. (6 points)

The last step here was to look at the storage blob logs. We could filter them this way to help us identify the name of the container:

`index=* sourcetype=StorageBlobLogs "172.235.129.221" | sort _time`

We found three operation names: **GetBlob**, **ListBlob**, and **ListContainers**. For this one, we needed to filter it further, and then we were able to identify the blob name.
<img width="1633" height="529" alt="BlobNQ7" src="https://github.com/user-attachments/assets/f0dc5a8e-9f88-41b5-9fc4-6580dcd44743" />
**Answer ==> quantum-research-secrets**


## Q8) Determine how many files the attacker successfully downloaded from the Azure blob storage during the attack. (6 points)

Now we need to look at the second operation, **GetBlob**, to get the number of files downloaded by the threat actor from Azure blob storage. We need to set this filter so it will be clear for us to get the exact number of files:

`index=* sourcetype=StorageBlobLogs "172.235.129.221" OperationName=GetBlob | sort _time | table ObjectKey, "TimeGenerated [UTC]"`
<img width="1900" height="455" alt="downloadedFilesQ8" src="https://github.com/user-attachments/assets/beac98c8-e068-49f6-aaa6-603e50e622ce" />
**Answer ==> 6**


## Q9) To gain access to the secret division systems, the attacker defaced the organization's website by deploying malicious content. Provide the URL that hosted the defaced website code. (6 points)

Here is another URL to find, so let’s go back to HTTP logs for the last part of this investigation. After using multiple commands by the attacker, like `ls -la` and `whoami`, the last command the attacker used showed the defaced website used to deploy the malicious content.
<img width="1914" height="618" alt="defacedURLQ9" src="https://github.com/user-attachments/assets/49b4a3d8-2380-429e-b353-c3a2a80e6581" />

**Answer ==> https://pastebin.com/raw/sBEs83q3**


## ✅ Conclusion

From this investigation, it is clear that the attacker successfully gained access to the cloud environment and performed multiple actions, including reconnaissance, credential access, and data exfiltration.

The attacker first identified EC2 instances, then retrieved sensitive credentials, and accessed S3 buckets to download data. After that, they pivoted into the Azure environment, where they continued accessing storage and downloading additional files.

Finally, the attacker defaced the organization’s website, showing that they were able to impact both internal systems and public-facing services.

This investigation highlights the importance of monitoring cloud activity and detecting suspicious behavior early to prevent further compromise.

<img width="849" height="656" alt="RottenCloudIR" src="https://github.com/user-attachments/assets/875c7a80-3184-4cc0-ab30-32ca4158c75c" />




