## **🕵️‍♂️ Threat Hunt Report – “The Great Admin Heist”**

![anthony](https://github.com/user-attachments/assets/bfb9d1cb-fd24-4dc1-a591-388dfc036240)

## **Cyber Threat Hunt Incident Response Report**


## **📚 Table of Contents**

1. 🧭 Executive Summary


2. 🧠 Threat Actor Overview


3. 🔍 Investigation Details


4. 🛠️ Response Actions


5. 🛡️ MITRE ATT&CK Mapping


6. 📎 Appendix
_____

## **1. 🧭 Executive Summary**

Summary:
Acme Corp detected suspicious activity on a privileged account—Bubba Rockerfetherman III—which was later attributed to a targeted campaign by an APT group known as The Phantom Hackers. The group attempted to gain persistence, exfiltrate sensitive assets, and use lateral movement to escalate environmental access. Through rapid investigation, the security team identified the full kill chain and neutralized the threat.
Objective of Attack:
Exfiltrate highly sensitive assets by compromising the privileged account of Bubba Rockerfetherman III.
____

## **2. 🧠 Threat Actor Overview**

Group: The Phantom Hackers

Motivation: Financial and espionage

Tactics Used: 

Masquerading as legitimate AV software

Scheduled tasks for persistence

Registry modifications

Command line process injection
_____

## **3. 🔍 Investigation Details**

🚩 Flag 1 – Suspicious Executable Detection

🎯 Objective: Identify unknown antivirus binaries launched on anthony-001.
```
🧪 Query Used:
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where AccountName != "system"
| where FileName startswith "A" or FileName startswith "B" or FileName startswith "C"
| order by Timestamp desc
```
📂 Folder Path Identified:
C:\ProgramData\BitSentinelCore.exe
 
⚠️ Finding:
The binary BitSentinelCore.exe mimicked a legitimate antivirus tool. The presence of this file in ProgramData—rather than Program Files—is unusual for genuine AV products. This strongly suggests masquerading.
 
✅ Answer: BitSentinelCore.exe
_____

🚩 Flag 2 – Binary Written to Disk

🎯 Objective: Detect when and where the malicious binary was written.
```
🔍 Query Used:
let MainDevice = "anthony-001";
DeviceFileEvents
| where Timestamp > ago(30d)
| where DeviceName contains MainDevice
| where FileName has "BitSentinelCore.exe"
```

![image](https://github.com/user-attachments/assets/ac9ed2c8-4c80-4a3f-8e68-8bb230cb7b37)

🛠️ Observed Behavior:
 PowerShell.exe was used to invoke csc.exe (C# compiler), which dynamically compiled and executed the malicious payload.
 
📂 Initiating Path:
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
 
✅ Answer: csc.exe

_____

🚩 Flag 3 – Manual Execution

🎯 Objective: Confirm if execution was user-initiated.
```
👨‍💻 Query Used:
let MainDevice = "anthony-001";
DeviceProcessEvents
| where Timestamp >ago(30d)
| where DeviceName == MainDevice
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/5e8de9b9-534d-4098-966b-c314f009f43b)

👤 Finding:
 Execution was manually initiated by the user, confirming interaction with the fake AV binary.
 
✅ Answer: BitSentinelCore.exe
_____

🚩 Flag 4 – Suspicious File Creation in AppData

🎯 Objective: Identify possible data collection or keylogging activity.
```
📂 Query Used:
let MainDevice = "anthony-001";
DeviceFileEvents
| where Timestamp >= datetime(2025-05-07T02:03:20.3416235Z)
| where DeviceName contains MainDevice
| where InitiatingProcessAccountName != "system"
| where FolderPath contains "Roaming"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/eafa2c95-3eaf-4c07-8d04-ff74ce70c8d8)

📎 Finding:
 A suspicious .lnk file was placed in the AppData\Roaming directory, suggesting potential surveillance or keylogging behavior.
 
✅ Answer: systemreport.lnk
____

🚩 Flag 5 – Persistence via Registry Modification

🎯 Objective: Identify registry-based persistence.
```
🧬 Query Used:
let MainDevice = "anthony-001";
DeviceRegistryEvents
| where DeviceName contains MainDevice
| where InitiatingProcessAccountName != "system"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```
![image](https://github.com/user-attachments/assets/a9131a7c-461b-405e-b1e8-ef53fa202328)

🗝️ Registry Path:
 HKEY_CURRENT_USER\...\Run
 
⚠️ Finding:
 Persistence mechanism created via the Run key to auto-execute BitSentinelCore.exe on startup.
 
✅ Answer: HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
____

🚩 Flag 6 – Scheduled Task Creation

🎯 Objective: Detect additional persistence through task scheduling.
```
📆 Query Used:
let MainDevice = "anthony-001";
DeviceProcessEvents
| where Timestamp >= datetime(2025-05-07T02:02:14.6264638Z)
| where DeviceName contains MainDevice
| where InitiatingProcessAccountName == "4nth0ny!"
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/6ab20c5c-ae18-4955-8553-07443ac1f4a3)

📌 Finding:
 Scheduled task UpdateHealthTelemetry was created to repeatedly run the malicious payload.
 
✅ Answer: UpdateHealthTelemetry
____

🚩 Flag 7 – Kill Chain Summary

🎯 Objective: Understand end-to-end execution flow.

🔄 Chain Observed:
 BitSentinelCore.exe ➡️ cmd.exe ➡️ schtasks.exe
```
📌 Query: 
let MainDevice = "anthony-001";
DeviceProcessEvents
| where Timestamp >= datetime(2025-05-07T02:02:14.6264638Z)
| where DeviceName contains MainDevice
| where InitiatingProcessAccountName == "4nth0ny!"
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/3e429a7d-71dc-4661-8c0e-c1aa0a656e6b)

🧠 Finding:
 Attack used PowerShell + csc.exe for dynamic compilation, then used command execution and scheduled task creation to maintain persistence.
 
✅ Answer: Multi-stage execution chain
____

🚩 Flag 8 – Forensic Timeline

📅 Event

🕒 Timestamp

2025-05-07T02:00:36Z
Malicious executable (BitSentinelCore.exe) written to disk

2025-05-07T02:02:14Z
Binary execution initiated by Bubba

2025-05-07T02:02:14.9Z
Registry persistence established

2025-05-07T02:02:15Z
Scheduled task UpdateHealthTelemetry created

2025-05-07T02:03:20Z
Suspicious .lnk file dropped in AppData\Roaming

![image](https://github.com/user-attachments/assets/9e603446-8228-41fc-8679-004feebe0358)

```
🧪 Query Used:
let MainDevice = "anthony-001";
DeviceFileEvents
| where DeviceName contains MainDevice
| where InitiatingProcessAccountName != "system"
| order by Timestamp asc
```

✅ Answer: 2025-05-07T02:00:36Z
_____

## **5. 🛠️ Response**

*🎯 Goal: Mitigate confirmed threats and prevent further compromise.*

*🔧 Activity: Collaboration with the security team for containment, eradication, and recovery.*


*✅ Actions Taken:*

🛑 Isolated infected host anthony-001 from the network


🧽 Removed BitSentinelCore.exe and .lnk artifacts


🗝️ Deleted malicious registry entries and scheduled task


🧼 Performed full malware scan; cleared remaining threats


🔁 Initiated reimage of device for assurance


👤 Notified Bubba and conducted a user awareness briefing


📘 Logged TTPs for rule updates and threat hunting
____

## **6. 🛡️ MITRE ATT&CK Mapping**

*🚀 Initial Execution & Scripting*

* 🧪 T1059.001 – PowerShell

* 🛠️ T1127 – Trusted Developer Utilities (csc.exe)

* 👤 T1204.002 – User Execution: Malicious File

*🏗️ Persistence*

* 🪣 T1547.001 – Registry Run Keys

* 📅 T1053.005 – Scheduled Task

*🎭 Defense Evasion*

* 🎭 T1036.005 – Masquerading (AV product)

*🔍 Discovery & Collection*

* 🧷 T1005 – Data from Local System (.lnk files)

*🧬 Execution*

* 🧨 T1055 – Process Injection (via cmd.exe)

*🧹 Cleanup / Hiding*

* 🗑️ T1070.004 – File Deletion and Artifact Hiding
____

## **7. 📎 Appendix**

*📁 File Artifacts:*

* BitSentinelCore.exe

* systemreport.lnk

*🗝️ Registry Keys:*

* HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BitSentinelCore

*⏰ Scheduled Task:*

* UpdateHealthTelemetry

*🧑 User:*

* Bubba Rockerfetherman III

* Account: 4nth0ny! on host anthony-001

*🔎 Queries Used:*

* ✅ DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents

## **🔚 Conclusion**
This targeted attack leveraged social engineering, .NET utilities, and persistence mechanisms to infiltrate Acme Corp through a high-privileged user account. Prompt detection and coordinated incident response prevented data exfiltration and halted the APT group's efforts.
____________________________________________________________________________________


-Investigated by: MaryAnna Moore

