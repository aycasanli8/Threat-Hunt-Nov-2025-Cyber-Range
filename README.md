# INCIDENT RESPONSE REPORT

**Date of Report:** 2025-11-23  

**Severity Level:** ☐ LOW  ☐ MEDIUM  ☒ HIGH  ☐ CRITICAL  

**Report Status:** ☐ Open  ☒ Contained  ☐ Eradicated  

**Escalated To:** [Pending / Security Team]  

**Incident ID:** INC-2025-XXXX  

**Analyst:** Ayca Sanli  

---

## SUMMARY OF FINDINGS

- Unauthorized RDP access to AZUKI-SL using stolen credentials.  
- Multi-stage intrusion: defense evasion, credential harvesting, persistence, data exfiltration.  
- Backdoor account `support` created and event logs cleared.  
- Data exfiltrated via Discord using `curl.exe`.  
- Attempted lateral movement to 10.1.0.188.  

---

## WHO, WHAT, WHEN, WHERE, WHY, HOW

### WHO

**Attacker:**  

- Initial Access IP: 88.97.178.12  
- C2 Server IP: 78.141.196.6  

**Compromised:**  

- Account: kenji.sato  
- System: AZUKI-SL  

---

### WHAT

1. Attacker logged in via RDP using stolen credentials.  
2. Executed malicious PowerShell scripts (`wupdate.ps1`) to deploy payloads.  
3. Created hidden malware staging directory and added Defender exclusions.  
4. Downloaded and executed `mm.exe` for credential harvesting.  
5. Compressed data into `export-data.zip` and exfiltrated via Discord.  
6. Created persistent backdoor account `support`.  
7. Cleared Security, System, and Application logs.  
8. Attempted lateral movement to 10.1.0.188.  

---

### WHEN

| Date/Time | Event |
| --- | --- |
| Nov 19, 2025 11:33:00 AM | RDP session initiated |
| Nov 19, 2025 11:37:40 AM | `wupdate.ps1` downloaded & executed |
| Nov 19, 2025 11:46:12 AM | `wupdate.bat` downloaded |
| Nov 19, 2025 11:49:05 AM | Temporary folder & hidden cache created; Defender exclusions added |
| Nov 19, 2025 12:03:21 PM | Malicious script run |
| Nov 19, 2025 12:07:04 PM | `mm.exe` executed for credential harvesting |
| Nov 19, 2025 12:07:35 PM | Scheduled task `Windows Update Check` created |
| Nov 19, 2025 12:08:11 PM | Collected data compressed (`export-data.zip`) |
| Nov 19, 2025 12:09:02 PM | Data exfiltrated via Discord |
| Nov 19, 2025 12:09:42 PM | Backdoor user `support` created |
| Nov 19, 2025 12:10:17 PM | Lateral movement attempted to 10.1.0.188 |
| Nov 19, 2025 12:11:05 PM | Logs cleared & C2 communication initiated |
| Nov 19, 2025 12:45:00 PM | Defender manifest installation completed |

---

### WHERE

**Compromised:** AZUKI-SL  

**Infrastructure:**  

- Attacker IP: 88.97.178.12  
- C2 Server: 78.141.196.6  

**Malware locations:**  

- `C:\ProgramData\WindowsCache\svchost.exe`  
- `C:\ProgramData\WindowsCache\mm.exe`  
- `C:\ProgramData\WindowsCache\export-data.zip`  

---

### WHY

**Root Cause:**  

- Stolen credentials used due to insufficient password security and lack of MFA.  

**Attacker Objective:**  

- Credential theft, data exfiltration, persistence, and lateral movement within network.  

---

### HOW

1. Initial Access via RDP.  
2. PowerShell script execution for payload deployment.  
3. Malware staging & defense evasion (hidden folders, Defender exclusions).  
4. Credential harvesting using Mimikatz variant (`mm.exe`).  
5. Data collected, compressed, and exfiltrated via Discord webhook.  
6. Persistence established with scheduled task and backdoor user.  
7. Anti-forensics by clearing Windows event logs.  
8. Attempted lateral movement to internal host.  

---

## IMPACT ASSESSMENT

**Actual Impact:**  

- High risk of sensitive data exposure.  
- Compromise of user credentials and potential lateral movement.  

**Risk Level:** HIGH  

---

## RECOMMENDATIONS

### IMMEDIATE

- Reset all credentials for affected and adjacent accounts.  
- Remove persistence mechanisms (scheduled tasks, malware files).  
- Block malicious IPs and Discord webhook endpoints at firewall.  

### SHORT-TERM (1-30 Days)

- Domain-wide password reset and credential hygiene.  
- Deploy enhanced endpoint monitoring & EDR alerting rules.  
- Perform network sweep for similar artifacts on lateral targets.  

### LONG-TERM

- Enforce MFA for all remote access including RDP.  
- Implement Zero Trust network segmentation to reduce lateral movement.  
- Harden endpoints: remove admin rights, enforce Defender policies.  

---

## APPENDIX

### A. Indicators of Compromise

| Category | Indicator | Description |
| --- | --- | --- |
| Attacker IP | 88.97.178.12 | Initial RDP source |
| C2 Server | 78.141.196.6 | Command & Control server |
| Malicious Files | `wupdate.ps1`, `mm.exe`, `export-data.zip` | Execution, credential theft, data exfiltration |
| Accounts | kenji.sato, support | Compromised & persistent accounts |
| Domain | discord.com | Exfiltration channel |

---

### B. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
| --- | --- | --- | --- |
| Initial Access | Valid Accounts | T1078 | RDP login using stolen credentials |
| Execution | PowerShell | T1059.001 | `wupdate.ps1` |
| Persistence | Scheduled Task | T1053.005 | `Windows Update Check` |
| Defense Evasion | Impair Defenses | T1562 | Hidden folder, Defender exclusions |
| Credential Access | LSASS Memory | T1003.001 | `mm.exe`, `sekurlsa::logonpasswords` |
| Lateral Movement | Remote Services: RDP | T1021.001 | `mstsc.exe` to 10.1.0.188 |
| Collection | Archive Collected Data | T1560 | `export-data.zip` |
| Command & Control | Application Layer Protocol: Web | T1071.001 | `svchost.exe` → 78.141.196.6:443 |
| Exfiltration | Exfiltration Over Web Service | T1567.002 | Discord webhook |
| Impact | Stored Data Manipulation | T1565.002 | Cleared Security logs |

---

### C. Investigation Timeline

| Time | Event | Details |
| --- | --- | --- |
| Nov 19, 2025 11:33:00 AM | RDP session initiated | mstsc.exe |
| Nov 19, 2025 11:37:40 AM | wupdate.ps1 downloaded & executed | PowerShell logs |
| Nov 19, 2025 11:46:12 AM | wupdate.bat downloaded | PowerShell logs |
| Nov 19, 2025 11:49:05 AM | Hidden cache created, Defender exclusions | Registry & File events |
| Nov 19, 2025 12:03:21 PM | Malicious script run | ProcessCommandLine |
| Nov 19, 2025 12:07:04 PM | Credential harvesting started | mm.exe |
| Nov 19, 2025 12:07:35 PM | Scheduled task created | `Windows Update Check` |
| Nov 19, 2025 12:08:11 PM | Data compressed | export-data.zip |
| Nov 19, 2025 12:09:02 PM | Data exfiltrated | Discord webhook via curl.exe |
| Nov 19, 2025 12:09:42 PM | Backdoor account created | net.exe |
| Nov 19, 2025 12:10:17 PM | Lateral movement attempted | mstsc.exe & cmdkey.exe |
| Nov 19, 2025 12:11:05 PM | Logs cleared & C2 communication | wevtutil.exe & network logs |
| Nov 19, 2025 12:45:00 PM | Defender manifest installation completed | wevtutil.exe |

---

### D. Evidence & Screenshots

- All screenshots attached with each query/flag.  
- Full query results attached.  
- Network logs reviewed.  
- File hashes documented where available.  

---

## E. Investigation Queries

---

### Query 1 - INITIAL ACCESS - Remote Access Source
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where isnotempty(RemoteIP) 
| where ActionType in ("RemoteInteractiveLogon", "LogonSuccess")
| project Timestamp, LogonType, AccountName, RemoteIP, ActionType, DeviceName
```
Results: **88.97.178.12**

<img width="1055" height="312" alt="Flag 1-2" src="https://github.com/user-attachments/assets/e80949ee-6417-4149-8619-5d679f2bae67" />

### Query 2 - INITIAL ACCESS - Compromised User Account
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where isnotempty(RemoteIP) 
| where ActionType in ("RemoteInteractiveLogon", "LogonSuccess")
| project Timestamp, LogonType, AccountName, RemoteIP, ActionType, DeviceName
```
Results: **kenji.sato**

<img width="1055" height="312" alt="Flag 1-2" src="https://github.com/user-attachments/assets/0610883a-2fbe-4abe-a5a7-5f873a9e3a90" />


### Query 3 - DISCOVERY - Network Reconnaissance
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("arp", "net view", "ipconfig", "route print", "nbtstat")
| project Timestamp, AccountName, ProcessCommandLine, FileName, DeviceName
| order by Timestamp asc

```
Results: **ARP.EXE -a**

<img width="898" height="240" alt="Flag 3" src="https://github.com/user-attachments/assets/f70061c4-0504-41cc-8d0e-5de39ba12114" />


### Query 4 - DEFENCE EVASION - Malware Staging Directory
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "attrib"
| project Timestamp, AccountName, FileName, ProcessCommandLine, DeviceName
| order by Timestamp asc

```
Results: **C:\ProgramData\WindowsCache**

<img width="1083" height="209" alt="Flag 4" src="https://github.com/user-attachments/assets/24bf5e0a-964a-4bc7-97ea-a3ed3f85733b" />


### Query 5 - DEFENCE EVASION - File Extension Exclusions 
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey has @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
| summarize UniqueExtensions = dcount(RegistryValueName)

```
Results: **3**

<img width="880" height="247" alt="Flag 5" src="https://github.com/user-attachments/assets/eca43ca1-d307-4bc5-8060-730cf154c98c" />


### Query 6 - DEFENCE EVASION - Temporary Folder Exclusion 
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey has @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
| project Timestamp, RegistryValueName, RegistryKey, DeviceName
| order by Timestamp asc

```
Results: **C:\Users\KENJI~1.SAT\AppData\Local\Temp**

<img width="1165" height="258" alt="Flag 6" src="https://github.com/user-attachments/assets/2ba425a9-014a-4591-98a3-64ad8350014a" />

### Query 7 - DEFENCE EVASION - Download Utility Abuse
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, FileName, ProcessCommandLine, AccountName, DeviceName
| order by Timestamp asc

```
Results: **certutil.exe**

<img width="1148" height="488" alt="Flag 7" src="https://github.com/user-attachments/assets/dd8704db-efe4-413d-853e-4e0af10e238f" />

### Query 8 - PERSISTENCE - Scheduled Task Name
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

```
Results: **Windows Update Check**

<img width="1167" height="227" alt="Flag 8" src="https://github.com/user-attachments/assets/7c4f1827-b348-46a7-b817-a5ae182f4229" />

### Query 9 - PERSISTENCE - Scheduled Task Target
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

```
Results: **C:\ProgramData\WindowsCache\svchost.exe**

<img width="1177" height="226" alt="Flag 9" src="https://github.com/user-attachments/assets/3fe2814d-ca98-40c7-8d2a-69762359248c" />

### Query 10 - COMMAND & CONTROL - C2 Server Address
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessFolderPath contains "ProgramData\\WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp asc

```
Results: **78.141.196.6**

<img width="1076" height="224" alt="Flag 10-11" src="https://github.com/user-attachments/assets/42b1eaf5-b11b-4954-8d12-ea766764593d" />

### Query 11 - COMMAND & CONTROL - C2 Communication Port
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessFolderPath contains "ProgramData\\WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp asc

```
Results: **443**

<img width="1076" height="224" alt="Flag 10-11" src="https://github.com/user-attachments/assets/886b3135-ac60-451f-a22e-abf3e2274dd6" />

### Query 12 - CREDENTIAL ACCESS - Credential Theft Tool 
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FolderPath startswith "C:\\ProgramData\\WindowsCache"
| where FileName endswith ".exe"
| project Timestamp, FileName, FolderPath, ActionType, DeviceName
| order by Timestamp asc

```
Results: **mm.exe**

<img width="1021" height="251" alt="Flag 12" src="https://github.com/user-attachments/assets/aaabf486-98e9-4a1d-9ea2-f293fea06921" />

### Query 13 - CREDENTIAL ACCESS - Memory Extraction Module
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName =~ "mm.exe" or ProcessCommandLine contains "mm.exe"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc 

```
Results: **sekurlsa::logonpasswords**

<img width="1199" height="256" alt="Flag 13" src="https://github.com/user-attachments/assets/f9750a1e-ffb1-4c0e-9d90-9ff8b87c9774" />

### Query 14 - COLLECTION - Data Staging Archive
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FolderPath contains "C:\\ProgramData\\WindowsCache"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, ActionType, DeviceName
| order by Timestamp asc
```
Results: **export-data.zip**

<img width="1121" height="216" alt="Flag 14" src="https://github.com/user-attachments/assets/6002bc03-516a-4937-9d8e-b4a8586db916" />

### Query 15 - EXFILTRATION - Exfiltration Channel
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName =~ "curl.exe"
| project Timestamp, FileName, ProcessCommandLine

```
Results: **Discord**

<img width="1272" height="224" alt="Flag 15" src="https://github.com/user-attachments/assets/40e2ec9d-814b-4b12-b234-f2d7f113e978" />


### Query 16 - ANTI-FORENSICS - Log Tampering 
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "wevtutil"
| where ProcessCommandLine contains "cl"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

```
Results: **Security**

<img width="1184" height="339" alt="Flag 16" src="https://github.com/user-attachments/assets/48abd76b-d49c-418c-bd73-6a7261f9c441" />

### Query 17 -  IMPACT - Persistence Account 
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "net.exe"
| where ProcessCommandLine contains "user"
| where ProcessCommandLine contains "/add"
| project Timestamp, AccountName, ProcessCommandLine
| order by Timestamp asc

```
Results: **support**

<img width="799" height="210" alt="Flag 17" src="https://github.com/user-attachments/assets/f5bd7632-ff1e-480f-9e58-d65c941b423f" />

### Query 18 - EXECUTION - Malicious Script
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where FileName == "powershell.exe"
| where ProcessCommandLine has ".ps1"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

```
Results: **wupdate.ps1**

<img width="1293" height="330" alt="Flag 18" src="https://github.com/user-attachments/assets/cfa22d24-56b9-408a-9713-e4c43cb17530" />

### Query 19 - LATERAL MOVEMENT - Secondary Targe
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc"
| project Timestamp, ProcessCommandLine

```
Results: **10.1.0.188**

<img width="887" height="303" alt="Flag 19" src="https://github.com/user-attachments/assets/5d1f6b68-107a-477e-9c5f-7993b669da58" />

### Query 20 - LATERAL MOVEMENT - Remote Access Tool
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc"
| project Timestamp, ProcessCommandLine

```
Results: **mstsc.exe**

<img width="1010" height="304" alt="Flag 20" src="https://github.com/user-attachments/assets/c52bced6-dc70-4f02-83cc-e8cf8ea7a819" />

## E. Supporting Evidence

- ☒ All screenshots attached  
- ☒ Full query results attached  
- ☒ Network logs reviewed  
- ☒ File hashes documented  

---

**Report Completed By:** Ayca Sanli  
**Date:** 23-Nov-2025  
**Reviewed By:** 



