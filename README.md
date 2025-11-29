# Threat-Hunt-Nov-2025-Cyber-Range - INCIDENT RESPONSE REPORT
# INCIDENT RESPONSE REPORT

**Report ID:** INC-2025-XXXX  
**Analyst:** Ayca Sanli  
**Investigation Date:** 23-Nov-2025  
**Incident Date:** 19-Nov-2025  

---

## 🟦 Executive Summary

Between 19 November 2025 and 20 November 2025, the AZUKI-SL workstation was compromised through unauthorized Remote Desktop Protocol (RDP) access originating from the external IP `88.97.178.12` using the stolen credentials of `kenji.sato`. After gaining interactive access, the attacker executed a multi-stage intrusion involving defense evasion, credential harvesting, persistence establishment, data exfiltration, and attempted lateral movement toward another internal system.

The threat actor created a hidden malware staging directory, downloaded multiple malicious payloads, disabled Windows Defender scanning, deployed a scheduled task for persistence, and extracted credentials using `mm.exe` with `sekurlsa::logonpasswords`. Later, the attacker compressed collected data into `export-data.zip` and exfiltrated it via Discord. Attempts were made to move laterally using `mstsc.exe` toward `10.1.0.188`.

Based on the breadth of actions performed—including credential access, data theft, log tampering, and lateral movement—the impact severity of this incident is assessed as **High**, and the compromise has been fully contained following removal of persistence mechanisms and malicious artifacts.

**What Happened:**  

**Impact Level:** ☐ Low ☐ Medium ☒ High ☐ Critical  
**Status:** ☒ Contained ☐ Eradicated ☐ In Progress    

---

## INCIDENT DETAILS

### Timeline
- **First Malicious Activity:** 19-Nov-2025 11:30 UTC  
- **Last Observed Activity:** 19-Nov-2025 16:23 UTC  
- **Total Duration:** ~5 hours  

### Attack Overview
- **Initial Access Method:** RDP via stolen credentials  
- **Compromised Account:** kenji.sato  
- **Affected System:** AZUKI-SL  
- **Attacker IP Address:** 88.97.178.12  

### Attack Chain (What did the attacker do?)
- **Initial Access (TA0001):** Attacker logged in via RDP from `88.97.178.12` using stolen credentials of `kenji.sato`.  
- **Execution (TA0002):** Executed malicious PowerShell script `wupdate.ps1` to automate payload deployment.  
- **Persistence (TA0003):** Created a scheduled task named `Windows Update Check` pointing to `C:\ProgramData\WindowsCache\svchost.exe`.  
- **Defense Evasion (TA0005):** Created hidden directory `C:\ProgramData\WindowsCache`, added Defender exclusions (extensions & temp folder), and used `certutil.exe` for downloading payloads.  
- **Discovery (TA0007):** Executed `arp -a` for local network reconnaissance.  
- **Credential Access (TA0006):** Used `mm.exe` to run `sekurlsa::logonpasswords` for credential harvesting.  
- **Lateral Movement (TA0008):** Attempted RDP connection to `10.1.0.188` using `mstsc.exe` and `cmdkey`.  
- **Collection (TA0009):** Compressed stolen data into `export-data.zip`.  
- **Command & Control (TA0011):** Communicated with external server `78.141.196.6` over port 443.  
- **Exfiltration (TA0010):** Uploaded ZIP archive via Discord webhook using `curl.exe`.  
- **Impact (TA0040):** Created backdoor user `support` and cleared Security event logs.  

---

## KEY FINDINGS

**Primary IOCs:**

| Type            | Value                     | Description                         |
|-----------------|---------------------------|-------------------------------------|
| IP Address       | 88.97.178.12              | Attacker RDP source                  |
| IP Address       | 78.141.196.6              | Command & Control server             |
| File             | wupdate.ps1               | Malicious execution script           |
| File             | mm.exe                    | Credential theft tool                |
| File             | export-data.zip           | Collected data archive               |
| Account          | kenji.sato                | Compromised legitimate user          |
| Account          | support                   | Malicious persistence account        |
| Domain           | discord.com               | Exfiltration channel                 |
| Hash             | (mm.exe hash if available)| Credential dumper                    |

---

## RECOMMENDATIONS

### Immediate Actions (Do Now)
1. Reset all credentials for affected and adjacent accounts.  
2. Remove persistence mechanisms (scheduled tasks, malicious files).  
3. Block malicious IPs and Discord webhook endpoints at firewall.  

### Short-term (1-30 days)
1. Conduct full credential hygiene and domain-wide password reset.  
2. Deploy enhanced endpoint monitoring & EDR alerting rules.  
3. Perform internal network sweep for similar artifacts on lateral targets.  

### Long-term (Security Improvements)
1. Enforce MFA for all remote access including RDP.  
2. Implement Zero Trust network segmentation to reduce lateral movement.  
3. Harden endpoint baseline: remove admin rights, enforce Defender policies.  

---

## APPENDIX

### A. Key Indicators of Compromise (IOCs)

| Type    | Value                      | Description                     |
|---------|---------------------------|---------------------------------|
| IP Address | 88.97.178.12            | Attacker RDP source              |
| IP Address | 78.141.196.6            | Command & Control server         |
| File      | wupdate.ps1               | Malicious execution script       |
| File      | mm.exe                    | Credential theft tool            |
| File      | export-data.zip           | Collected data archive           |
| Account   | kenji.sato                | Compromised legitimate user      |
| Account   | support                   | Malicious persistence account    |
| Domain    | discord.com               | Exfiltration channel             |
| Hash      | (mm.exe hash if available)| Credential dumper                |

### B. MITRE ATT&CK Mapping

| Tactic            | Technique ID     | Technique Name                     | Evidence                       | Flag # |
|------------------|-----------------|-----------------------------------|--------------------------------|--------|
| Initial Access    | T1078            | Valid Accounts                     | RDP login using stolen credentials | 1–2 |
| Execution         | T1059.001        | PowerShell                          | wupdate.ps1 execution          | 18 |
| Persistence       | T1053.005        | Scheduled Task                      | Windows Update Check           | 8–9 |
| Defense Evasion   | T1562            | Impair Defenses                     | Defender exclusions, hidden folder | 4–7 |
| Discovery         | T1018            | Network Discovery                   | arp -a                         | 3 |
| Credential Access | T1003.001        | LSASS Memory                        | mm.exe, sekurlsa::logonpasswords | 13 |
| Lateral Movement  | T1021.001        | RDP                                 | mstsc.exe to 10.1.0.188        | 19–20 |
| Collection        | T1560            | Archive Collected Data              | export-data.zip                | 14 |
| Command & Control | T1071.001        | Web Protocols                        | svchost.exe → 78.141.196.6:443 | 10–11 |
| Exfiltration      | T1567.002        | Exfiltration Over Web Service        | Discord webhook                | 15 |
| Impact            | T1565.002        | Data Destruction/Tamper             | Cleared Security logs          | 16 |

### C. Investigation Timeline

| Time (UTC) | Event                        | Evidence Source           |
|------------|------------------------------|---------------------------|
| 11:30      | Script execution begins      | DeviceProcessEvents       |
| 11:37      | wupdate.ps1 downloaded       | PowerShell logs           |
| 12:03      | Malicious script run         | ProcessCommandLine        |
| 12:09      | Backdoor account created     | net.exe logs              |
| 12:09      | Data staging begins          | WindowsCache artifacts    |
| 12:11      | Logs cleared                 | wevtutil                  |
| 12:09–12:10| Credential harvesting        | mm.exe                     |
| 12:09      | Data compressed              | export-data.zip           |
| 12:09      | Exfiltration via Discord     | curl.exe                  |
| Later      | Lateral movement to 10.1.0.188 attempted | mstsc.exe          |

# Security Investigation Report

## C. Investigation Timeline

| Time (UTC) | Event                        | Evidence Source           |
|------------|------------------------------|---------------------------|
| 11:30      | Script execution begins      | DeviceProcessEvents       |
| 11:37      | wupdate.ps1 downloaded       | PowerShell logs           |
| 12:03      | Malicious script run         | ProcessCommandLine        |
| 12:09      | Backdoor account created     | net.exe logs              |
| 12:09      | Data staging begins          | WindowsCache artifacts    |
| 12:11      | Logs cleared                 | wevtutil                  |
| 12:09–12:10| Credential harvesting        | mm.exe                     |
| 12:09      | Data compressed              | export-data.zip           |
| 12:09      | Exfiltration via Discord     | curl.exe                  |
| Later      | Lateral movement to 10.1.0.188 attempted | mstsc.exe          |

---

## D. Evidence - KQL Queries & Screenshots

The following queries cover activities between 19–20 November 2025.  
Each flag contains **Query**, **Results**, and **Screenshot** placeholders.

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



