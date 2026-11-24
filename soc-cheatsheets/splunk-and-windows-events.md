# SOC Analyst Field Guide: Splunk (SPL) & Windows Event IDs (SAL1 Prep)

A quick-reference triage playbook for investigating Windows endpoints, lateral movement, persistence, and malicious PowerShell execution in Splunk.

---

## 1. High-Priority Windows & Sysmon Event IDs

### Sysmon Operational (`Microsoft-Windows-Sysmon/Operational`)

| Event ID | Event Name | Key Fields to Inspect | What It Detects |
| :--- | :--- | :--- | :--- |
| **1** | Process Creation | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User` | Malicious executables, LOLBins (`WMIC`, `rundll32`, `mshta`), suspicious parent-child chains (e.g., `winword.exe` -> `cmd.exe`) |
| **3** | Network Connection | `Image`, `DestinationIp`, `DestinationPort`, `DestinationHostname` | Outbound C2 beacons, reverse shells, unauthorized remote connections |
| **7** | Image Loaded | `Image`, `ImageLoaded`, `Signed`, `Signature` | DLL side-loading / hijacking, unsigned DLL injection |
| **8** | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartFunction` | Process injection (e.g., injecting into `lsass.exe` or `explorer.exe`) |
| **11** | File Created | `Image`, `TargetFilename` | Dropped payloads, web shells, scripts written to `Temp` or `AppData` |
| **12 / 13 / 14** | Registry Object / Value Modified | `EventType`, `TargetObject`, `Details` | Persistence (`Run` / `RunOnce` keys), SAM database tampering, security tool disabling |
| **22** | DNS Query | `Image`, `QueryName`, `QueryResults` | C2 domain lookups, DGA domains, DNS tunneling |

### Windows Security (`Security`)

| Event ID | Event Name | Key Fields to Inspect | What It Detects |
| :--- | :--- | :--- | :--- |
| **4624** | Successful Logon | `TargetUserName`, `LogonType`, `IpAddress`, `WorkstationName` | Compromised account access (`LogonType 3` = Network, `10` = RDP, `2` = Interactive) |
| **4625** | Failed Logon | `TargetUserName`, `FailureReason`, `IpAddress` | Brute-force or password-spraying attacks |
| **4688** | Process Creation | `NewProcessName`, `CommandLine`, `ParentProcessName` | Native Windows fallback for process tracking when Sysmon isn't installed |
| **4697 / 7045** | Service Installed | `ServiceName`, `ServiceFileName` | Lateral movement (`PsExec`) or service-based persistence |
| **4720** | User Account Created | `TargetUserName`, `SubjectUserName` | Unauthorized local/domain backdoor accounts |
| **4728 / 4732** | Member Added to Security Group | `MemberName`, `TargetUserName` | Privilege escalation (e.g., adding a user to `Administrators` or `Domain Admins`) |

### PowerShell Logs

| Event ID | Log Channel | Key Fields to Inspect | What It Detects |
| :--- | :--- | :--- | :--- |
| **4103** | `PowerShell/Operational` | `ContextInfo`, `Payload`, `HostApplication` | **Module Logging:** Pipeline execution details & command arguments |
| **4104** | `PowerShell/Operational` | `ScriptBlockText`, `Path` | **Script Block Logging:** Full deobfuscated PowerShell code executed in memory |
| **400 / 800** | `Windows PowerShell` | `Message`, `HostApplication` | Legacy PowerShell engine start & pipeline execution logs |

---

## 2. 4-Step Splunk Triage Workflow

### Step 1: Scope Available Logs & Field Names
Before filtering by specific fields, check what log sources and field schemas exist (e.g., `EventID` vs. `EventCode`, `Hostname` vs. `ComputerName`):
```splunk
index=* | stats count by sourcetype, source
```

### Step 2: Hunt for Suspicious Process Execution (`EventID=1`)
Look for LOLBins, encoded commands, or unusual parent-child relationships:
```splunk
index=* EventID=1 (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*/node:*" OR CommandLine="*http*")
| table _time Hostname User ParentImage Image CommandLine
```

### Step 3: Trace Account Creation & Logon Activity
Check for newly provisioned accounts and verify whether they were used to authenticate:
```splunk
index=* (EventID=4720 OR EventID=4624 OR EventID=4625)
| stats count by EventID, TargetUserName, IpAddress
```

### Step 4: Audit PowerShell Execution (Check Both 4103 & 4104)
Always query both Module Logging (`4103`) and Script Block Logging (`4104`) when hunting obfuscated scripts:
```splunk
index=* (EventID=4103 OR EventID=4104)
| table _time Hostname AccountName EventID HostApplication
```

---

## 3. Quick Deobfuscation & IoC Tips
* **Decoding PowerShell Base64 (`-enc`):** Always decode using **Base64 -> UTF-16LE** (Windows PowerShell encodes strings in UTF-16 Little Endian by default).
* **Defanging IoCs for Reports:** Always replace `http` with `hxxp` and `.` with `[.]` (e.g., `hxxp[://]10[.]10[.]10[.]5/news[.]php`) so malicious links are non-clickable in documentation.
