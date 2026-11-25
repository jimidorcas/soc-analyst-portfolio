# Endpoint Telemetry & Threat Hunting: Detecting Adversary Activity with Sysmon

**Platform:** TryHackMe – *Sysmon*  
**Tools Used:** Microsoft Sysmon, Windows Event Viewer, PowerShell (`Get-WinEvent`), Sysmon XML Configurations (SwiftOnSecurity)  
**MITRE ATT&CK Techniques:** T1059 (Command and Scripting Interpreter), T1003.001 (OS Credential Dumping: LSASS Memory), T1055 (Process Injection), T1547.001 (Registry Run Keys / Startup Folder), T1070 (Indicator Removal)

---

## 1. Executive Summary
This investigation focuses on configuring, filtering, and hunting malicious endpoint activity using **Microsoft Sysmon** telemetry. Across multiple simulated compromise scenarios (`.evtx` log sets), high-signal Sysmon Event IDs were analyzed via Windows Event Viewer and PowerShell XPath queries to cut through high-volume log noise and detect C2 reverse shells, credential dumping (Mimikatz), malware persistence, and defense evasion techniques.

---

## 2. Telemetry Tuning & Noise Reduction 
Unfiltered Sysmon configurations generate overwhelming alert fatigue—particularly for network connections (**Event ID 3**). Using PowerShell `Get-WinEvent` with XPath filters on `Filtering.evtx` demonstrated the baseline volume before applying exclusion rules (such as SwiftOnSecurity's `sysmonconfig.xml`).

```powershell
# Count baseline Event ID 3 network events
(Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx" -FilterXPath "*[System[EventID=3]]").Count

# Retrieve the earliest network connection timestamp
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx" -FilterXPath "*[System[EventID=3]]" -Oldest -MaxEvents 1 | Format-List TimeCreated, Message
```
* **Baseline Event ID 3 Volume:** `73,591` events 
* **Earliest Event UTC Timestamp:** `[]`

*(Optional: Embed Screenshot #1 here)*
```markdown
![PowerShell Event ID 3 Filtering](filtering-eventid3-count.png)
```

---

## 3. Threat Hunting Scenarios

### Scenario 1: Hunting Metasploit Reverse Shells (Task 5 – `Investigation-1.evtx`)
To identify a staged Metasploit payload and its outbound Command & Control (C2) channel, file creation (**Event ID 11**) and network connection (**Event ID 3**) events were correlated.
```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx" -FilterXPath "*[System[EventID=3 or EventID=11]]" | Format-List Message
```
* **Malicious Payload Path (`Image`):** `[Paste Full Payload Path, e.g., C:\Users\THM-Analyst\Desktop\...]`
* **C2 Server IP (`DestinationIp`):** `[Defanged C2 IP, e.g., 10[.]10[.]X[.]X]`
* **C2 Listening Port (`DestinationPort`):** `[Port Number]`

*(Optional: Embed Screenshot #2 here)*
```markdown
![Metasploit Event ID 3 C2 Connection](metasploit-eventid3-c2.png)
```

---

### Scenario 2: Detecting Credential Dumping & Mimikatz (Task 6 – `Investigation-2.evtx`)
To detect credential harvesting tools accessing Local Security Authority Subsystem Service (`lsass.exe`) memory, Sysmon **Event ID 10** (*ProcessAccess*) and **Event ID 1** (*ProcessCreate*) were inspected.
```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-2.evtx" -FilterXPath "*[System[EventID=1 or EventID=10]]" | Format-List Message
```
* **Target Process:** `C:\Windows\System32\lsass.exe`
* **Source Process (`SourceImage`):** `[Malicious Binary Path]`
* **Granted Access Mask (`GrantedAccess`):** `[e.g., 0x1010 / 0x1410]`
* **Key Indicator:** Unusual read access requests (`GrantedAccess`) targeting `lsass.exe` from non-system binaries.

---

### Scenario 3: Hunting Malware Persistence & RATs (Task 7 – `Investigation-3.1.evtx` & `3.2.evtx`)
Registry modification logs (**Event ID 12 / 13 / 14**) and file drops (**Event ID 11**) were queried to uncover unauthorized startup persistence.
```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1.evtx" -FilterXPath "*[System[EventID=11 or EventID=13]]" | Format-List Message
```
* **Dropped Persistence Binary:** `[Filename & Path]`
* **Modified Registry Key (`TargetObject`):** `[Full Registry Run Key Path]`
* **File Hash (`Hashes`):** `[MD5 / SHA256 Hash]`

---

### Scenario 4: Detecting Defense Evasion & Log Tampering (Task 8 – `Investigation-4.evtx`)
Adversaries frequently attempt to blind endpoint monitoring by clearing event logs or altering Sysmon's own registry configuration.
* **Tampering Vector:** `[Describe Event ID / Registry or Service Change]`
* **Process / Command Executed:** `[CommandLine or Image]`

---

### Scenario 5: Practical Real-World Threat Hunt (Task 9 – `Practice` Logs)
Correlating process lineage (`ParentImage` -> `Image`), network connections (`Event ID 3`), and DNS queries (`Event ID 22`) reconstructed an end-to-end workstation infection.
* **Initial Execution Vector:** `[Parent Process -> Child Process]`
* **Suspicious Domain / IP Queried (`Event ID 22` / `3`):** `[Defanged Domain / IP]`
* **Persistence / Payload Artifact:** `[Dropped File or Registry Entry]`

---

## 4. Summary of Indicators of Compromise (IoCs)

| Scenario | Indicator Type | Value | Detection Event ID |
| :--- | :--- | :--- | :--- |
| **Metasploit** | Payload & C2 | `[Payload Path]` -> `[Defanged IP]:[Port]` | Event ID 11 & 3 |
| **Mimikatz** | `lsass.exe` Access | `[SourceImage]` (`GrantedAccess: [Mask]`) | Event ID 10 |
| **Persistence** | Registry Run Key | `[TargetObject Path]` | Event ID 13 |
| **Defense Evasion** | Tampering Artifact | `[Process / Registry Path]` | Event ID 1 / 13 |

---

## 5. Defensive & Detection Engineering Takeaways
1. **Deploy Baseline Exclusions:** Never run Sysmon with default unfiltered rules in production; apply community-vetted baselines (such as `SwiftOnSecurity/sysmon-config` or `olafhartong/sysmon-modular`) to filter benign OS network noise (`Event ID 3`).
2. **Monitor `lsass.exe` Access (`Event ID 10`):** Alert on any non-EDR/non-system process requesting `0x1010`, `0x1410`, or `0x1438` access rights to `lsass.exe`.
3. **Protect Sysmon Service & Registry:** Restrict write permissions on `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv` and alert immediately if the Sysmon service stops or its configuration hash changes (`Event ID 16`).
