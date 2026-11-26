# Endpoint Telemetry & Threat Hunting: Detecting Adversary Activity with Sysmon

**Platform:** TryHackMe – *Sysmon*  
**Tools Used:** Microsoft Sysmon, Windows Event Viewer, PowerShell (`Get-WinEvent` / XPath), Sysmon XML Configurations (SwiftOnSecurity)  
**MITRE ATT&CK Techniques:** T1091 (Replication Through Removable Media), T1218.005 (System Binary Proxy Execution: Mshta), T1546.008 (Event Triggered Execution: Accessibility Features / Sticky Keys), T1053.005 (Scheduled Task/Job), T1564.004 (Hide Artifacts: NTFS File Attributes / Alternate Data Streams), T1003.001 (OS Credential Dumping: LSASS Memory)

---

## 1. Executive Summary
This project demonstrates endpoint telemetry collection, noise reduction, and threat hunting using **Microsoft Sysmon** and PowerShell (`Get-WinEvent`). Across five forensic log investigations (`.evtx` datasets), high-signal Sysmon Event IDs were isolated via XPath filtering to cut through high-volume network noise and uncover rogue USB execution, HTML smuggling (`mshta.exe`), Sticky Keys registry hijacking, NTFS Alternate Data Stream (ADS) scheduled task persistence, and PowerShell Empire Command & Control (C2) traffic.

---

## 2. Telemetry Tuning & Noise Reduction (`Filtering.evtx`)
Unfiltered Sysmon configurations generate significant alert fatigue—particularly for network connections (**Event ID 3**). Using PowerShell `Get-WinEvent` with XPath filters on `Filtering.evtx` quantified the baseline log volume before applying exclusion-first rules (such as SwiftOnSecurity's `sysmonconfig.xml`).

```powershell
# Count baseline Event ID 3 network connections
(Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx" -FilterXPath '*/System/EventID=3').Count

# Retrieve the earliest network connection UTC timestamp
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx" -FilterXPath '*/System/EventID=3' -Oldest -MaxEvents 1 | fl Message
```
* **Baseline Event ID 3 Volume:** `73,591` network connection events
* **Earliest Event UTC Timestamp:** `2021-01-06 01:35:50.464` (`svchost.exe` RDP connection to `10[.]10[.]98[.]207:3389`)

![PowerShell Event ID 3 Noise Filtering](task4-filtering-noise.jpg)

---

## 3. Practical Threat Hunting Investigations

### Investigation 1: Rogue USB Execution & Raw Disk Access (`Investigation-1.evtx`)
Correlating Registry modification (**Event ID 13**), Raw Access Read (**Event ID 9**), and Process Creation (**Event ID 1**) events traced unauthorized removable media activity.
```powershell
Get-WinEvent -Path .\Investigation-1.evtx -FilterXPath '*/System/EventID=9' | fl Message
Get-WinEvent -Path .\Investigation-1.evtx -FilterXPath '*/System/EventID=1' -Oldest | fl Message
```
* **USB Registry Key (`TargetObject`):** `HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName`
* **Raw Disk Access Device (`Event ID 9`):** `\Device\HarddiskVolume3`
* **Initial Executable Launched (`Event ID 1`):** `rundll32.exe` (spawned via `explorer.exe` following `WUDFHost.exe` driver initialization)

![Investigation 1 RawAccessRead and Process Lineage](inv1-usb-rawaccess.png)

---

### Investigation 2: Masqueraded HTML Smuggling & `mshta.exe` Execution (`Investigation-2.evtx`)
Inspecting Process Creation (**Event ID 1**) and Network Connection (**Event ID 3**) telemetry uncovered an HTML smuggling attack leveraging a signed Windows LOLBin.
```powershell
Get-WinEvent -Path .\Investigation-2.evtx -FilterXPath '*/System/EventID=1 or */System/EventID=3' | fl Message
```
* **Masqueraded Lure File (`ParentCommandLine`):** `C:\Users\IEUser\Downloads\update.html` (opened via `iexplore.exe`)
* **Executed HTA Payload (`CommandLine`):** `C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\S97W7YG7\update.hta`
* **Signed LOLBin Executed (`Image`):** `C:\Windows\System32\mshta.exe`
* **C2 Server IP & Port (`Event ID 3`):** `10[.]0[.]2[.]18` on port `4443`

![Investigation 2 Mshta HTML Smuggling](inv2-mshta-smuggling.png)
![Investigation 2 C2 Network Connection](inv2-c2-network.png)

---

### Investigation 3.1: Sticky Keys Hijacking & Registry-Stored Payload (`Investigation-3.1.evtx`)
Querying Registry events (**Event ID 12 / 13**) and Network connections (**Event ID 3**) exposed an Accessibility Features persistence backdoor paired with an encoded PowerShell payload stored directly inside the Windows Registry.
```powershell
Get-WinEvent -Path .\Investigation-3.1.evtx -FilterXPath '*/System/EventID=12 or */System/EventID=13' | fl Message
Get-WinEvent -Path .\Investigation-3.1.evtx -FilterXPath '*/System/EventID=3' | fl Message
```
* **Affected Endpoint Hostname:** `DESKTOP-0153T4R`
* **Payload Storage Registry Key (`TargetObject`):** `HKLM\SOFTWARE\Microsoft\Network\debug`
* **Sticky Keys Persistence Command (`sethc.exe\Debugger`):**
  ```powershell
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "x=((gp HKLM:Software\Microsoft\Network debug).debug);start -Win Hidden -A \"-enc \$x\" powershell";exit;
  ```
* **C2 Infrastructure (`Event ID 3`):** `172[.]30[.]1[.]253` (Hostname: `empirec2`)

![Investigation 3.1 Sticky Keys and Registry Payload](inv3-1-sethc-persistence.png)

---

### Investigation 3.2: Scheduled Task Persistence via Alternate Data Stream (`Investigation-3.2.evtx`)
Analyzing Process Creation (**Event ID 1**), Network Connection (**Event ID 3**), and Process Access (**Event ID 10**) logs revealed a daily scheduled task reading a hidden Base64 payload from an NTFS Alternate Data Stream (ADS).
```powershell
Get-WinEvent -Path .\Investigation-3.2.evtx -FilterXPath '*/System/EventID=1' | fl Message
Get-WinEvent -Path .\Investigation-3.2.evtx -FilterXPath '*/System/EventID=10' | fl Message
```
* **Adversary IP (`Event ID 3`):** `172[.]168[.]103[.]188` (`://aol.com`)
* **Hidden ADS Payload Location:** `c:\users\q\AppData:blah.txt`
* **Scheduled Task Persistence Command (`schtasks.exe`):**
  ```cmd
  "C:\WINDOWS\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String(\$(cmd /c ''more < c:\users\q\AppData:blah.txt''))))\""
  ```
* **Sensitive Process Accessed (`Event ID 10`):** `lsass.exe`

![Investigation 3.2 Scheduled Task and Alternate Data Stream](inv3-2-schtasks-ads.png)

---

### Investigation 4: PowerShell Empire C2 Beaconing (`Investigation-4.evtx`)
Filtering outbound TCP connections in **Event ID 3** isolated active Command & Control beaconing over HTTP.
```powershell
Get-WinEvent -Path .\Investigation-4.evtx -FilterXPath '*/System/EventID=3' | fl Message
```
* **Adversary C2 IP:** `172[.]30[.]1[.]253`
* **C2 Port:** `80` (TCP)
* **C2 Framework Utilized:** `Empire` (`empirec2`)

![Investigation 4 PowerShell Empire C2 Traffic](inv4-empire-c2.png)

---

## 4. Summary of Indicators of Compromise (IoCs)

| Investigation | Indicator Type | Value | Detection Event ID |
| :--- | :--- | :--- | :--- |
| **Inv 1 (USB)** | Raw Disk & Binary | `\Device\HarddiskVolume3` -> `rundll32.exe` | Event ID 9 & 1 |
| **Inv 2 (HTA)** | Payload & C2 | `update.hta` (`mshta.exe`) -> `10[.]0[.]2[.]18:4443` | Event ID 1 & 3 |
| **Inv 3.1 (Registry)** | Persistence & C2 | `HKLM\SOFTWARE\Microsoft\Network\debug` -> `172[.]30[.]1[.]253` (`empirec2`) | Event ID 13 & 3 |
| **Inv 3.2 (ADS)** | Hidden Stream & IP | `c:\users\q\AppData:blah.txt` (`schtasks.exe`) -> `172[.]168[.]103[.]188` | Event ID 1 & 3 |
| **Inv 4 (Empire)** | C2 Endpoint | `172[.]30[.]1[.]253:80` (`empirec2`) | Event ID 3 |

---

## 5. Defensive & Detection Engineering Recommendations
1. **Enforce Exclusion-First Sysmon Baselines:** Deploy community-vetted configurations (`SwiftOnSecurity/sysmon-config` or `sysmon-modular`) to suppress high-volume benign OS network traffic (`Event ID 3`) while preserving high-signal anomalous connections.
2. **Alert on LOLBin & Accessibility Hijacks:** Trigger high-severity SIEM alerts when `mshta.exe`, `rundll32.exe`, or `powershell.exe` spawn from browsers (`iexplore.exe`) or when registry writes target `Image File Execution Options\sethc.exe`.
3. **Monitor NTFS Alternate Data Streams & Scheduled Tasks:** Alert on `schtasks.exe /Create` commands containing `FromBase64String`, `-enc`, or colon-delimited file stream syntax (`:`).
4. **Protect `lsass.exe` & Sysmon Integrity:** Alert on non-system processes requesting read access (`Event ID 10`) to `lsass.exe` and restrict write permissions on the Sysmon service and registry keys.

---

## 6. Mission Debrief
For a summary of key investigation wins, methodology takeaways, and areas for improvement from this lab, view the [Post-Incident Mission Debrief](./debrief).
