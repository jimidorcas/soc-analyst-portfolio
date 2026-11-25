# SOC Incident Investigation: Lateral Movement, Persistence & Encoded PowerShell (Splunk)

**Platform:** TryHackMe – *Investigating with Splunk*  
**Tools Used:** Splunk Enterprise, Windows Event Logs, Sysmon, CyberChef  
**MITRE ATT&CK Techniques:** T1136.001 (Create Account: Local Account), T1047 (Windows Management Instrumentation), T1036.005 (Masquerading), T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated Files or Information), T1562.001 (Impair Defenses: Disable or Modify Tools)

---

## 1. Executive Summary
During a threat-hunting investigation using Splunk on ingested Windows Security, Sysmon, and PowerShell logs, unauthorized administrative activity was uncovered across multiple network hosts. The adversary executed remote `WMIC` commands to create a typosquatted backdoor user account (`A1berto`), modified the SAM registry hive for persistence, and executed a multi-stage Base64-encoded PowerShell payload on `James.browne` that bypassed AMSI/Script Block Logging and initiated an outbound HTTP request to `hxxp[://]10[.]10[.]10[.]5/news[.]php`.

---

## 2. Investigation Methodology

### Phase 1: Unauthorized Account Creation & Masquerading
To identify newly created accounts, Windows Security logs were filtered for **Event ID 4720** (*A user account was created*).
```splunk
index="main" EventID=4720
```
* **Findings:** A rogue local account (`A1berto`) was created using homoglyph substitution (swapping `1` for `l`) to impersonate legitimate user `Alberto`.
* **Authentication Audit:** Querying logon events (`index="main" (EventID=4624 OR EventID=4625) A1berto`) confirmed `0` authentication attempts using the backdoor account, indicating it was staged strictly for persistence.

### Phase 2: Registry Persistence & Remote Execution (WMIC)
Querying Sysmon **Event ID 13** (*Registry value set*) and **Event ID 1** (*Process Creation*) exposed how the account was provisioned remotely:
```splunk
index="main" (EventID=1 OR EventID=13) A1berto
```
* **Registry Modification:** `TargetObject` confirmed updates to `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto` (and its corresponding RID key) to store the new account in the local Security Account Manager database.
* **Lateral Movement Command:** `WMIC.exe` was invoked remotely against `WORKSTATION6` to add the user:
  ```cmd
  C:\Windows\System32\wbem\WMIC.exe /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
  ```

### Phase 3: Malicious PowerShell Execution & Two-Stage Payload Decoding
Pivoting to PowerShell operational logs revealed suspicious execution activity on host `James.browne`.
```splunk
index="main" EventID=4103
```
* **Log Volume:** PowerShell Module Logging (`Event ID 4103`) recorded `79` total events associated with the malicious pipeline execution.
* **Deobfuscation:** Inspecting the logged execution details uncovered an encoded command (`-enc`). Decoding the first UTF-16LE Base64 layer revealed a script designed to disable Script Block Logging and AMSI (`amsiInitFailed`), alongside a second nested Base64 string (`aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==`). Decoding the nested string revealed an outbound RC4-encrypted web request to `hxxp[://]10[.]10[.]10[.]5/news[.]php`.

---

## 3. Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **Rogue Username** | `A1berto` | Typosquatted local account impersonating `Alberto` |
| **Registry Path** | `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto` | SAM database modification for local account persistence |
| **WMIC Command** | `C:\Windows\System32\wbem\WMIC.exe /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"` | Remote user creation via `WMIC.exe` |
| **Compromised Host** | `James.browne` | Endpoint executing obfuscated PowerShell (`EventID=4103`) |
| **Malicious URL** | `hxxp[://]10[.]10[.]10[.]5/news[.]php` | External payload/C2 destination decoded from nested Base64 |

---

## 4. Detection & Remediation Recommendations
1. **Account & Host Containment:** Delete the unauthorized `A1berto` local account across affected endpoints, force a password reset for `Alberto`, and isolate `James.browne` and `WORKSTATION6` for full forensic triage.
2. **Network Blocking:** Block outbound traffic to `10.10.10.5` at the perimeter firewall/proxy and inspect proxy/DNS logs for any other internal hosts communicating with this IP.
3. **SIEM Detection Rules:**
   * Alert on Windows Security `EventID=4720` outside approved IT provisioning windows.
   * Alert on Sysmon `EventID=1` where `Image="*\\WMIC.exe"` and `CommandLine="*/node:*"` paired with `net user` or `/add`.
   * Alert on PowerShell Module/Script Block logs (`EventID=4103` or `EventID=4104`) containing `-EncodedCommand`, `-enc`, `amsiInitFailed`, or `FromBase64String`.

---

## 5. Mission Debrief
For a summary of key investigation wins, methodology takeaways, and areas for improvement from this lab, view the [Post-Incident Mission Debrief](./debrief).

