# SOC Incident Investigation: Lateral Movement, Persistence & Encoded PowerShell (Splunk)

**Platform:** TryHackMe – *Investigating with Splunk*  
**Tools Used:** Splunk Enterprise, Windows Event Logs, Sysmon, CyberChef  
**MITRE ATT&CK Techniques:** T1136.001 (Create Account: Local Account), T1047 (Windows Management Instrumentation), T1036.005 (Masquerading), T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated Files or Information)

---

## 1. Executive Summary
During a threat-hunting investigation using Splunk on ingested Windows Security, Sysmon, and PowerShell logs, unauthorized administrative activity was uncovered across multiple network hosts. The adversary executed remote `WMIC` commands to create a typosquatted backdoor user account, modified the SAM registry hive for persistence, attempted authentication using the rogue account, and executed a Base64-encoded PowerShell payload on a secondary host to initiate an external web request.

---

## 2. Investigation Methodology

### Phase 1: Unauthorized Account Creation & Masquerading
To identify newly created accounts, Windows Security logs were filtered for **Event ID 4720** (*A user account was created*).
```splunk
index="main" EventID=4720
```
* **Findings:** A rogue local account (`[Backdoor Username]`) was created to impersonate legitimate user `[Impersonated Username]`.
* **Authentication Audit:** Querying logon events (**Event ID 4624 / 4625**) revealed `[Number of Login Attempts]` authentication attempt(s) utilizing the backdoor account.

### Phase 2: Registry Persistence & Remote Execution (WMIC)
Querying Sysmon **Event ID 13** (*Registry value set*) and **Event ID 1** (*Process Creation*) exposed how the account was provisioned remotely:
```splunk
index="main" (EventID=1 OR EventID=13) [Backdoor Username]
```
* **Registry Modification:** `TargetObject` confirmed updates to `[Full Registry Key Path]`.
* **Lateral Movement Command:** `WMIC.exe` was invoked remotely to add the user:
  ```cmd
  [Full WMIC CommandLine String]
  ```

### Phase 3: Malicious PowerShell Execution & Payload Decoding
Pivoting to investigate execution activity across endpoints revealed suspicious PowerShell usage on host `[Infected Hostname]`.
```splunk
index="main" source="*PowerShell*"
```
* **Log Volume:** PowerShell Script Block Logging recorded `[Event Count]` total events associated with the malicious execution.
* **Deobfuscation:** Inspecting the logged script blocks uncovered an encoded command. Decoding the Base64 payload via CyberChef (UTF-16LE) revealed an outbound web request to `[Defanged URL, e.g., hxxps://example[.]com/payload]`.

---

## 3. Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **Rogue Username** | `[Backdoor Username]` | Typosquatted account impersonating `[Impersonated Username]` |
| **Registry Path** | `[Full Registry Key Path]` | SAM database modification for local account persistence |
| **WMIC Command** | `[CommandLine Snippet]` | Remote user creation via `WMIC.exe` |
| **Compromised Host** | `[Infected Hostname]` | Endpoint executing obfuscated PowerShell |
| **Malicious URL** | `[Defanged URL]` | External payload/C2 destination decoded from Base64 |

---

## 4. Detection & Remediation Recommendations
1. **Account & Host Containment:** Remove `[Backdoor Username]`, force password resets for `[Impersonated Username]`, and isolate `[Infected Hostname]` for full malware triage.
2. **Network Blocking:** Block outbound traffic to `[Defanged URL]` at the perimeter firewall/proxy and inspect DNS/proxy logs for any other internal hosts communicating with this domain.
3. **SIEM Detection Rules:**
   * Alert on Windows Event ID `4720` outside approved change windows.
   * Alert on `WMIC.exe` spawning remote `/node:` processes with `net user`.
   * Alert on PowerShell (`Event ID 4104`) containing `-EncodedCommand`, `-enc`, or `FromBase64String`.
