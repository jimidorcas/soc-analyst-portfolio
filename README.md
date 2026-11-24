# SOC Analyst & Blue Team Portfolio

Welcome to my cybersecurity investigation repository. This portfolio documents hands-on incident response scenarios, SIEM threat hunts, log analyses, and defensive security labs completed across platforms like TryHackMe and personal home-lab environments.

## Core Skills & Tools
* **SIEM & Log Management:** Splunk (SPL), Windows Event Logs, Sysmon, PowerShell Script Block Logging
* **Threat Hunting & Analysis:** MITRE ATT&CK Mapping, Indicator of Compromise (IoC) Extraction, Base64/Payload Deobfuscation (CyberChef)
* **Incident Response:** Persistence Detection, Lateral Movement Tracking, Remediation & Alert Engineering

---

## Completed Investigations

| Date | Investigation / Scenario | Focus Area | Tools Used | Report |
| :--- | :--- | :--- | :--- | :--- |
| Nov 2026 | **Backdoor Persistence & Encoded PowerShell** | Unauthorized account creation (Event 4720), SAM registry tampering, WMIC lateral movement & Base64 C2 decoding | Splunk, Sysmon, CyberChef | [View Report](./siem-investigations/splunk-backdoor-lateral-movement/README.md) |

---

## Repository Structure
```text
soc-analyst-portfolio/
├── README.md                                  # Portfolio overview & investigation index
└── siem-investigations/
    └── splunk-backdoor-lateral-movement/
        ├── README.md                          # Full incident investigation report
        └── images/                            # Supporting SIEM query & log screenshots
```

---

## Connect With Me

