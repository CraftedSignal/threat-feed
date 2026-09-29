---
title: Critical Vulnerabilities in WatchGuard AP Firmware
slug: 2026-09-watchguard-ap-vulnerabilities
description: Multiple vulnerabilities in WatchGuard AP firmware versions prior to 3.4.8, including improper access control and command injection, could allow unauthenticated or authenticated attackers to execute arbitrary commands.
date: "2026-09-29T22:22:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:h:watchguard:ap:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - networking
  - watchguard
vendors:
  - WatchGuard
products:
  - WatchGuard AP (< 3.4.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-101891 — WatchGuard AP Improper Access Control in API Service Allows Unauthenticated Access
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: CVE-2026-86102 — WatchGuard AP Command Injection in Internal Management API Allows Command Execution
    confidence_band: high
cves:
  - id: CVE-2026-101891
  - id: CVE-2026-86102
  - id: CVE-2026-87969
references:
  - https://cyber.gc.ca/en/alerts-advisories/watchguard-security-advisory-av26-972
  - https://psirt.watchguard.com/CVE-2026-101891
  - https://psirt.watchguard.com/CVE-2026-86102
  - https://psirt.watchguard.com/CVE-2026-87969
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade WatchGuard AP devices to firmware version 3.4.8 or later.
      owner: IT Operations
      addresses: CVE-2026-101891, CVE-2026-86102, CVE-2026-87969
      evidence: Source advisory AV26-972
---

WatchGuard has released a security advisory addressing multiple critical vulnerabilities affecting WatchGuard AP access points running firmware versions prior to 3.4.8. These flaws present significant risks to network infrastructure integrity and availability.

The vulnerabilities include CVE-2026-101891, an improper access control flaw in the device API service that permits unauthenticated access. Additionally, CVE-2026-86102 enables command injection via the internal management API, potentially allowing attackers to execute unauthorized commands. Finally, CVE-2026-87969 involves an authenticated command injection vulnerability within the diagnostic Command Line Interface (CLI). Successful exploitation of these vulnerabilities could result in full device compromise, enabling attackers to gain unauthorized persistence within the managed network environment. Administrators are advised to update affected hardware to firmware version 3.4.8 or later immediately.

## Impact

Successful exploitation of these vulnerabilities allows for unauthorized access and arbitrary command execution on WatchGuard access points. Given their role in enterprise network access, compromised APs could facilitate further lateral movement, traffic interception, or the permanent disruption of network services.

## Recommendation

* Apply the firmware update to version 3.4.8 or later on all impacted WatchGuard AP units as documented in the WatchGuard PSIRT advisory.
* Restrict network management access to AP devices to authorized administrative subnets only.
* Audit logs for anomalous POST requests or diagnostic CLI activity on networking hardware.
