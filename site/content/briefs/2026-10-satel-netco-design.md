---
title: Multiple Vulnerabilities in Satel Netco Design
slug: 2026-10-satel-netco-design
description: Satel Netco Design versions prior to v2.1.7 contain multiple vulnerabilities, including path traversal, XSS, and regex-based DoS, which could be chained by an authenticated user for unauthorized file modification and remote code execution.
date: "2026-10-08T17:06:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - industrial-control-system
  - ics-advisory
vendors:
  - Satel
products:
  - Satel Netco Design (< v2.1.7)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Successful exploitation could result in unauthorized file creation or modification and, under certain conditions, arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user with Viewer privileges could submit crafted search input that causes excessive processing.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-03
  - https://www.cve.org/CVERecord?id=CVE-2026-105269
  - https://www.cve.org/CVERecord?id=CVE-2026-104628
  - https://www.cve.org/CVERecord?id=CVE-2026-105275
  - https://www.cve.org/CVERecord?id=CVE-2026-101024
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Satel Netco Design to v2.1.7
      owner: IT Operations
      addresses: CVE-2026-105269, CVE-2026-104628, CVE-2026-105275, CVE-2026-101024
      evidence: Satel advises users to update to Satel Netco Design v2.1.7.
---

Satel Netco Design versions prior to v2.1.7 are susceptible to a suite of four vulnerabilities that, when combined, present a significant risk to communications infrastructure. These vulnerabilities include two instances of relative path traversal (CVE-2026-105275, CVE-2026-101024), a stored cross-site scripting (XSS) vulnerability (CVE-2026-105269), and an inefficient regular expression complexity flaw (CVE-2026-104628).

The path traversal vulnerabilities in the data import and export functions permit authenticated users with Viewer privileges to access restricted file paths and write attacker-controlled content to the application's file system. This capability, particularly within the export function, may lead to remote code execution by overwriting legitimate application files. The XSS vulnerability allows for script execution in the context of other users' sessions, and the regex flaw can be leveraged to cause denial-of-service by consuming excessive system resources. Defenders should prioritize patching to version 2.1.7 to mitigate these high-severity risks.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise, unauthorized file creation or modification, application-level denial-of-service, and the execution of arbitrary scripts in the browser of other users. These vulnerabilities target the communications sector globally, potentially allowing an authenticated attacker to pivot from limited Viewer or Operator access to elevated control over the affected device.

## Recommendation

- Upgrade Satel Netco Design to version 2.1.7 immediately to address the vulnerabilities identified in CVE-2026-105269, CVE-2026-104628, CVE-2026-105275, and CVE-2026-101024.
- Restrict access to the Netco Design management interface to trusted internal networks to mitigate the impact of unauthorized access by authenticated users.
- Implement monitoring on application service file system changes to detect anomalous file creation or modification attempts originating from the application process.
