---
title: Multiple Vulnerabilities in CISA Malcolm
slug: 2026-10-cisa-malcolm
description: CISA Malcolm versions prior to v26.06.0 contain multiple critical vulnerabilities, including command injection, path traversal, and SSRF, allowing attackers to achieve remote code execution, authentication bypass, and unauthorized data access.
date: "2026-10-01T17:06:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cisa
  - rce
  - ssrf
vendors:
  - CISA
products:
  - Malcolm (< v26.06.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerabilities allow an unauthenticated network attacker to craft a link that... executes arbitrary script in the context of the affected application.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An automated process later constructs and runs a system command using the uploaded file's name, allowing an authenticated attacker to embed and execute arbitrary operating system commands.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-254-01
  - https://www.cve.org/CVERecord?id=CVE-2026-90443
  - https://www.cve.org/CVERecord?id=CVE-2026-90444
  - https://www.cve.org/CVERecord?id=CVE-2026-90445
  - https://www.cve.org/CVERecord?id=CVE-2026-90446
  - https://www.cve.org/CVERecord?id=CVE-2026-90447
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade CISA Malcolm to v26.06.0 or later
      owner: IT Operations
      due: 24h
      evidence: 'Vendor fix: The latest version of Malcolm (September 2026 or later) fixes these vulnerabilities.'
  mitigation_plan:
    - priority: immediate
      action: Patch CISA Malcolm
      owner: IT Operations
      addresses: CVE-2026-90443, CVE-2026-90444, CVE-2026-90445, CVE-2026-90446, CVE-2026-90447
      evidence: Vendor fix provided in the advisory.
---

CISA Malcolm versions prior to v26.06.0 are affected by a suite of high-severity vulnerabilities discovered in its web-based interfaces and API endpoints. These vulnerabilities range from unauthenticated Cross-Site Scripting (CVE-2026-90443) to authenticated Remote Code Execution (CVE-2026-90444), Path Traversal (CVE-2026-90445), Server-Side Request Forgery (CVE-2026-90446), and Authentication Bypass via header manipulation (CVE-2026-90447). The flaws reside in how the application processes user-supplied input, manages file uploads, and handles internal routing.

These vulnerabilities allow attackers, depending on their authentication status, to execute arbitrary operating system commands with application privileges, traverse directory structures to write files to arbitrary locations, and interact with internal data stores. Malcolm is deployed globally across sectors including Energy, IT, and Water, making the timely application of vendor-provided patches essential for maintaining operational integrity.

## Impact

Successful exploitation of these vulnerabilities can lead to full system compromise, unauthorized data exfiltration from internal backend services, and the injection of malicious records into diagnostic or logging data. Given the application's role in network traffic analysis and its deployment within critical infrastructure environments, successful exploitation could provide an attacker with a foothold for lateral movement into sensitive segments of an internal network.

## Recommendation

Prioritize patching all instances of CISA Malcolm immediately. 

- Upgrade all CISA Malcolm instances to the September 2026 release (v26.06.0 or later) as specified in the vendor remediation guidance.
- Implement strict ingress filtering for web and API interfaces to ensure only authorized personnel can interact with the system.
- Review all system logs for anomalous file upload activity or unexpected outbound connections from the Malcolm instance, which may indicate exploitation attempts related to CVE-2026-90444 or CVE-2026-90446.
