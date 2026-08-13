---
title: Multiple Vulnerabilities in ANDRITZ HIPASE-250 and 250 SCALA
slug: 2026-08-andritz-hipase-vulnerabilities
description: ANDRITZ HIPASE-250 and 250 SCALA devices (versions <=7.20) contain multiple high-severity vulnerabilities, including hard-coded credentials, missing authentication on critical functions, and insecure password storage, enabling potential remote exploitation.
date: "2026-08-13T16:52:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - energy
  - ot
  - vulnerability
  - cve-2026-65309
  - cve-2026-65310
  - cve-2026-65311
  - cve-2026-65313
vendors:
  - ANDRITZ
products:
  - HIPASE-250
  - 250 SCALA
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker with network access can read live process values and server configuration.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
    evidence: A remote, unauthenticated attacker with network access to the service may suppress audit logging, potentially concealing other activity on the system.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Because the same credential is applied to every workstation provisioned this way, an attacker with adjacent-network access who knows the password can gain VNC access to affected workstations.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: This allows an attacker able to read the credential store or capture network traffic to recover all stored passwords.
    confidence_band: high
cves:
  - id: CVE-2026-65309
    cvss: 7.5
    epss: 0.00152
  - id: CVE-2026-65310
    cvss: 7.5
    epss: 0.00318
  - id: CVE-2026-65311
    cvss: 5.3
    epss: 0.00269
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-05
  - https://www.cve.org/CVERecord?id=CVE-2026-65309
  - https://www.cve.org/CVERecord?id=CVE-2026-65310
  - https://www.cve.org/CVERecord?id=CVE-2026-65311
  - https://www.cve.org/CVERecord?id=CVE-2026-65313
action_plan:
  priority: elevated
  owners:
    - OT Security
    - IT Operations
  immediate_actions:
    - action: Upgrade ANDRITZ equipment to V8.15.00
      owner: IT Operations
      due: 72h
      evidence: Vendor remediation in CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to management interfaces
      owner: Network Security
      addresses: CVE-2026-65310
      evidence: Source support for missing authentication
---

ANDRITZ HIPASE-250 and 250 SCALA devices (versions 7.20 and earlier) are susceptible to a suite of vulnerabilities that expose critical industrial control system (ICS) infrastructure to unauthorized access and manipulation. These flaws include CVE-2026-65309 (storing passwords in a recoverable format), CVE-2026-65310 (missing authentication for critical configuration endpoints), CVE-2026-65311 (unauthorized modification of logging levels), and CVE-2026-65313 (use of hard-coded credentials for x11vnc).

These issues, impacting the Energy sector globally, stem from insecure design patterns during development and provisioning. An unauthenticated attacker can gain visibility into live process data, recover credentials, or establish remote control over engineering workstations via VNC. These vulnerabilities highlight the risk of exposed ICS management interfaces and the necessity for robust authentication and secure credential management within operational technology (OT) environments. ANDRITZ has released versions V8.00.00 and V8.15.00 to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities allows for unauthorized access to process values, potential credential harvesting across the enterprise, and the concealment of malicious activity by disabling system logging. In the context of the Energy sector, these impacts pose significant operational risks, including the potential for unauthorized process manipulation or the compromise of sensitive engineering infrastructure, affecting organizations globally that rely on these ANDRITZ platforms.

## Recommendation

- Upgrade all ANDRITZ HIPASE-250 and 250 SCALA instances to version V8.15.00 immediately as specified in the vendor remediation.
- Audit network segmentation to ensure management interfaces for HIPASE-250 and 250 SCALA are not reachable from untrusted or public networks to mitigate the risk of unauthenticated access (CVE-2026-65310).
- Review all engineering workstations for VNC services and change default passwords immediately to address CVE-2026-65313.
- Implement monitoring for unauthorized or anomalous access to configuration endpoints and log-level adjustment endpoints, particularly targeting the specific undocumented interfaces described in CVE-2026-65311.
