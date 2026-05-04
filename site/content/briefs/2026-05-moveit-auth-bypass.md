---
title: Critical Authentication Bypass Vulnerability in MOVEit Automation (CVE-2026-4670)
slug: 2026-05-moveit-auth-bypass
description: A critical authentication bypass vulnerability (CVE-2026-4670) in Progress MOVEit Automation allows an unauthenticated remote attacker to gain administrative access, potentially leading to full control over the application and sensitive file transfer workflows.
date: "2026-05-04T15:08:49Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - authentication-bypass
  - privilege-escalation
  - cve-2026-4670
  - cve-2026-5174
  - webserver
vendors:
  - Progress Software
products:
  - MOVEit Automation
  - MOVEit Automation <= 2025.1.4
  - MOVEit Automation <= 2025.0.8
  - MOVEit Automation <= 2024.1.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4670
    cvss: 9.8
    epss: 0.00074
  - id: CVE-2026-5174
    cvss: 7.7
    epss: 0.00059
references:
  - https://ccb.belgium.be/advisories/warning-critical-authentication-bypass-moveit-automation-cve-2026-4670-patch-immediately
  - https://community.progress.com/s/article/MOVEit-Automation-Critical-Security-Alert-Bulletin-April-2026-CVE-2026-4670-CVE-2026-5174
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4670
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5174
rules:
  - title: Detect MOVEit Automation Authentication Bypass Attempt
    description: Detects potential attempts to exploit the CVE-2026-4670 authentication bypass vulnerability in MOVEit Automation based on suspicious HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MOVEit Automation Privilege Escalation Attempt
    description: Detects potential attempts to exploit the CVE-2026-5174 privilege escalation vulnerability in MOVEit Automation based on suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Progress MOVEit Automation is affected by a critical authentication bypass vulnerability, CVE-2026-4670, which has a CVSS score of 9.8. Successful exploitation allows an unauthenticated remote attacker to gain administrative access to the vulnerable service. Additionally, a high severity privilege escalation vulnerability, CVE-2026-5174, exists due to improper input validation. While there is no current evidence of active exploitation in the wild, the historical targeting of Managed File Transfer (MFT) solutions, such as the 2023 Cl0p ransomware campaigns targeting MOVEit Transfer, heightens the urgency of patching this vulnerability. The affected versions of MOVEit Automation include versions prior to 2024.0.0, versions 2024.0.0 before 2024.1.8, versions 2025.0.0 before 2025.0.9, and versions 2025.1.0 before 2025.1.5. Defenders should prioritize patching to prevent potential exploitation.

## Attack Chain

1.  An unauthenticated attacker sends a specially crafted request to the MOVEit Automation server, exploiting CVE-2026-4670 (authentication bypass).
2.  The vulnerable MOVEit Automation software fails to properly validate the attacker's identity, granting them unauthorized access.
3.  The attacker gains access to the MOVEit Automation application with administrative privileges.
4.  The attacker leverages CVE-2026-5174 (improper input validation) to further escalate privileges within the application.
5.  The attacker manipulates sensitive file transfer workflows, potentially modifying file permissions or altering transfer schedules.
6.  The attacker exfiltrates sensitive data stored within MOVEit Automation.
7.  Alternatively, the attacker could deploy malicious scripts or backdoors to maintain persistence and control over the system.
8.  The attacker achieves complete control over the MOVEit Automation server, potentially impacting connected systems and data integrity.

## Impact

Successful exploitation of CVE-2026-4670 allows an unauthenticated attacker to gain administrative access to Progress MOVEit Automation servers. This can lead to the compromise of sensitive data, disruption of file transfer workflows, and potential deployment of ransomware or other malicious payloads. Given the history of MOVEit products being targeted, a successful attack could have widespread impact across various sectors that rely on MOVEit for secure file transfer, potentially affecting thousands of organizations.

## Recommendation

*   Immediately patch all affected MOVEit Automation installations to versions 2025.1.5 or later, 2025.0.9 or later, or 2024.1.8 or later as recommended by Progress Software to remediate CVE-2026-4670 and CVE-2026-5174.
*   Upscale monitoring and detection capabilities to identify any suspicious activity related to MOVEit Automation, as recommended by the CCB.
*   Implement the provided Sigma rule "Detect MOVEit Automation Authentication Bypass Attempt" to identify potential exploitation attempts targeting CVE-2026-4670 based on web server logs.
