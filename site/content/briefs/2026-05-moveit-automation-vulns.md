---
title: Multiple Vulnerabilities in Progress MOVEit Automation
slug: 2026-05-moveit-automation-vulns
description: Multiple vulnerabilities in Progress MOVEit Automation allow for remote denial of service, security policy bypass, and unspecified security issues.
date: "2026-05-21T12:19:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:progress:moveit_automation:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
  - security-bypass
vendors:
  - Progress
products:
  - MOVEit Automation (2025.1.x)
  - MOVEit Automation
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-8485
    cvss: 5.9
  - id: CVE-2026-8486
    cvss: 5.3
  - id: CVE-2026-8487
    cvss: 6.5
  - id: CVE-2026-8488
    cvss: 4.3
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0624/
  - https://docs.progress.com/bundle/moveit-automation-release-notes-2026/page/Fixed-Issues-2026.html
  - https://www.cve.org/CVERecord?id=CVE-2026-8485
  - https://www.cve.org/CVERecord?id=CVE-2026-8486
  - https://www.cve.org/CVERecord?id=CVE-2026-8487
  - https://www.cve.org/CVERecord?id=CVE-2026-8488
rules:
  - title: Detect MOVEit Automation Security Policy Bypass Attempt
    description: Detects attempts to bypass security policies in Progress MOVEit Automation by monitoring for abnormal access patterns or unauthorized file access attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect MOVEit Automation Remote Denial of Service Attempt
    description: Detects potential remote denial-of-service (DoS) attacks against Progress MOVEit Automation by monitoring for excessive requests or abnormal traffic patterns.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

On May 21, 2026, CERT-FR published an advisory regarding multiple vulnerabilities in Progress MOVEit Automation. These vulnerabilities, identified by CVE-2026-8485, CVE-2026-8486, CVE-2026-8487, and CVE-2026-8488, can lead to remote denial-of-service (DoS), security policy bypass, and unspecified security compromises. The affected versions include MOVEit Automation versions 2025.1.x prior to 2025.1.7 and versions prior to 2025.0.11. Defenders should apply the patches released by Progress to mitigate these risks and ensure the confidentiality, integrity, and availability of MOVEit Automation instances.

## Attack Chain

1. An attacker identifies a vulnerable MOVEit Automation instance running a version prior to 2025.0.11 or 2025.1.7.
2. The attacker exploits CVE-2026-8485, CVE-2026-8486, CVE-2026-8487, or CVE-2026-8488 to gain unauthorized access.
3. Depending on the specific vulnerability exploited, the attacker bypasses security policies implemented within MOVEit Automation.
4. The attacker crafts malicious requests to trigger a denial-of-service condition, impacting the availability of MOVEit Automation services.
5. The attacker leverages the unspecified security vulnerability to perform unauthorized actions.
6. The attacker may attempt to escalate privileges within the MOVEit Automation system.
7. The attacker may attempt to access sensitive data stored or processed by MOVEit Automation.
8. The attacker disrupts or disables MOVEit Automation services.

## Impact

Successful exploitation of these vulnerabilities can lead to significant disruption of file transfer operations, potential data breaches, and reputational damage. Organizations relying on MOVEit Automation for critical file transfers may experience service outages, compliance violations, and financial losses. The unspecified vulnerability could potentially allow for more severe impacts, such as data exfiltration or complete system compromise.

## Recommendation

*   Immediately patch MOVEit Automation instances to version 2025.1.7 or later to remediate CVE-2026-8485, CVE-2026-8486, CVE-2026-8487, and CVE-2026-8488 as referenced in the advisory.
*   Monitor web server logs for suspicious activity targeting MOVEit Automation endpoints to detect potential exploitation attempts.
*   Deploy the Sigma rule "Detect MOVEit Automation Security Policy Bypass Attempt" to identify potential security policy circumvention.
