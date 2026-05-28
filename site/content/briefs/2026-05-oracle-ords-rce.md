---
title: 'CVE-2026-46839: Oracle REST Data Services Vulnerability Allows Remote Takeover'
slug: 2026-05-oracle-ords-rce
description: CVE-2026-46839 is an easily exploitable vulnerability in Oracle REST Data Services versions 24.2.0 through 26.1.0, allowing a low-privileged attacker with network access via HTTPS to compromise the service, potentially impacting other products and leading to a complete takeover.
date: "2026-05-28T21:18:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - rce
  - oracle
  - ords
vendors:
  - Oracle
products:
  - REST Data Services (24.2.0-26.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-46839
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46839
rules:
  - title: Detect CVE-2026-46839 Exploitation Attempt
    description: Detects CVE-2026-46839 exploitation attempt - suspicious HTTP POST requests to Oracle REST Data Services that may indicate an attempt to exploit the vulnerability
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-46839 Exploitation Attempt - ORDS Authentication Bypass
    description: Detects CVE-2026-46839 exploitation attempt - Monitors for specific URI patterns that may indicate an authentication bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-46839 is a critical vulnerability affecting Oracle REST Data Services (ORDS). Specifically, the 'Core' component in versions 24.2.0 through 26.1.0 is susceptible to a remote takeover. A low-privileged attacker with network access via HTTPS can exploit this vulnerability. The scope of impact extends beyond ORDS, potentially affecting additional products. This means a successful exploit can have cascading effects across an organization's infrastructure that relies on the affected ORDS instance. Given the potential for complete system takeover, patching and mitigation are critical.

## Attack Chain

1.  The attacker identifies an Oracle REST Data Services instance running a vulnerable version (24.2.0 - 26.1.0).
2.  The attacker establishes network access to the ORDS instance via HTTPS (port 443 or a custom HTTPS port).
3.  The attacker authenticates to the ORDS instance using low-privileged credentials.
4.  The attacker crafts a malicious HTTPS request specifically targeting the vulnerable component within the ORDS core.
5.  The malicious request exploits the vulnerability, allowing the attacker to execute arbitrary code within the ORDS environment.
6.  The attacker leverages the initial foothold to escalate privileges within the ORDS instance.
7.  The attacker gains full control of the ORDS instance, potentially compromising sensitive data and configurations.
8.  The attacker pivots from the compromised ORDS instance to other connected systems, leveraging the "scope change" mentioned in the vulnerability description to compromise additional products.

## Impact

Successful exploitation of CVE-2026-46839 can lead to a complete takeover of the Oracle REST Data Services instance. This can result in unauthorized access to sensitive data, modification of critical system configurations, and disruption of services. Due to the potential "scope change," other products integrated with the compromised ORDS instance may also be affected, leading to a wider breach of confidentiality, integrity, and availability.

## Recommendation

*   Immediately patch all Oracle REST Data Services instances to a version outside the vulnerable range (24.2.0 - 26.1.0) to address CVE-2026-46839.
*   Monitor network traffic for suspicious HTTPS requests targeting ORDS instances, specifically requests with unusual parameters or payloads, using a network intrusion detection system (NIDS).
*   Implement the provided Sigma rule `Detect CVE-2026-46839 Exploitation Attempt` to identify potential exploitation attempts within web server logs.
*   Review and restrict network access to ORDS instances, limiting access to only authorized users and systems, to reduce the attack surface.
