---
title: WatchGuard Agent on Windows Multiple Vulnerabilities
slug: 2026-05-watchguard-agent-vulns
description: WatchGuard Agent on Windows (version 1.25.02.0000 and prior) is vulnerable to multiple privilege escalation and denial-of-service vulnerabilities, potentially allowing local attackers to execute arbitrary code with SYSTEM privileges or cause a denial of service.
date: "2026-05-06T17:24:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - denial-of-service
  - windows
vendors:
  - WatchGuard
products:
  - WatchGuard Agent on Windows (<= 1.25.02.0000)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-6787
  - id: CVE-2026-6788
  - id: CVE-2026-41288
  - id: CVE-2026-41286
  - id: CVE-2026-41287
references:
  - https://cyber.gc.ca/en/alerts-advisories/watchguard-security-advisory-av26-428
  - https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2026-00013
  - https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2026-00012
  - https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2026-00011
  - https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2026-00010
  - https://www.watchguard.com/wgrd-psirt/advisories
rules:
  - title: Detect WatchGuard Agent Discovery Service Crash
    description: Detects potential denial-of-service attacks against the WatchGuard Agent Discovery Service by monitoring for crashes related to buffer overflows.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - application
      - windows
  - title: Detect Suspicious Processes Spawned by WatchGuard Agent
    description: Detects suspicious processes spawned by the WatchGuard Agent, which may indicate exploitation of privilege escalation vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 6, 2026, WatchGuard released security advisories addressing multiple vulnerabilities affecting the WatchGuard Agent on Windows, specifically versions 1.25.02.0000 and prior. These vulnerabilities include several privilege escalation flaws (CVE-2026-6787, CVE-2026-6788, CVE-2026-41288) that could allow a local attacker to gain SYSTEM privileges. Additionally, stack-based buffer overflow vulnerabilities (CVE-2026-41286, CVE-2026-41287) in the WatchGuard Agent Discovery Service could lead to a denial-of-service condition. Successful exploitation of these vulnerabilities could allow an attacker to execute arbitrary code with elevated privileges or disrupt the normal operation of systems running the affected WatchGuard Agent.

## Attack Chain

1.  Attacker gains initial access to the target Windows system through existing credentials, phishing, or other means.
2.  Attacker leverages CVE-2026-6787 or CVE-2026-6788, chained agent service vulnerabilities, to achieve local privilege escalation.
3.  Attacker exploits CVE-2026-41288, another privilege escalation vulnerability, to further elevate privileges.
4.  Alternatively, attacker targets the WatchGuard Agent Discovery Service by sending a specially crafted network request.
5.  The malformed request triggers a stack-based buffer overflow (CVE-2026-41286 or CVE-2026-41287) within the Discovery Service.
6.  The buffer overflow causes the Discovery Service to crash, leading to a denial-of-service condition.
7.  With elevated privileges, the attacker installs malicious software, modifies system configurations, or steals sensitive data.
8.  If denial-of-service is achieved, the targeted system becomes unavailable, disrupting business operations.

## Impact

Successful exploitation of these vulnerabilities could have significant consequences. Privilege escalation could allow attackers to gain complete control over affected systems, leading to data breaches, malware infections, and system compromise. The denial-of-service vulnerabilities could disrupt business operations and negatively impact productivity. These vulnerabilities affect any system running WatchGuard Agent on Windows version 1.25.02.0000 and prior.

## Recommendation

*   Apply the necessary updates provided by WatchGuard to patch CVE-2026-6787, CVE-2026-6788, CVE-2026-41288, CVE-2026-41286, and CVE-2026-41287 on all systems running the WatchGuard Agent on Windows.
*   Enable Sysmon process-creation logging to monitor for suspicious processes spawned by the WatchGuard Agent that may indicate exploitation of privilege escalation vulnerabilities to enhance detection capabilities.
*   Deploy the Sigma rule "Detect WatchGuard Agent Discovery Service Crash" to identify potential denial of service attacks targeting the WatchGuard Agent.
