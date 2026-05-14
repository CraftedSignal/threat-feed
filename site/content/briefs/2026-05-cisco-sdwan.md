---
title: Cisco Catalyst SD-WAN Manager Multiple Vulnerabilities
slug: 2026-05-cisco-sdwan
description: Multiple vulnerabilities in Cisco Catalyst SD-WAN Manager could allow a remote attacker to gain access to sensitive information, elevate privileges, or gain unauthorized access to the application.
date: "2026-05-14T16:01:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cisco
  - sdwan
  - vulnerability
  - privilege-escalation
  - initial-access
vendors:
  - Cisco
products:
  - Catalyst SD-WAN Manager
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-mltvnps2-JxpWm7R
  - CVE-2026-20209
  - CVE-2026-20210
  - CVE-2026-20224
rules:
  - title: Detect CVE-2026-20209 and CVE-2026-20210 Exploitation Attempt - Suspicious URI Access
    description: Detects potential exploitation attempts of CVE-2026-20209 and CVE-2026-20210 by monitoring for suspicious URI access patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    data_sources:
      - webserver
  - title: Detect CVE-2026-20224 Exploitation Attempt - Unauthorized API Access
    description: Detects potential exploitation attempts of CVE-2026-20224 by monitoring for unauthorized API access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, is affected by multiple vulnerabilities that could lead to sensitive information disclosure, privilege escalation, or unauthorized application access. These vulnerabilities are identified as CVE-2026-20209, CVE-2026-20210, and CVE-2026-20224. Cisco has released software updates to address these issues and recommends immediate upgrades. These vulnerabilities pose a significant risk to organizations relying on Cisco Catalyst SD-WAN Manager for network management, potentially allowing attackers to compromise the confidentiality, integrity, and availability of the SD-WAN infrastructure. There are no known workarounds; patching is the only remediation.

## Attack Chain

1.  The attacker identifies a vulnerable Cisco Catalyst SD-WAN Manager instance.
2.  The attacker exploits CVE-2026-20209 to gain unauthorized access. This might involve sending a crafted request to a specific endpoint.
3.  Upon gaining initial access, the attacker leverages CVE-2026-20210 to escalate privileges within the application.
4.  With elevated privileges, the attacker exploits CVE-2026-20224 to access sensitive information stored within the SD-WAN Manager.
5.  The attacker uses the disclosed information to further compromise the SD-WAN environment.
6.  The attacker gains complete control over the SD-WAN Manager, potentially disrupting network operations.

## Impact

Successful exploitation of these vulnerabilities could allow a remote attacker to gain unauthorized access to sensitive information, elevate privileges, or gain unauthorized access to the application. This could lead to a complete compromise of the SD-WAN infrastructure, potentially affecting numerous organizations relying on the affected Cisco product for network management. The vulnerabilities are rated as critical by Cisco.

## Recommendation

*   Apply the software updates provided by Cisco to address CVE-2026-20209, CVE-2026-20210, and CVE-2026-20224 on all affected Catalyst SD-WAN Manager instances.
*   Deploy the Sigma rules provided below to your SIEM to detect potential exploitation attempts targeting these vulnerabilities.
*   Monitor network traffic for suspicious activity related to Cisco Catalyst SD-WAN Manager, focusing on unusual access patterns and data exfiltration attempts.
