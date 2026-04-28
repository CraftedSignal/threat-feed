---
title: JetBrains TeamCity Authentication Bypass and Path Traversal Vulnerabilities
slug: 2026-04-jetbrains-teamcity-vulns
description: Unpatched JetBrains TeamCity servers are being actively exploited via an authentication bypass (CVE-2024-27198) and path traversal vulnerability (CVE-2024-27199), allowing attackers to perform administrative actions and potentially conduct supply-chain attacks.
date: "2026-04-22T10:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - teamcity
  - vulnerability
  - authentication bypass
  - path traversal
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-27198
    cvss: 9.8
    epss: 0.93047
  - id: CVE-2024-27199
    cvss: 7.3
    epss: 0.91011
references:
  - https://ccb.belgium.be/advisories/warning-authentication-bypass-and-path-traversal-vulnerabilities-jetbrains-teamcity
  - https://nvd.nist.gov/vuln/detail/CVE-2024-27198
  - https://nvd.nist.gov/vuln/detail/CVE-2024-27199
  - https://www.cisa.gov/news-events/alerts/2026/04/20/cisa-adds-eight-known-exploited-vulnerabilities-catalog
  - https://www.jetbrains.com/privacy-security/issues-fixed/
rules:
  - title: Detect TeamCity Authentication Bypass Attempt
    description: Detects attempts to exploit CVE-2024-27198 by identifying suspicious requests that bypass authentication in JetBrains TeamCity.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect TeamCity Path Traversal Attempt
    description: Detects potential path traversal attempts (CVE-2024-27199) in JetBrains TeamCity by identifying requests containing directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - resource_development
    techniques:
      - T1190
      - T1588.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

JetBrains TeamCity, a CI/CD software platform, is vulnerable to CVE-2024-27198, an authentication bypass, and CVE-2024-27199, a path traversal vulnerability. These flaws affect TeamCity versions prior to 2023.11.4. Initially, there was no observed active exploitation. However, by March 7, 2024, widespread exploitation was detected following the public availability of proof-of-concept code. Attackers are actively exploiting these vulnerabilities to create new user accounts on publicly exposed, unpatched TeamCity instances. A substantial number of compromised servers are utilized as production machines for software building and deployment. These attacks have the potential to lead to supply-chain compromises by exposing sensitive information. CISA added CVE-2024-27199 to its Known Exploited Vulnerabilities catalog on April 20, 2026.

## Attack Chain

1.  The attacker sends a crafted HTTP request to a vulnerable TeamCity server, exploiting CVE-2024-27198 to bypass authentication.
2.  Once authenticated (or bypassing authentication), the attacker leverages CVE-2024-27199, a path traversal vulnerability, to access sensitive files and directories on the server.
3.  The attacker reads configuration files containing credentials for other systems and services.
4.  The attacker creates new administrative user accounts on the TeamCity server to ensure persistent access.
5.  The attacker modifies build configurations to inject malicious code into software builds.
6.  The attacker compromises the software supply chain by injecting malicious code into build artifacts.
7.  The attacker uses stolen credentials to access deployment environments and deploy compromised builds.

## Impact

Successful exploitation allows attackers to perform administrative actions on affected TeamCity servers, leading to a compromise of confidentiality, integrity, and availability of data and infrastructure. The compromise of TeamCity servers used for software building and deployment can result in supply-chain attacks, as these servers often contain sensitive information, such as credentials for deployment environments. A substantial portion of compromised TeamCity servers are utilized as production machines for software building and deployment processes, increasing the scope and impact of potential supply chain attacks.

## Recommendation

*   Immediately patch all JetBrains TeamCity servers to version 2023.11.4 or later to remediate CVE-2024-27198 and CVE-2024-27199 (Reference: https://www.jetbrains.com/privacy-security/issues-fixed/).
*   Deploy the Sigma rule "Detect TeamCity Authentication Bypass Attempt" to your SIEM to detect exploitation attempts of CVE-2024-27198.
*   Enable web server logging and increase monitoring to detect suspicious activity related to path traversal attempts indicative of CVE-2024-27199 exploitation.
*   Monitor for the creation of new user accounts within TeamCity, especially administrative accounts, which could indicate successful exploitation.
