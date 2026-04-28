---
title: Multiple Critical Vulnerabilities in CISCO ISE Leading to Remote Code Execution
slug: 2026-04-cisco-ise-rce
description: Multiple critical vulnerabilities in CISCO ISE (CVE-2026-20186, CVE-2026-20147, CVE-2026-20180) allow remote attackers with low privileges to execute arbitrary commands, potentially escalating privileges to root and causing denial-of-service.
date: "2026-04-17T08:45:05Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cisco-ise
  - rce
  - command-injection
  - path-traversal
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
cves:
  - id: CVE-2026-20186
    cvss: 9.9
    epss: 0.0023
  - id: CVE-2026-20147
    cvss: 9.9
    epss: 0.0023
  - id: CVE-2026-20180
    cvss: 9.9
    epss: 0.00211
references:
  - https://ccb.belgium.be/advisories/warning-multiple-critical-vulnerabilities-cisco-ise-can-lead-rce-patch-immediately
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-rce-4fverepv
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-rce-traversal-8bYndVrZ
rules:
  - title: Detect Suspicious HTTP Requests to Cisco ISE Exploiting CVE-2026-20180
    description: Detects suspicious HTTP requests to Cisco ISE that may be exploiting CVE-2026-20180 by identifying unusual URI queries.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Cisco ISE Path Traversal Attempts via HTTP Requests
    description: Detects attempts to exploit path traversal vulnerabilities in Cisco ISE through HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Cisco Identity Services Engine (ISE) versions 3.x.x (3.1.0 - 3.4.0, and 3.1.0 p1-p10, 3.2.0 p1-p7, 3.3 Patches 1-7, and 3.4 Patches 1-3) are vulnerable to three newly disclosed vulnerabilities that can lead to remote code execution. These vulnerabilities, CVE-2026-20186, CVE-2026-20147, and CVE-2026-20180, can be exploited by remote attackers with low privileges, such as having Read Only Admin credentials. Successful exploitation can result in service disruption, system takeover, and complete compromise of the ISE instance. The vulnerabilities involve command injection and path traversal due to insufficient validation of user-supplied input in HTTP request handling. There is currently no public proof-of-concept or proof-of-exploitation available.

## Attack Chain

1.  Attacker authenticates to CISCO ISE with low-privilege credentials (e.g., Read Only Admin).
2.  Attacker crafts a malicious HTTP request targeting a vulnerable endpoint within the ISE web application.
3.  The crafted request exploits CVE-2026-20186 by injecting commands to escalate privileges to root.
4.  Alternatively, the attacker exploits CVE-2026-20147 by sending a crafted HTTP request to execute arbitrary commands on the underlying operating system.
5.  As another option, the attacker leverages CVE-2026-20180 by exploiting insufficient validation of user-supplied input, leading to remote code execution.
6.  The injected commands or executed code elevates the attacker's privileges to root.
7.  The attacker gains full control over the ISE system, enabling them to modify configurations, access sensitive data, or install malicious software.
8.  In single-node ISE deployments, successful exploitation can lead to a denial-of-service condition, disrupting network authentication and authorization services.

## Impact

Successful exploitation of these vulnerabilities allows attackers to gain complete control over the CISCO ISE system. This can lead to the compromise of sensitive network access policies, credentials, and other confidential information managed by ISE. The impact includes potential disruption of network services due to denial-of-service, unauthorized access to network resources, and the potential for lateral movement to other systems within the network. Given that ISE is a critical component for network access control, a successful attack can have widespread and severe consequences.

## Recommendation

*   Immediately patch vulnerable CISCO ISE instances to the latest version to remediate CVE-2026-20186, CVE-2026-20147, and CVE-2026-20180 (Cisco Security Advisory).
*   Implement enhanced monitoring and detection capabilities to identify suspicious activity related to these vulnerabilities (CCB Recommendation).
*   Investigate and remediate any existing compromises by reviewing system logs and configurations for unauthorized changes (CCB Recommendation).
