---
title: Critical Unauthenticated RCE Vulnerability Exploited in Microsoft SharePoint
slug: 2026-03-sharepoint-rce
description: A remote code execution vulnerability in Microsoft SharePoint (CVE not specified) is being actively exploited by unauthenticated attackers, prompting urgent patching recommendations for internet-facing servers.
date: "2026-03-25T08:51:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sharepoint
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://cert.europa.eu/publications/security-advisories/2026-004/
rules:
  - title: SharePoint Suspicious Process Creation
    description: Detects suspicious processes spawned by the SharePoint application pool account, indicating potential RCE exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: SharePoint Unauthenticated RCE Attempt
    description: Detects potential unauthenticated RCE attempts against SharePoint based on HTTP request patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

On March 17, 2026, Microsoft revised a January 2026 security advisory concerning a remote code execution (RCE) vulnerability in Microsoft SharePoint. The update included a heightened CVSS score and a clarification indicating that the vulnerability could be exploited by unauthenticated attackers. This exploitability led to its inclusion in CISA's Known Exploited Vulnerabilities (KEV) catalog on March 18, 2026. The advisory also mentions that three additional RCE vulnerabilities in Microsoft SharePoint were addressed in the March 2026 update. Given the active exploitation and the potential for significant impact, defenders should prioritize patching internet-facing SharePoint instances.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable, internet-facing SharePoint server.
2.  The attacker crafts a malicious HTTP request targeting the RCE vulnerability.
3.  The SharePoint server processes the request without proper authentication or input validation.
4.  The attacker injects a payload, such as a web shell, into the SharePoint server's process.
5.  The injected payload executes arbitrary code within the context of the SharePoint application pool account.
6.  The attacker leverages the web shell for remote access and reconnaissance within the SharePoint environment.
7.  The attacker attempts to escalate privileges within the compromised server or the Active Directory domain.
8.  The attacker moves laterally within the network, potentially targeting sensitive data or deploying ransomware.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary code on vulnerable Microsoft SharePoint servers. The impact includes potential data breaches, system compromise, and lateral movement within the network. Given the widespread use of SharePoint in enterprise environments, a successful attack could lead to significant disruption and financial losses, especially if attackers deploy ransomware or exfiltrate sensitive information. The specific number of affected organizations is currently unknown, but CERT-EU emphasizes the critical need for immediate patching.

## Recommendation

*   Immediately patch all Microsoft SharePoint servers, prioritizing internet-facing assets, as recommended by CERT-EU.
*   Implement the provided Sigma rule (`SharePoint_Suspicious_Process`) to detect suspicious process creation by the SharePoint application pool account.
*   Monitor web server logs for unusual HTTP requests targeting SharePoint servers that could indicate exploitation attempts (refer to the `SharePoint_Unauth_RCE` Sigma rule).
*   Review and harden SharePoint server configurations to minimize the attack surface.
