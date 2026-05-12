---
title: Multiple Vulnerabilities in Microsoft Edge Allow for Privilege Escalation, Data Breach, and Security Policy Bypass
slug: 2026-05-multiple-edge-vulns
description: Multiple vulnerabilities in Microsoft Edge and Microsoft Edge for Android can allow an attacker to perform privilege escalation, cause a data breach, and bypass security policies.
date: "2026-05-12T14:14:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - data-breach
  - security-policy-bypass
vendors:
  - Microsoft
products:
  - Edge
  - Edge for Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7897
    cvss: 7.5
    epss: 0.00074
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0570/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35429
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41107
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42838
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42891
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7897
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7905
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7912
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7913
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7915
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7931
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7941
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7993
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8020
  - https://www.cve.org/CVERecord?id=CVE-2026-35429
  - https://www.cve.org/CVERecord?id=CVE-2026-41107
  - https://www.cve.org/CVERecord?id=CVE-2026-42838
  - https://www.cve.org/CVERecord?id=CVE-2026-42891
  - https://www.cve.org/CVERecord?id=CVE-2026-7897
  - https://www.cve.org/CVERecord?id=CVE-2026-7905
  - https://www.cve.org/CVERecord?id=CVE-2026-7912
  - https://www.cve.org/CVERecord?id=CVE-2026-7913
  - https://www.cve.org/CVERecord?id=CVE-2026-7915
  - https://www.cve.org/CVERecord?id=CVE-2026-7931
  - https://www.cve.org/CVERecord?id=CVE-2026-7941
  - https://www.cve.org/CVERecord?id=CVE-2026-7993
  - https://www.cve.org/CVERecord?id=CVE-2026-8020
rules:
  - title: Detect Suspicious Edge Process Creation
    description: Detects suspicious process creation events originating from Microsoft Edge, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Edge Outbound Connection
    description: Detects suspicious outbound network connections from Microsoft Edge processes to unusual ports or IPs.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On May 12, 2026, CERT-FR published an advisory (CERTFR-2026-AVI-0570) detailing multiple vulnerabilities in Microsoft Edge and Microsoft Edge for Android. The vulnerabilities can lead to privilege escalation, data breaches, and security policy bypass. The affected versions are Microsoft Edge versions earlier than 148.0.3967.55 and Microsoft Edge for Android versions earlier than 148.0.3967.55. These vulnerabilities pose a significant risk, as successful exploitation could allow attackers to gain unauthorized access and control over affected systems and sensitive user data.

## Attack Chain

Due to the nature of the vulnerabilities (privilege escalation, data breach, and security policy bypass) without specific exploitation details, a generic attack chain is presented:

1.  An attacker identifies a vulnerable Microsoft Edge or Edge for Android version.
2.  The attacker crafts a malicious payload or exploits a specific vulnerability (CVE-2026-35429, CVE-2026-41107, CVE-2026-42838, CVE-2026-42891, CVE-2026-7897, CVE-2026-7905, CVE-2026-7912, CVE-2026-7913, CVE-2026-7915, CVE-2026-7931, CVE-2026-7941, CVE-2026-7993, CVE-2026-8020).
3.  The user interacts with the malicious payload, such as by visiting a compromised website or opening a specially crafted file.
4.  The vulnerability is triggered, allowing the attacker to execute arbitrary code within the context of the Edge process.
5.  The attacker escalates privileges, gaining higher-level access to the system or application.
6.  Sensitive data is accessed and potentially exfiltrated.
7.  Security policies are bypassed, allowing the attacker to perform actions that would normally be restricted.
8.  The attacker maintains persistence and expands their access to other systems on the network.

## Impact

Successful exploitation of these vulnerabilities could have severe consequences. Attackers could gain elevated privileges, enabling them to perform administrative tasks, install malware, or modify system settings. Data breaches could lead to the theft of sensitive user information, such as credentials, financial data, or personal details. Bypassing security policies could allow attackers to circumvent security controls and perform unauthorized actions, potentially compromising the entire system.

## Recommendation

*   Apply the latest Microsoft Edge updates to version 148.0.3967.55 or later for both desktop and Android platforms to remediate the vulnerabilities (see CVE-2026-35429, CVE-2026-41107, CVE-2026-42838, CVE-2026-42891, CVE-2026-7897, CVE-2026-7905, CVE-2026-7912, CVE-2026-7913, CVE-2026-7915, CVE-2026-7931, CVE-2026-7941, CVE-2026-7993, CVE-2026-8020).
*   Implement the "Detect Suspicious Edge Process Creation" Sigma rule to identify potential exploitation attempts through unusual process spawning.
*   Monitor network traffic for suspicious outbound connections originating from Microsoft Edge processes using the "Detect Suspicious Edge Outbound Connection" Sigma rule.
