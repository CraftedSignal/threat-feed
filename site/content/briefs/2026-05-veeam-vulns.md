---
title: Multiple Vulnerabilities in Veeam Products Allow Remote Code Execution
slug: 2026-05-veeam-vulns
description: Multiple vulnerabilities in Veeam ONE and Service Provider Console allow remote code execution (CVE-2026-32998) and an unspecified security issue, potentially leading to complete system compromise.
date: "2026-05-28T11:34:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - veeam
  - rce
  - vulnerability
vendors:
  - Veeam
products:
  - ONE
  - Service Provider Console
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-32998
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0657/
  - https://www.veeam.com/kb4853
  - https://www.veeam.com/kb4856
  - https://www.veeam.com/kb4858
  - https://www.cve.org/CVERecord?id=CVE-2026-32998
rules:
  - title: Detect Suspicious Veeam ONE Network Activity
    description: Detects unusual network connections to Veeam ONE servers, potentially indicating exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Veeam ONE PowerShell usage
    description: Detects Veeam ONE related PowerShell usage, which could indicate malicious activity
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 28, 2026, CERT-FR published an advisory regarding multiple vulnerabilities affecting Veeam ONE and Veeam Service Provider Console. Successful exploitation of these vulnerabilities could allow a remote attacker to execute arbitrary code or trigger an unspecified security issue. The most critical of these flaws is tracked as CVE-2026-32998 and could lead to a complete compromise of the affected system. The advisory highlights that vulnerable versions of Veeam ONE are older than 13.0.2.6723, Service Provider Console versions prior to 9.2.0.33215, and Service Provider Console 9.2.1.x versions before 9.2.1.33875 are affected. Organizations using these versions of Veeam products are urged to apply the provided patches to mitigate the risk.

## Attack Chain

1.  Attacker identifies a vulnerable Veeam ONE or Service Provider Console instance exposed to the network.
2.  The attacker sends a specially crafted request to the vulnerable service, exploiting CVE-2026-32998 or another undisclosed vulnerability.
3.  The vulnerable service processes the malicious request without proper sanitization.
4.  The attacker achieves remote code execution on the Veeam server.
5.  The attacker leverages the initial access to escalate privileges on the system.
6.  The attacker uses the compromised Veeam server as a pivot point to move laterally within the network.
7.  The attacker gains access to sensitive data, such as backup configurations and credentials.
8.  The attacker exfiltrates the stolen data or deploys ransomware to encrypt critical systems.

## Impact

Successful exploitation of these vulnerabilities could allow attackers to execute arbitrary code, potentially leading to complete system compromise. The unspecified security issue could lead to data breaches, service disruption, or further malicious activities. Organizations using vulnerable Veeam products are at risk of data loss, financial damages, and reputational harm. The impact is significant, as Veeam products are widely used for data backup and disaster recovery, making them attractive targets for malicious actors.

## Recommendation

*   Immediately upgrade Veeam ONE to version 13.0.2.6723 or later, as per [Veeam Security Bulletin kb4853](https://www.veeam.com/kb4853).
*   Upgrade Veeam Service Provider Console to version 9.2.0.33215 or later, or 9.2.1.33875 or later, according to [Veeam Security Bulletins kb4856](https://www.veeam.com/kb4856) and [kb4858](https://www.veeam.com/kb4858).
*   Monitor network traffic for suspicious activity targeting Veeam servers using the [Sigma rule "Detect Suspicious Veeam ONE Network Activity"].
*   Apply network segmentation to limit the blast radius of a potential compromise.
