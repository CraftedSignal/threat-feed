---
title: Multiple Vulnerabilities in Mozilla Thunderbird Allow for Remote Code Execution and Data Breach
slug: 2026-05-thunderbird-vulns
description: Multiple vulnerabilities in Mozilla Thunderbird prior to versions 150.0.1 and Thunderbird ESR prior to 140.10.1 could allow a remote attacker to achieve arbitrary code execution, data confidentiality breach, and security policy bypass.
date: "2026-05-04T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - databreach
  - securitybypass
vendors:
  - Mozilla
products:
  - Thunderbird ESR
  - Thunderbird
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7320
    cvss: 7.5
    epss: 0.00037
  - id: CVE-2026-7321
    cvss: 9.6
    epss: 0.00042
  - id: CVE-2026-7322
    cvss: 7.3
    epss: 0.00049
  - id: CVE-2026-7323
    cvss: 7.3
    epss: 0.00044
  - id: CVE-2026-7324
    cvss: 7.3
    epss: 0.00039
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0529/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-38/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-39/
  - https://www.cve.org/CVERecord?id=CVE-2026-7320
  - https://www.cve.org/CVERecord?id=CVE-2026-7321
  - https://www.cve.org/CVERecord?id=CVE-2026-7322
  - https://www.cve.org/CVERecord?id=CVE-2026-7323
  - https://www.cve.org/CVERecord?id=CVE-2026-7324
rules:
  - title: Detect Thunderbird Spawning Suspicious Processes
    description: Detects Thunderbird spawning suspicious child processes, which could indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Thunderbird Running External Commands
    description: Detects Thunderbird running external commands via command line interpreters or script engines.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 4, 2026, CERT-FR published an advisory regarding multiple vulnerabilities affecting Mozilla Thunderbird. Specifically, Thunderbird versions prior to 150.0.1 and Thunderbird ESR versions prior to 140.10.1 are vulnerable. Successful exploitation of these vulnerabilities could allow an attacker to achieve remote code execution, compromise the confidentiality of data, and bypass security policies. The advisory highlights the urgency for users and organizations utilizing affected versions to apply the necessary patches to mitigate these risks. These vulnerabilities underscore the importance of maintaining up-to-date software versions to defend against potential exploitation.

## Attack Chain

1.  Attacker identifies a target using a vulnerable version of Mozilla Thunderbird (ESR < 140.10.1 or < 150.0.1).
2.  Attacker crafts a malicious email or leverages a compromised website to deliver a specially crafted exploit.
3.  The user opens the malicious email or visits the compromised website within Thunderbird.
4.  The exploit triggers a vulnerability in Thunderbird, such as CVE-2026-7320 (or another from the listed CVEs), leading to code execution.
5.  Attacker gains initial access to the user's system with the privileges of the Thunderbird process.
6.  Attacker escalates privileges, if necessary, to gain a higher level of control over the system.
7.  Attacker executes arbitrary commands to install malware, exfiltrate sensitive data, or perform other malicious actions.
8.  The attacker achieves their objective, such as data theft, system compromise, or establishing a persistent foothold.

## Impact

Successful exploitation of these vulnerabilities could have severe consequences. An attacker could remotely execute arbitrary code, potentially leading to full system compromise. Sensitive data stored within Thunderbird, such as emails, contacts, and passwords, could be exposed. The security policy bypass could allow attackers to perform actions that are normally restricted, further compromising the system's security. This can lead to significant financial losses, reputational damage, and legal liabilities for affected organizations.

## Recommendation

*   Immediately upgrade Mozilla Thunderbird to version 150.0.1 or later, or Thunderbird ESR to version 140.10.1 or later, to patch the vulnerabilities described in Mozilla security advisories mfsa2026-38 and mfsa2026-39.
*   Deploy the Sigma rule "Detect Thunderbird Spawning Suspicious Processes" to identify potential exploitation attempts via unusual child processes.
*   Monitor process creation events for Thunderbird spawning command interpreters or script engines using the Sigma rule "Detect Thunderbird Running External Commands".
*   Review and harden email security policies to prevent the delivery of malicious emails that could exploit these vulnerabilities.
