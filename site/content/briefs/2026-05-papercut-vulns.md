---
title: Multiple Vulnerabilities in PaperCut Allow Data Confidentiality Breach and Security Policy Bypass
slug: 2026-05-papercut-vulns
description: Multiple vulnerabilities in PaperCut Embedded App versions prior to 2.2.0 on Ricoh devices and PaperCut NG/MF versions prior to 25.0.11 allow attackers to compromise data confidentiality and bypass security policies, potentially leading to unauthorized access and control.
date: "2026-05-05T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - papercut
  - data-breach
  - security-bypass
vendors:
  - PaperCut
products:
  - PaperCut Embedded App
  - PaperCut NG/MF
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6180
  - id: CVE-2026-6418
  - id: CVE-2026-7824
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0533/
  - https://www.papercut.com/kb/Main/papercut-ng-mf-and-papercut-hive-security-bulletin-may-2026/
  - https://www.cve.org/CVERecord?id=CVE-2026-6180
  - https://www.cve.org/CVERecord?id=CVE-2026-6418
  - https://www.cve.org/CVERecord?id=CVE-2026-7824
rules:
  - title: Detect PaperCut NG/MF Unauthorized Access Attempt
    description: Detects attempts to exploit PaperCut NG/MF vulnerabilities by monitoring for suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PaperCut Ricoh Embedded App Unauthorized Access Attempt
    description: Detects attempts to exploit PaperCut Ricoh Embedded App vulnerabilities by monitoring for suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified in PaperCut, a print management software, posing significant risks to data confidentiality and security policy enforcement. Specifically, PaperCut Embedded App versions prior to 2.2.0 on Ricoh devices and PaperCut NG/MF versions prior to 25.0.11 are affected. Successful exploitation of these vulnerabilities could allow an attacker to gain unauthorized access to sensitive data, bypass security controls, and potentially compromise the entire print management system. The vulnerabilities were disclosed in a PaperCut security bulletin released on May 5, 2026. Defenders should apply the vendor-provided patches to mitigate these risks.

## Attack Chain

1. An attacker identifies a vulnerable PaperCut NG/MF server or PaperCut Embedded App on a Ricoh device.
2. The attacker exploits CVE-2026-6180, CVE-2026-6418 or CVE-2026-7824 to gain unauthorized access.
3. Upon successful exploitation, the attacker bypasses authentication mechanisms.
4. The attacker gains access to sensitive print job data, including documents and user information.
5. The attacker modifies security policies to escalate privileges.
6. The attacker gains control over print queues and system configurations.
7. The attacker can intercept, modify, or delete print jobs.
8. The attacker exfiltrates sensitive data.

## Impact

Successful exploitation of these vulnerabilities could lead to a significant breach of data confidentiality, allowing attackers to access sensitive documents and user information. The bypassing of security policies could lead to unauthorized access and control over the print management system. This could result in the compromise of sensitive data, disruption of printing services, and potential reputational damage for organizations using vulnerable versions of PaperCut.

## Recommendation

*   Immediately upgrade PaperCut NG/MF to version 25.0.11 or later to patch the identified vulnerabilities, as referenced in the PaperCut security bulletin.
*   Upgrade PaperCut Embedded App on Ricoh devices to version 2.2.0 or later.
*   Monitor web server logs for suspicious activity targeting PaperCut servers, focusing on HTTP requests associated with the exploitation of CVE-2026-6180, CVE-2026-6418, and CVE-2026-7824.
