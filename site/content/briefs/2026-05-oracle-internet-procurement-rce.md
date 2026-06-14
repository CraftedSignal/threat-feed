---
title: 'CVE-2026-46819: Oracle Internet Procurement Connector Unauthenticated Remote Code Execution'
slug: 2026-05-oracle-internet-procurement-rce
description: CVE-2026-46819 is a critical vulnerability in Oracle Internet Procurement Connector versions 12.2.3-12.2.15 that allows an unauthenticated attacker with network access via HTTP to compromise the system, leading to unauthorized data access, modification, or deletion.
date: "2026-05-28T21:17:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - rce
  - oracle
vendors:
  - Oracle
products:
  - Internet Procurement Connector
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-46819
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46819
  - CVE-2026-46819
rules:
  - title: Detects CVE-2026-46819 Exploitation Attempts - Oracle Internet Procurement Connector Unauthenticated Access
    description: Detects CVE-2026-46819 exploitation attempts by identifying HTTP requests to Oracle Internet Procurement Connector that bypass authentication.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-46819 Exploitation - Unauthorized Data Modification
    description: Detects CVE-2026-46819 exploitation by monitoring for attempts to modify critical data within the Oracle Internet Procurement Connector via HTTP.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-46819 is a critical vulnerability within the Internal Operations component of Oracle Internet Procurement Connector, a part of Oracle E-Business Suite. The vulnerability affects supported versions 12.2.3 through 12.2.15. This easily exploitable flaw allows an unauthenticated attacker with network access via HTTP to compromise the Oracle Internet Procurement Connector. Successful exploitation can lead to unauthorized creation, deletion, or modification of critical data, as well as unauthorized access to sensitive information. This poses a significant risk to organizations using the affected versions of Oracle E-Business Suite.

## Attack Chain

1.  The attacker identifies a vulnerable Oracle Internet Procurement Connector instance accessible via HTTP.
2.  The attacker sends a specially crafted HTTP request to the vulnerable Internal Operations component.
3.  The crafted request exploits the lack of authentication and authorization checks.
4.  The vulnerability allows the attacker to bypass security controls.
5.  The attacker gains unauthorized access to the Oracle Internet Procurement Connector's data.
6.  The attacker creates, modifies, or deletes critical data within the system.
7.  The attacker exfiltrates sensitive data from the Oracle Internet Procurement Connector.
8.  The attacker achieves complete compromise of the Oracle Internet Procurement Connector, potentially impacting other connected systems.

## Impact

Successful exploitation of CVE-2026-46819 can result in unauthorized creation, deletion, or modification of critical data, as well as unauthorized access to sensitive information. The vulnerability has a CVSS 3.1 base score of 9.1, indicating a critical impact on confidentiality and integrity. This could lead to significant financial losses, reputational damage, and regulatory fines for affected organizations. The lack of authentication required for exploitation makes this vulnerability particularly dangerous.

## Recommendation

*   Apply the security patches provided by Oracle to address CVE-2026-46819 on all affected Oracle Internet Procurement Connector instances (versions 12.2.3-12.2.15).
*   Deploy the Sigma rule to detect potential exploitation attempts against the Internal Operations component of Oracle Internet Procurement Connector.
*   Monitor HTTP traffic to Oracle Internet Procurement Connector instances for suspicious patterns and unauthorized access attempts.
*   Implement network segmentation to limit the potential impact of a successful exploitation of CVE-2026-46819.
