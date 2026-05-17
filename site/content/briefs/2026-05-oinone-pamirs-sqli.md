---
title: Oinone Pamirs SQL Injection Vulnerability (CVE-2026-8734)
slug: 2026-05-oinone-pamirs-sqli
description: Oinone Pamirs up to version 7.2.0 is vulnerable to SQL injection in the RSQLToSQLNodeConnector.makeVariable function of the queryListByWrapper Interface, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-05-17T06:16:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql injection
  - cve-2026-8734
  - web application
vendors:
  - Oinone
products:
  - Pamirs (<= 7.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-8734
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8734
  - https://github.com/SourByte05/SourByte-Lab/issues/12
  - https://vuldb.com/submit/809886
  - https://vuldb.com/vuln/364322
  - https://vuldb.com/vuln/364322/cti
rules:
  - title: Detect CVE-2026-8734 Exploitation — SQL Injection in Oinone Pamirs
    description: Detects CVE-2026-8734 exploitation — suspicious HTTP requests containing SQL injection attempts targeting the queryListByWrapper interface.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1505.001
    data_sources:
      - webserver
  - title: Detect Potential SQL Injection via Suspicious Characters
    description: Detects potential SQL injection attempts through the presence of special characters and keywords commonly used in SQL injection payloads.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1505.001
    data_sources:
      - webserver
rules_count: 2
---

Oinone Pamirs, up to version 7.2.0, is susceptible to SQL injection (CVE-2026-8734) within the `RSQLToSQLNodeConnector.makeVariable` function of the `queryListByWrapper` interface. This vulnerability enables a remote attacker to inject and execute arbitrary SQL commands by manipulating input to this function.  The vulnerability has a CVSS v3.1 base score of 7.3, indicating a high severity. Public exploits targeting this flaw have been disclosed, increasing the risk of exploitation. The vendor was notified of the vulnerability but did not respond.

## Attack Chain

1.  An attacker identifies an Oinone Pamirs instance running a version equal to or below 7.2.0 with the vulnerable `queryListByWrapper` interface exposed.
2.  The attacker crafts a malicious HTTP request targeting the `queryListByWrapper` interface.
3.  The request includes specially crafted input designed to inject SQL commands into the `RSQLToSQLNodeConnector.makeVariable` function.
4.  The application processes the malicious input without proper sanitization.
5.  The injected SQL commands are executed against the underlying database.
6.  The attacker gains unauthorized access to sensitive data stored in the database.
7.  The attacker may modify or delete data, potentially leading to data corruption or denial of service.
8.  The attacker could potentially use the database as a pivot point to compromise other systems on the network.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-8734) can lead to unauthorized access to sensitive information, data manipulation, and potential compromise of the underlying database server. Given the presence of publicly available exploits, organizations using vulnerable versions of Oinone Pamirs are at significant risk. The impact could range from data breaches and financial loss to reputational damage and disruption of services.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to mitigate SQL injection vulnerabilities, referencing CWE-89.
*   Deploy the Sigma rule `Detect CVE-2026-8734 Exploitation — SQL Injection in Oinone Pamirs` to identify potential exploitation attempts.
*   Monitor web server logs for suspicious requests targeting the `queryListByWrapper` interface (logsource: webserver).
*   Review and restrict database access privileges to minimize the impact of potential SQL injection attacks.
