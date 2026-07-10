---
title: Oracle PeopleSoft Enterprise PeopleTools Unauthorized Data Access Vulnerability (CVE-2026-34309)
slug: 2024-01-peoplesoft-rce
description: CVE-2026-34309 is an easily exploitable vulnerability in Oracle PeopleSoft Enterprise PeopleTools versions 8.61-8.62, allowing a low-privileged attacker with network access via HTTP to gain unauthorized access to create, delete, or modify sensitive data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - peoplesoft
  - rce
  - vulnerability
  - network
vendors:
  - Oracle
products:
  - PeopleSoft Enterprise PeopleTools
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34309
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34309
rules:
  - title: Detect Suspicious HTTP Request to PeopleSoft Enterprise PeopleTools
    description: Detects suspicious HTTP requests to PeopleSoft Enterprise PeopleTools that may indicate an attempt to exploit CVE-2026-34309.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PeopleSoft Enterprise PeopleTools Unauthorized Data Modification
    description: Detects unauthorized data modification in PeopleSoft Enterprise PeopleTools by monitoring specific HTTP requests and status codes.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-34309 is a critical vulnerability affecting Oracle PeopleSoft Enterprise PeopleTools versions 8.61 and 8.62. This vulnerability allows a low-privileged attacker with network access to the PeopleSoft application via HTTP to compromise the system. The vulnerability exists within the Security component of PeopleTools and, if successfully exploited, can lead to significant data breaches and integrity issues. An attacker could gain unauthorized access to create, delete, or modify critical data or gain complete access to all PeopleSoft Enterprise PeopleTools accessible data. Due to the ease of exploitation, defenders should prioritize patching and monitoring for potential exploitation attempts targeting this vulnerability.

## Attack Chain

1.  The attacker gains network access to the PeopleSoft Enterprise PeopleTools application.
2.  The attacker sends a crafted HTTP request targeting the vulnerable Security component.
3.  The vulnerable component processes the malicious request without proper authorization checks.
4.  The attacker gains unauthorized access to the PeopleSoft data.
5.  The attacker creates, modifies, or deletes critical data within the PeopleSoft system.
6.  The attacker accesses sensitive information, potentially including personally identifiable information (PII), financial records, or proprietary business data.
7.  The attacker may establish persistence through modification of system settings.

## Impact

Successful exploitation of CVE-2026-34309 can lead to significant data breaches, data corruption, and unauthorized modifications within PeopleSoft Enterprise PeopleTools. The vulnerability affects versions 8.61 and 8.62, potentially impacting a wide range of organizations using these versions. Consequences include financial loss, reputational damage, regulatory fines, and disruption of business operations. The CVSS score of 8.1 highlights the high potential for confidentiality and integrity impacts.

## Recommendation

*   Apply the patch provided by Oracle to address CVE-2026-34309 on all PeopleSoft Enterprise PeopleTools instances (reference: CVE-2026-34309).
*   Deploy the provided Sigma rule to detect suspicious HTTP requests targeting the PeopleSoft application and potentially exploiting CVE-2026-34309.
*   Monitor web server logs for unusual HTTP activity and error messages related to the Security component of PeopleSoft Enterprise PeopleTools to help identify potential exploitation attempts.
*   Review and enforce strict access control policies to limit the exposure of the PeopleSoft application to unauthorized users.
