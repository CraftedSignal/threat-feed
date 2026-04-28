---
title: Firebird FB3 Client Library Information Leak (CVE-2025-65104)
slug: 2026-04-firebird-xsqlda-leak
description: Firebird FB3 client library incorrectly handles data lengths when communicating with FB4+ servers, leading to an information leak exploitable by a local attacker.
date: "2026-04-17T18:16:30Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - cve-2025-65104
  - information-leak
  - firebird
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
cves:
  - id: CVE-2025-65104
    cvss: 7.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-65104
  - https://github.com/FirebirdSQL/firebird/releases/tag/v4.0.0
  - https://github.com/FirebirdSQL/firebird/security/advisories/GHSA-mfpr-9886-xjhg
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Firebird Client Process Creation
    description: Detects the creation of a Firebird client process, which may indicate exploitation attempts related to CVE-2025-65104.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Linux Firebird Client Process Creation
    description: Detects the creation of a Firebird client process, which may indicate exploitation attempts related to CVE-2025-65104.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2025-65104 describes an information leak vulnerability affecting the Firebird open-source relational database management system. The vulnerability exists within the FB3 versions of the client library. When an FB3 client communicates with a Firebird FB4 or higher server, the client library incorrectly places data length values into the XSQLDA (SQL Data Area) fields. This incorrect handling of data lengths can result in an information leak, potentially exposing sensitive data to an attacker with local access. The vulnerability was reported in April 2026. The recommended solution is to upgrade the client library to FB4 or a later version. This vulnerability is significant because it could allow unauthorized access to sensitive information stored within the Firebird database.

## Attack Chain

1.  Attacker gains local access to a system with a Firebird FB3 client library installed.
2.  Attacker identifies a Firebird FB4 or higher server to target.
3.  Attacker crafts a malicious SQL query or uses an existing application to interact with the server.
4.  The FB3 client library processes the query and prepares the XSQLDA structure.
5.  Due to the vulnerability, the FB3 client library places incorrect data length values into the XSQLDA fields.
6.  The server responds with data, and the client uses the incorrect length values to interpret the response.
7.  The attacker leverages the incorrect data length values to extract more data than intended, leading to an information leak.
8.  The attacker exfiltrates the leaked information.

## Impact

Successful exploitation of CVE-2025-65104 results in an information leak. An attacker with local access can potentially extract sensitive data from a Firebird database server. While the exact impact depends on the data stored, it could include user credentials, financial data, or other confidential information. This could lead to further compromise of systems and data. The vulnerability exists because of incorrect data length calculations when FB3 clients communicate with FB4+ servers, which highlights the importance of maintaining up-to-date client libraries.

## Recommendation

*   Upgrade all Firebird client libraries to version FB4 or higher to remediate CVE-2025-65104 as recommended by the vendor.
*   Monitor network connections and process creations involving `fbclient.dll` or `libfbclient.so` (depending on the OS) to detect suspicious activity related to Firebird database interactions.
*   Implement the Sigma rule provided below to detect suspicious process execution related to Firebird clients.
