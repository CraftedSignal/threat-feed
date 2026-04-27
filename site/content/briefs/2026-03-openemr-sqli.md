---
title: OpenEMR SQL Injection Vulnerability (CVE-2026-33910)
slug: 2026-03-openemr-sqli
description: OpenEMR versions up to 8.0.0.2 are vulnerable to SQL injection in the patient selection feature, which can be exploited by authenticated attackers due to insufficient input validation, potentially leading to unauthorized data access and modification.
date: "2026-03-26T12:00:00Z"
severities:
  - high
tags:
  - sqli
  - openemr
  - cve-2026-33910
  - healthcare
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33910
  - https://github.com/openemr/openemr/commit/73db3264aed253684532839380cae3b0a56c83d2
  - https://github.com/openemr/openemr/releases/tag/v8_0_0_3
  - https://github.com/openemr/openemr/security/advisories/GHSA-x32c-xj5g-7jx7
ioc_counts:
  email: 1
rules:
  - title: Detect SQL Injection Attempts in OpenEMR Patient Selection
    description: Detects potential SQL injection attempts in OpenEMR patient selection based on suspicious characters and keywords in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect OpenEMR SQL Injection via POST Request
    description: Detects SQL injection attempts targeting OpenEMR by analyzing POST request data for common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenEMR, a widely-used open-source electronic health records and medical practice management application, is vulnerable to SQL injection. Specifically, versions up to and including 8.0.0.2 contain a flaw in the patient selection feature (CVE-2026-33910). Authenticated attackers with valid user credentials can exploit this vulnerability due to insufficient input validation. Successful exploitation allows attackers to execute arbitrary SQL queries, potentially leading to unauthorized access…
