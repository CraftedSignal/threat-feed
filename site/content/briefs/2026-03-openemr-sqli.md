---
brief_id: brief-2026-03-26-openemr-sqli
event_id: brief-2026-03-26-openemr-sqli
revision: 1
activity_at: "2026-03-26T12:00:00Z"
title: OpenEMR SQL Injection Vulnerability (CVE-2026-33910)
slug: 2026-03-openemr-sqli
description: OpenEMR versions up to 8.0.0.2 are vulnerable to SQL injection in the patient selection feature, which can be exploited by authenticated attackers due to insufficient input validation, potentially leading to unauthorized data access and modification.
date: "2026-03-26T12:00:00Z"
lastmod: "2026-10-16T00:05:57Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
tags:
  - sqli
  - openemr
  - cve-2026-33910
  - healthcare
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.0.0.3)
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
cves:
  - id: CVE-2026-33910
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33910
  - https://github.com/openemr/openemr/commit/73db3264aed253684532839380cae3b0a56c83d2
  - https://github.com/openemr/openemr/releases/tag/v8_0_0_3
  - https://github.com/openemr/openemr/security/advisories/GHSA-x32c-xj5g-7jx7
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CHRISSUB08-CVE-2026-33910_SQLINJECTIONVULNERABILITYOPENEMR8.0.0.2&utm_source=rss&utm_medium=rss
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
updates:
  - at: "2026-10-16T00:05:57Z"
    level: L1
    summary: new product
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CHRISSUB08-CVE-2026-33910_SQLINJECTIONVULNERABILITYOPENEMR8.0.0.2&utm_source=rss&utm_medium=rss
---

OpenEMR, a widely-used open-source electronic health records and medical practice management application, is vulnerable to SQL injection. Specifically, versions up to and including 8.0.0.2 contain a flaw in the patient selection feature (CVE-2026-33910). Authenticated attackers with valid user credentials can exploit this vulnerability due to insufficient input validation. Successful exploitation allows attackers to execute arbitrary SQL queries, potentially leading to unauthorized access, modification, or deletion of sensitive patient data. OpenEMR version 8.0.0.3 addresses this vulnerability with a patch. This vulnerability poses a significant risk to healthcare providers and their patients, potentially leading to data breaches, compliance violations, and reputational damage.

## Attack Chain

1. An attacker gains valid credentials for an OpenEMR user account.
2. The attacker logs into the OpenEMR application.
3. The attacker navigates to the patient selection feature within the application.
4. The attacker crafts a malicious SQL query and injects it into the input fields of the patient selection form.
5. The application executes the attacker-controlled SQL query against the database.
6. The attacker retrieves sensitive patient data, such as personal information, medical history, and insurance details.
7. The attacker modifies patient records, potentially altering medical diagnoses or treatment plans.
8. The attacker exfiltrates the stolen data or uses it for malicious purposes, like identity theft or fraud.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-33910) could result in a significant data breach, potentially affecting thousands of patients. The healthcare sector is a prime target for cyberattacks due to the sensitive nature of the data it holds. A successful attack could lead to regulatory fines, legal action, and a loss of trust from patients and the community. The impact includes unauthorized access to Electronic Health Records (EHR), potential modification of medical information, and exfiltration of Protected Health Information (PHI).

## Recommendation

*   Immediately upgrade all OpenEMR installations to version 8.0.0.3 or later to patch the SQL injection vulnerability (CVE-2026-33910).
*   Deploy the Sigma rules provided in this brief to detect potential exploitation attempts against the patient selection feature.
*   Implement input validation and sanitization measures for all user-supplied data within the OpenEMR application to prevent future SQL injection vulnerabilities.
*   Review and enforce strong authentication and authorization policies for all OpenEMR user accounts.
