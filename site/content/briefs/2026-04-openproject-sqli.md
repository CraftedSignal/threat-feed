---
title: OpenProject SQL Injection Vulnerability (CVE-2026-34717)
slug: 2026-04-openproject-sqli
description: OpenProject versions before 17.2.3 are susceptible to SQL injection due to improper input sanitization in the '=n' operator, potentially allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-02T18:16:33Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - openproject
  - sqli
  - cve-2026-34717
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34717
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34717
  - https://github.com/opf/openproject/releases/tag/v17.2.3
  - https://github.com/opf/openproject/security/advisories/GHSA-5rrm-6qmq-2364
rules:
  - title: Detect OpenProject SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting OpenProject instances by identifying suspicious patterns in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenProject Version Check via HTTP Request
    description: Detects requests to common OpenProject version check files.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenProject, a web-based project management software, is vulnerable to SQL injection in versions prior to 17.2.3. The vulnerability lies within the `=n` operator located in `modules/reporting/lib/report/operator.rb:177`. This operator improperly handles user input by directly embedding it into SQL WHERE clauses without adequate parameterization. An attacker could leverage this flaw to inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion. The vulnerability was reported on April 2, 2026, and patched in version 17.2.3. Organizations using vulnerable versions of OpenProject are at risk of data breaches and system compromise.

## Attack Chain

1.  An attacker identifies an OpenProject instance running a version prior to 17.2.3.
2.  The attacker crafts a malicious HTTP request targeting an endpoint that utilizes the vulnerable `=n` operator within the `modules/reporting/lib/report/operator.rb` file.
3.  The malicious request injects SQL code through a parameter processed by the vulnerable operator.
4.  The OpenProject application executes the attacker-controlled SQL code against the database due to the lack of input sanitization.
5.  The attacker bypasses authentication or authorization checks by manipulating the SQL query.
6.  The attacker retrieves sensitive data from the database, such as user credentials or project information.
7.  The attacker may modify data within the database, potentially altering project configurations or injecting malicious content.
8.  The attacker achieves complete database compromise, potentially leading to a full system takeover if database privileges are sufficient.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to significant data breaches, potentially exposing sensitive project data, user credentials, and confidential information. The impact ranges from unauthorized data access and modification to complete database compromise. Depending on the database privileges, this could lead to full system takeover. Organizations in various sectors utilizing vulnerable versions of OpenProject could be affected, resulting in financial losses, reputational damage, and legal liabilities. The CVSS v3.1 base score for this vulnerability is 9.9 (Critical).

## Recommendation

*   Upgrade OpenProject instances to version 17.2.3 or later to patch the SQL injection vulnerability (CVE-2026-34717).
*   Monitor web server logs for suspicious HTTP requests targeting the vulnerable endpoint (`modules/reporting/lib/report/operator.rb`) that contain SQL injection attempts. Deploy the provided Sigma rule `Detect OpenProject SQL Injection Attempt` to detect potential exploitation.
*   Implement a web application firewall (WAF) to filter out malicious requests and prevent SQL injection attacks.
*   Review and harden database access controls to minimize the impact of potential SQL injection attacks.
*   Enable and monitor audit logs for database activity to detect any unauthorized data access or modification.
