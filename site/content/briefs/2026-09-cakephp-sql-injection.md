---
title: SQL Injection in CakePHP FunctionsBuilder
slug: 2026-09-cakephp-sql-injection
description: The CakePHP framework contains an SQL injection vulnerability in the FunctionsBuilder::jsonValue() method when using the Postgres driver, allowing unauthorized database command execution via user-controlled jsonPath input.
date: "2026-09-08T21:49:04Z"
lastmod: "2026-09-19T21:59:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cakephp:cakephp:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=7B4261CB-3017-55B1-BF94-54E3BFAE5905&utm_source=rss&utm_medium=rss
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - CakePHP
products:
  - cakephp (5.1.x, 5.2.x, 5.3.x)
  - database (5.1.x, 5.2.x, 5.3.x)
  - CakePHP (4.5.0-4.5.11, 4.6.0-4.6.4, 5.0.0-5.1.8, 5.2.0-5.2.13, 5.3.0-5.3.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The FunctionsBuilder::jsonValue() methods with the Postgres driver is vulnerable to SQL injection if user controlled data is supplied to the $jsonPath parameter.
    confidence_band: high
cves:
  - id: CVE-2026-77635
    epss: 0.00294
  - id: CVE-2026-77634
    epss: 0.00312
references:
  - https://github.com/advisories/GHSA-fxf7-vhh8-7vpq
  - https://github.com/advisories/GHSA-2qh5-382h-3jpc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77634
  - https://sploitus.com/exploit?id=7B4261CB-3017-55B1-BF94-54E3BFAE5905&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade CakePHP dependencies to versions 5.1.10, 5.2.15, or 5.3.7.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-77635 remediation requirements.
  mitigation_plan:
    - priority: immediate
      action: Validate user input before calling FunctionsBuilder::jsonValue().
      owner: Application Security
      addresses: CVE-2026-77635
      evidence: Source workaround recommendation.
updates:
  - at: "2026-09-08T21:53:09Z"
    level: L2
    summary: added coverage for CakePHP (4.5.0-4.5.11, 4.6.0-4.6.4, 5.0.0-5.1.8, 5.2.0-5.2.13, 5.3.0-5.3.6)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2qh5-382h-3jpc
  - at: "2026-09-19T21:59:20Z"
    level: L2
    summary: poc_available; added CVE-2026-77634
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=7B4261CB-3017-55B1-BF94-54E3BFAE5905&utm_source=rss&utm_medium=rss
---

The CakePHP framework contains a critical SQL injection vulnerability identified as CVE-2026-77635. The flaw exists within the `FunctionsBuilder::jsonValue($field, $jsonPath)` method specifically when utilizing the Postgres driver. Attackers can exploit this vulnerability by supplying malicious, user-controlled input to the `$jsonPath` parameter. Because the framework does not adequately sanitize this parameter before incorporating it into SQL queries sent to the PostgreSQL backend, an attacker can append arbitrary SQL commands, potentially leading to unauthorized data extraction, modification, or deletion within the database. The vulnerability affects versions 5.1.x, 5.2.x, and 5.3.x of the `cakephp/cakephp` and `cakephp/database` packages. 

## Impact

Successful exploitation of this vulnerability allows unauthenticated or authenticated attackers to perform unauthorized database operations, which may lead to full database compromise, exfiltration of sensitive application data, or remote code execution depending on the database configuration and permissions. All applications using the affected CakePHP versions with a PostgreSQL backend are at risk.

## Recommendation

Prioritized remediation steps include:

- Upgrade the `cakephp/cakephp` and `cakephp/database` packages to versions 5.1.10, 5.2.15, or 5.3.7 or later to address CVE-2026-77635.
- Audit application codebases for instances where user-supplied input is directly passed to the `$jsonPath` parameter of `FunctionsBuilder::jsonValue()`.
- Implement strict input validation and allowlisting for any data intended for database query parameters until patching can be completed.
- Review database query logs for unusual syntax, such as SQL comments, union operators, or concatenation patterns originating from web application controllers that interface with the affected methods.
