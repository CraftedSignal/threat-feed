---
title: Erupt Framework SQL Injection Vulnerability (CVE-2026-4594)
slug: 2024-01-02-erupt-sql-injection
description: A SQL injection vulnerability (CVE-2026-4594) exists in erupts erupt up to version 1.13.3, allowing remote attackers to execute arbitrary SQL commands by manipulating the sort.field argument in the geneEruptHqlOrderBy function.
date: "2026-03-23T18:16:26Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - vulnerability
  - erupt
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4594
rules:
  - title: Detect SQL Injection Attempts in Erupt Framework via sort.field
    description: Detects potential SQL injection attempts in the Erupt framework by monitoring HTTP requests with suspicious SQL syntax in the sort.field parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Erupt Framework SQL Injection - Hibernate Specific Keywords
    description: Detects SQL injection attempts targeting Erupt framework by looking for hibernate specific keywords
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-4594, has been discovered in the erupts erupt framework, affecting versions up to 1.13.3. The vulnerability resides within the `geneEruptHqlOrderBy` function in the `erupt-data/erupt-jpa/src/main/java/xyz/erupt/jpa/dao/EruptJpaUtils.java` file. Attackers can remotely exploit this flaw by manipulating the `sort.field` argument, leading to arbitrary SQL command execution within the Hibernate framework. Public exploit code is available…
