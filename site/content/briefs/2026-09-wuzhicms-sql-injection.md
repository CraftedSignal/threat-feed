---
title: SQL Injection Vulnerability in WuzhiCMS
slug: 2026-09-wuzhicms-sql-injection
description: WuzhiCMS versions up to 4.1.0 contain a SQL injection vulnerability in the article::getDataOfJson function, allowing remote attackers to execute arbitrary SQL commands via the title or master_table parameters.
date: "2026-09-15T17:42:41Z"
lastmod: "2026-09-16T15:52:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wuzhicms:wuzhicms:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-application
  - ssrf
  - web-vulnerability
vendors:
  - WuzhiCMS
products:
  - WuzhiCMS (<= 4.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument title/master_table leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-91848
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91848
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92380
rules:
  - title: Detects CVE-2026-91848 Exploitation - SQL Injection in WuzhiCMS
    description: Detects potential exploitation of CVE-2026-91848 by identifying SQL injection attempts in the title or master_table parameters of the article::getDataOfJson endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-92380 Exploitation - SSRF in WuzhiCMS Remote Image Fetch
    description: Detects exploitation of the SSRF vulnerability in WuzhiCMS by identifying POST requests to the index.php attachment handler containing the source[] parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rules or SIEM detections based on the provided Sigma rule to monitor for exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms public availability of exploit.
  mitigation_plan:
    - priority: medium_term
      action: Upgrade WuzhiCMS once a security patch is provided by the vendor.
      owner: IT Operations
      addresses: CVE-2026-91848
      evidence: NVD vulnerability report
updates:
  - at: "2026-09-16T15:52:07Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-92380 Exploitation - SSRF in WuzhiCMS Remote Image Fetch'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92380
---

A SQL injection vulnerability has been identified in WuzhiCMS in versions up to and including 4.1.0. The vulnerability resides within the article::getDataOfJson function, which is reachable via the endpoint /index.php?m=content&f=article&v=getDataOfJson. By manipulating the 'title' or 'master_table' arguments within an HTTP request, an unauthenticated remote attacker can inject arbitrary SQL commands. This flaw allows for potential unauthorized database access, including data exfiltration, modification, or deletion, depending on the privileges of the database user configured for the CMS. As of the disclosure date, the vulnerability is publicly documented with an available exploit, and the vendor has not yet addressed the issue. Organizations running affected WuzhiCMS instances should implement web application firewalls or similar controls to inspect incoming requests for SQL injection patterns targeting the specified endpoint.

## Impact

Successful exploitation of CVE-2026-91848 allows remote, unauthenticated attackers to perform SQL injection. This can lead to complete compromise of the WuzhiCMS database, including the theft of sensitive user credentials, content, or system configuration data. The impact is significant for organizations relying on WuzhiCMS as it provides a direct vector for data exfiltration or potential persistence within the application layer.

## Recommendation

- Deploy web application firewall (WAF) rules to inspect and filter incoming HTTP POST/GET requests to /index.php where the query parameters 'm=content', 'f=article', and 'v=getDataOfJson' are present, specifically monitoring the 'title' and 'master_table' fields for SQL injection payloads.
- Monitor web server logs for suspicious requests containing SQL keywords (e.g., SELECT, UNION, SLEEP, FROM) within the defined vulnerable parameters.
- If feasible, restrict access to the /index.php?m=content&f=article&v=getDataOfJson endpoint at the network or web server level until a patch is released by the vendor.
- Audit database user privileges used by the WuzhiCMS application to follow the principle of least privilege, limiting the potential impact of a successful injection attack.
