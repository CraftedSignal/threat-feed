---
title: SQL Injection in SiYuan via /api/search/searchEmbedBlock
slug: 2026-08-siyuan-sqli
description: SiYuan versions 3.7.2 and earlier contain a critical SQL injection vulnerability in the /api/search/searchEmbedBlock endpoint, allowing unauthenticated or low-privileged users to execute stacked SQL queries and modify database content.
date: "2026-08-03T16:04:48Z"
lastmod: "2026-08-09T21:32:42Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=EFAE4382-8B52-52E8-B2F7-900D05C3A218&utm_source=rss&utm_medium=rss
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - SiYuan
  - B3log
products:
  - SiYuan (<= 3.7.2)
  - SiYuan (< 3.7.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SiYuan versions <= v3.7.2 expose the /api/search/searchEmbedBlock endpoint, which passes a client-supplied SQL statement verbatim.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Because the underlying driver executes stacked statements, an attacker can read and modify content.
    confidence_band: high
cves:
  - id: CVE-2026-69084
    cvss: 10
    epss: 0.0029
  - id: CVE-2026-69085
    cvss: 10
    epss: 0.0025
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69084
  - https://sploitus.com/exploit?id=EFAE4382-8B52-52E8-B2F7-900D05C3A218&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=EFAE4382-8B52-52E8-B2F7-900D05C3A218
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-69084 Exploitation - SQL Injection in /api/search/searchEmbedBlock
    description: Detects exploitation of CVE-2026-69084 by identifying suspicious SQL metacharacters or stacked query indicators in requests to the vulnerable searchEmbedBlock endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all instances of SiYuan to v3.7.3.
      owner: IT Operations
      due: 24h
      evidence: Fixed in v3.7.3.
  hunt_leads:
    - lead: Search logs for POST/GET requests to /api/search/searchEmbedBlock with SQL delimiters.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint exposes database to raw SQL input.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict authentication and block unauthorized access to the application API.
      owner: IT Operations
      addresses: CVE-2026-69084
      evidence: Endpoint is gated only by CheckAuth, making it reachable by anonymous users when publish authentication is disabled.
updates:
  - at: "2026-08-09T21:32:42Z"
    level: L2
    summary: poc_available; added CVE-2026-69085
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=EFAE4382-8B52-52E8-B2F7-900D05C3A218&utm_source=rss&utm_medium=rss
---

SiYuan versions v3.7.2 and earlier are affected by a critical SQL injection vulnerability identified as CVE-2026-69084. The application exposes the /api/search/searchEmbedBlock endpoint, which fails to sanitize client-supplied SQL statements before passing them to the main read-write siyuan.db database handle. The implementation does not enforce read-only or admin-level restrictions on this endpoint, and it improperly validates authorization via the CheckAuth function.

Consequently, the vulnerability is accessible to users with minimal privileges, such as those holding a 'RoleReader' token, or even to anonymous users if publish authentication is disabled. Because the underlying database driver supports stacked queries, an attacker can execute arbitrary SQL commands. This allows for unauthorized reading and modification of data stored in all unencrypted notebooks within the SiYuan environment. The issue is resolved in version v3.7.3.

## Impact

The successful exploitation of this vulnerability grants attackers the ability to read and modify sensitive content within unencrypted notebooks. Given the base CVSS score of 10.0, the impact is comprehensive regarding data integrity and confidentiality for the affected application instances. Any environment utilizing an outdated version of SiYuan, particularly those with enabled publish features, is at significant risk of unauthorized data manipulation.

## Recommendation

- Upgrade all SiYuan installations to version v3.7.3 or later immediately to patch CVE-2026-69084.
- Audit webserver access logs for POST or GET requests targeting the /api/search/searchEmbedBlock path, specifically looking for anomalous query parameters containing SQL syntax (e.g., semicolons, 'DROP', 'UPDATE', 'UNION').
- Ensure that publish authentication is strictly enforced in any environment where SiYuan is exposed to a network.
- Monitor for unauthorized database modifications that deviate from standard user activity logs.
