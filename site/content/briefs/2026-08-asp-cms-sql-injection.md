---
title: SQL Injection Vulnerability in ASP-CMS commentList.asp
slug: 2026-08-asp-cms-sql-injection
description: An unauthenticated SQL injection vulnerability in the ASP-CMS commentList.asp endpoint allows remote attackers to bypass keyword filters and extract sensitive database contents via the id parameter.
date: "2026-08-13T18:56:36Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - ASP-CMS
products:
  - ASP-CMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ASP-CMS contains a SQL injection vulnerability in the commentList.asp endpoint that allows unauthenticated remote attackers to inject arbitrary SQL
    confidence_band: high
cves:
  - id: CVE-2019-25765
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25765
rules:
  - title: Detects CVE-2019-25765 Exploitation - SQL Injection via commentList.asp
    description: Detects exploitation attempts against the ASP-CMS commentList.asp endpoint by identifying suspicious SQL keywords or obfuscation patterns in the id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms active exploitation risk.
  hunt_leads:
    - lead: Search logs for access to /commentList.asp with suspicious query parameters.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Shadowserver observed exploitation.
  mitigation_plan:
    - priority: immediate
      action: Patch ASP-CMS or block access to the vulnerable endpoint via WAF.
      owner: IT Operations
      addresses: CVE-2019-25765
      evidence: High CVSS score and confirmed exploitation.
---

ASP-CMS contains a critical SQL injection vulnerability in the commentList.asp endpoint, identified as CVE-2019-25765. This flaw allows unauthenticated remote attackers to execute arbitrary SQL queries by manipulating the id parameter within GET requests. The vulnerability is significant because attackers can circumvent existing application-level keyword blocklists - used to prevent common SQL injection patterns - by interleaving specific strings, such as 'master', into prohibited SQL keywords. This obfuscation technique enables the successful extraction of sensitive database contents. The Shadowserver Foundation first observed exploitation of this vulnerability on October 18, 2023. Given the ease of exploitation via simple HTTP GET requests and the potential for unauthorized data exfiltration, organizations utilizing ASP-CMS must prioritize remediation.

## Attack Chain

1. Attacker performs reconnaissance to identify sites running ASP-CMS and target the commentList.asp script.
2. Attacker crafts a malicious HTTP GET request targeting the 'id' parameter.
3. Attacker uses SQL injection techniques, embedding obfuscated keywords (e.g., 'ma' + 'ster') to bypass internal blocklists.
4. The vulnerable commentList.asp endpoint processes the unsanitized 'id' parameter input.
5. The underlying database executes the injected SQL command.
6. Attacker observes application responses (or error messages) to confirm successful injection.
7. Attacker iterates requests to systematically dump table names, schemas, or sensitive records from the database.
8. Final objective is achieved: unauthorized exfiltration of sensitive database data.

## Impact

Successful exploitation allows unauthenticated attackers to perform arbitrary database queries against an ASP-CMS installation. This can lead to the full compromise of database contents, including user credentials, administrative configurations, and application data. Historically, this has resulted in data exfiltration incidents observed globally since October 2023.

## Recommendation

* Identify and audit all web servers hosting ASP-CMS for the presence of the vulnerable commentList.asp endpoint.
* Deploy the provided Sigma rule to web server access logs to detect potential SQL injection attempts targeting the id parameter.
* Patch or update the ASP-CMS installation to a version that implements proper parameter sanitization and parameterized queries.
* Apply a Web Application Firewall (WAF) rule to block requests where the 'id' parameter contains suspicious SQL patterns, specifically those attempting to bypass blocklists using obfuscation.
