---
title: SQL Injection in Yot CMS Cookie Handler
slug: 2026-09-yot-cms-sqli
description: An unauthenticated remote SQL injection vulnerability in Yot CMS versions up to 3.3.1 allows attackers to execute arbitrary database commands via the Login function.
date: "2026-09-14T11:33:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yot:cms:*:*:*:*:*:*:*:*
vendors:
  - Yot
products:
  - Yot CMS (<= 3.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90708
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90708
rules:
  - title: Detects CVE-2026-90708 Exploitation - SQL Injection in Yot CMS
    description: Detects exploitation attempts against the Yot CMS Cookie Handler by looking for SQL injection syntax in the yot3_user or yot3_pass arguments.
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
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rule to block SQL injection characters in cookie arguments.
      owner: SOC
      due: 24h
      evidence: Source confirms remote SQL injection vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Identify affected Yot CMS installations and restrict access until an update is applied.
      owner: IT Operations
      addresses: CVE-2026-90708
      evidence: Vulnerability affects versions up to 3.3.1.
---

Yot CMS versions up to 3.3.1 are vulnerable to a SQL injection vulnerability (CVE-2026-90708) located in the Login function within the global.php file of the Cookie Handler component. The vulnerability arises from improper sanitization of the yot3_user and yot3_pass arguments. Attackers can trigger this vulnerability remotely by sending malicious HTTP requests containing SQL injection payloads to the application. Public exploit code for this vulnerability is available, increasing the risk of exploitation. Defenders should treat this as a high-priority risk for internet-facing installations of Yot CMS and consider implementation of input validation controls or upgrading the software if a patch is available.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Yot CMS instances.
2. Attacker locates the application login page or cookie handling logic.
3. Attacker crafts an HTTP request targeting the Login function in global.php.
4. Attacker inserts malicious SQL syntax into the yot3_user or yot3_pass cookie arguments.
5. The server-side application fails to sanitize these inputs and passes them to the database query.
6. The database executes the injected SQL commands, potentially leading to unauthorized data access, credential theft, or bypass of authentication.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to the backend database. This may lead to the exfiltration of sensitive information, including user credentials or session data, and in some configurations, could result in administrative account compromise or complete control over the CMS instance.

## Recommendation

1. Identify all instances of Yot CMS (<= 3.3.1) in your environment.
2. Implement a Web Application Firewall (WAF) rule to inspect and block HTTP requests containing SQL injection patterns directed at the Login function or global.php.
3. Monitor web server logs for anomalies in the 'yot3_user' or 'yot3_pass' parameters.
4. Coordinate with IT operations to patch or upgrade Yot CMS to a version beyond 3.3.1.
