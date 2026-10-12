---
title: SQL Injection in Exponent CMS XML-RPC Component
slug: 2026-10-exponent-cms-sqli
description: Exponent CMS versions up to 3.0.2patch2 contain a SQL injection vulnerability in the userLogin function within xmlrpc.php that allows unauthenticated remote attackers to execute arbitrary SQL commands.
date: "2026-10-12T18:32:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:exponentcms:exponent_cms:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-application
  - cms
  - vulnerability
vendors:
  - Exponent CMS
products:
  - Exponent CMS (<= 3.0.2patch2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-108900
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108900
rules:
  - title: Detect CVE-2026-108900 Exploitation - SQL Injection in Exponent CMS XML-RPC
    description: Detects potential SQL injection attempts targeting the userLogin function in Exponent CMS via xmlrpc.php
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
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for exploitation attempts against xmlrpc.php
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms public exploit disclosure
  mitigation_plan:
    - priority: immediate
      action: Block or restrict access to xmlrpc.php via WAF or web server configuration
      owner: IT Operations
      addresses: CVE-2026-108900
      evidence: Source identifies xmlrpc.php as the vulnerable component
---

A critical security vulnerability has been identified in Exponent CMS versions up to 3.0.2patch2. The flaw exists within the userLogin function located in the xmlrpc.php file, which is part of the system's XML-RPC component. This vulnerability is classified as a SQL injection (SQLi) issue that can be triggered remotely by an unauthenticated attacker. The vulnerability stems from improper sanitization of input provided to the XML-RPC interface. Since a public exploit for this vulnerability exists and the vendor has not provided a patch, installations running affected versions are at high risk of database compromise, including unauthorized data exfiltration or potential administrative account takeover. Defenders should prioritize auditing web server access logs for anomalous traffic targeting xmlrpc.php and evaluate migrating or isolating instances of Exponent CMS.

## Impact

Successful exploitation of CVE-2026-108900 allows an unauthenticated remote attacker to execute arbitrary SQL commands against the underlying database. This could lead to full unauthorized access to sensitive application data, modification of user credentials, or database manipulation. The impact is severe, particularly as the vulnerability is publicly disclosed and likely being targeted by automated scanners or opportunistic threat actors.

## Recommendation

* Monitor web server logs for HTTP requests targeting the /xmlrpc.php endpoint, specifically looking for abnormal strings associated with SQL injection payloads (e.g., SELECT, UNION, WAITFOR, or sleep commands).
* If possible, restrict access to the xmlrpc.php file at the web server (Nginx/Apache) level or block the file entirely if XML-RPC functionality is not required for site operations.
* Audit web application logs to detect unauthorized calls to the userLogin function within the XML-RPC component.
* Since no vendor patch is currently available, evaluate if the CMS instance can be migrated to a secure platform or placed behind a Web Application Firewall (WAF) with specific rulesets designed to block SQL injection attempts.
