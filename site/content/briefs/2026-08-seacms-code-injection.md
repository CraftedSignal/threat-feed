---
title: Remote Code Injection in SeaCMS Template Engine
slug: 2026-08-seacms-code-injection
description: SeaCMS versions 13.6 and earlier contain a code injection vulnerability in the search.php file, allowing remote attackers to execute arbitrary code via the searchtype parameter.
date: "2026-08-31T03:13:38Z"
lastmod: "2026-08-31T03:13:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:seacms:seacms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - webserver
  - web-application-vulnerability
  - sql-injection
  - cve-2026-82600
vendors:
  - SeaCMS
products:
  - SeaCMS (<= 13.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This manipulation of the argument searchtype causes code injection.
    confidence_band: high
cves:
  - id: CVE-2026-82598
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82598
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82600
rules:
  - title: Detects CVE-2026-82600 Exploitation - SQL Injection in SeaCMS
    description: Detects potential SQL injection attempts against the SeaCMS /zyapi.php endpoint by monitoring the 'ids' parameter for common SQL injection patterns.
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
    - action: Inventory all servers running SeaCMS and restrict access to search.php
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82598 affects versions <= 13.6
  mitigation_plan:
    - priority: immediate
      action: Apply updates provided by SeaCMS or implement WAF filtering for the searchtype parameter
      owner: IT Operations
      addresses: CVE-2026-82598
      evidence: Source confirms code injection via searchtype argument
updates:
  - at: "2026-08-31T03:13:48Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-82600 Exploitation - SQL Injection in SeaCMS'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82600
---

SeaCMS versions up to 13.6 are vulnerable to a remote code injection vulnerability located within the Template Engine component. The flaw resides in the 'parseIf' function within the 'search.php' file. An unauthenticated remote attacker can exploit this by sending a crafted HTTP request that manipulates the 'searchtype' argument. Successful exploitation allows for the execution of arbitrary code on the underlying web server, potentially leading to full system compromise. This vulnerability has been publicly disclosed and is considered actively exploitable, posing a high risk to organizations utilizing this content management system. 

## Impact

Successful exploitation of CVE-2026-82598 allows an attacker to achieve remote code execution (RCE) on the host web server. This can lead to unauthorized data access, system disruption, modification of web content, or further movement into the internal network. Given the prevalence of CMS vulnerabilities, this flaw is likely to be targeted by automated scanners and automated exploit scripts.

## Recommendation

Prioritize the immediate remediation of all SeaCMS installations. If an official patch is available from the vendor, apply it immediately. If no patch is available, ensure the web application is behind a Web Application Firewall (WAF) configured to inspect HTTP parameters for malicious payloads.

* Identify and audit all web servers running SeaCMS 13.6 or earlier.
* Configure WAF rules to sanitize or block input to the 'searchtype' parameter in 'search.php' that contains suspicious characters or script tags.
* Monitor web server logs for suspicious POST requests targeting 'search.php' with unusual 'searchtype' parameters.
