---
title: Unauthenticated SQL Injection in Chanjet CRM (CVE-2021-48008)
slug: 2026-09-chanjet-crm-sqli
description: Chanjet CRM contains an unauthenticated SQL injection vulnerability in the webservice endpoint, enabling remote attackers to extract sensitive data via the site_id parameter.
date: "2026-09-18T20:07:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:chanjet:crm:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sql-injection
  - cve-2021-48008
vendors:
  - Chanjet
products:
  - CRM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Chanjet CRM contains an unauthenticated SQL injection vulnerability that allows remote attackers to execute arbitrary SQL queries
    confidence_band: high
cves:
  - id: CVE-2021-48008
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-48008
rules:
  - title: Detects CVE-2021-48008 Exploitation - Unauthenticated SQL Injection in Chanjet CRM
    description: Detects exploitation attempts against the Chanjet CRM webservice endpoint via the site_id GET parameter using common SQL injection techniques
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
    - action: Deploy Sigma detection rule to monitor web server logs for CVE-2021-48008 exploitation patterns
      owner: Detection Engineering
      due: 24h
      evidence: Source document confirms observed exploitation
  hunt_leads:
    - lead: Search logs for historical attempts to access /webservice with SQL syntax in the site_id parameter
      technique_id: T1190
      data_needed:
        - Webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Shadowserver observed exploitation attempts in 2023
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate Chanjet CRM instances; implement WAF filtering for SQLi patterns
      owner: IT Operations
      addresses: CVE-2021-48008
      evidence: NVD vulnerability details
  gaps:
    - Need to verify if internal systems are running an affected version of Chanjet CRM
---

Chanjet CRM is affected by an unauthenticated SQL injection vulnerability identified as CVE-2021-48008. The flaw exists within the application's webservice endpoint, specifically due to improper handling of the 'site_id' GET parameter. An unauthenticated remote attacker can inject arbitrary SQL commands by manipulating this parameter, bypassing input sanitization to interact directly with the backend database. 

The vulnerability is categorized as a high-severity risk (CVSS v3.1 base score 7.5) because it does not require user authentication to trigger. Successful exploitation allows for UNION-based SQL injection, which can lead to the unauthorized extraction of sensitive information, such as user credentials, customer data, or configuration details. The Shadowserver Foundation reported observing exploitation attempts in the wild starting as early as October 18, 2023. Defenders should prioritize auditing web server logs for suspicious requests targeting the webservice endpoint with SQL-specific syntax.

## Impact

The vulnerability poses a significant risk to organizational confidentiality. If exploited, an attacker can conduct unauthorized queries against the application database, leading to the full exfiltration of stored business intelligence or personally identifiable information (PII). Given the public disclosure and observed in-the-wild activity, there is a high probability of automated exploitation by opportunistic threat actors scanning for vulnerable instances.

## Recommendation

- Audit web access logs for requests to the webservice endpoint containing SQL injection patterns such as 'UNION SELECT', 'ORDER BY', or common SQL comment markers.
- Implement strict input validation or parameterization on all GET and POST parameters within the Chanjet CRM webservice API.
- Patch affected Chanjet CRM instances to the latest vendor-supplied version to remediate the lack of input sanitization in the 'site_id' parameter.
- Use a Web Application Firewall (WAF) to block incoming requests containing classic SQL injection payloads directed at the 'site_id' parameter.
