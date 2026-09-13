---
title: Remote SQL Injection in Feng Office Legacy API
slug: 2026-09-feng-office-sqli
description: Feng Office versions up to 3.11.13.11 are susceptible to remote SQL injection via the 'auth' parameter in the Legacy API component.
date: "2026-09-13T05:24:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fengoffice:feng_office:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-application
  - vulnerability
vendors:
  - Fengoffice
products:
  - Feng Office (<= 3.11.13.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Such manipulation of the argument auth leads to sql injection. The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90495
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90495
rules:
  - title: Detect CVE-2026-90495 Exploitation - SQL Injection in Feng Office
    description: Detects potential SQL injection attempts targeting the Feng Office Legacy API 'auth' parameter.
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
    - action: Deploy WAF filter to monitor/block requests to Legacy API endpoint containing SQL metacharacters.
      owner: SOC
      due: 24h
      evidence: CVE-2026-90495 vulnerability description.
  mitigation_plan:
    - priority: immediate
      action: Restrict network exposure of the Feng Office Legacy API until a vendor patch is provided.
      owner: IT Operations
      addresses: CVE-2026-90495
      evidence: No official vendor patch response.
---

A critical SQL injection vulnerability exists in Feng Office versions up to 3.11.13.11, specifically affecting the 'findAll' function within 'application/models/CompanyWebsite.class.php'. This component, part of the Legacy API, fails to properly neutralize the 'auth' argument before incorporating it into database queries. Remote, unauthenticated attackers can exploit this flaw to inject arbitrary SQL commands, potentially leading to unauthorized data exfiltration, modification, or full compromise of the backend database. While public proof-of-concept exploits exist, the vendor has not responded to disclosure reports, leaving current installations at high risk. Detection engineers should focus on monitoring HTTP traffic for patterns associated with SQL injection attempts targeting the Legacy API endpoint.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass authentication controls and execute arbitrary SQL queries against the application database. This can lead to the exposure of sensitive organizational data, including contact information and internal records, as well as the potential for administrative account takeovers or database-level system modifications.

## Recommendation

1. Review web server logs for suspicious 'auth' parameter values containing SQL syntax characters (e.g., UNION, SELECT, --, ;) targeting the Legacy API path.
2. Implement WAF rules to sanitize or block input to the 'auth' parameter in the Legacy API module.
3. If patching is unavailable due to lack of vendor response, restrict network access to the Legacy API component using edge firewall controls.
