---
title: Unauthenticated SQL Injection in WooCommerce Lottery Plugin
slug: 2026-08-woocommerce-sqli
description: The WooCommerce Lottery plugin for WordPress is vulnerable to unauthenticated time-based SQL injection via the 'orderby' and 'order' GET parameters, allowing attackers to extract sensitive database information.
date: "2026-08-26T16:21:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - sqli
  - wordpress
vendors:
  - WordPress
products:
  - WooCommerce Lottery
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WooCommerce Lottery plugin for WordPress is vulnerable to an unauthenticated time-based SQL injection.
    confidence_band: high
cves:
  - id: CVE-2026-18884
    cvss: 7.5
    epss: 0.00414
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18884
rules:
  - title: Detect CVE-2026-18884 Exploitation - SQL Injection via orderby parameter
    description: Detects exploitation attempts against the WooCommerce Lottery plugin by identifying common time-based SQL injection markers within the orderby GET parameter.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update WooCommerce Lottery plugin to the latest version beyond 2.2.9
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18884 vulnerability report
  hunt_leads:
    - lead: Search logs for suspicious GET requests targeting 'orderby' or 'order' parameters
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source describes vulnerability in these parameters
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to sanitize or block requests with SQL keywords in query params
      owner: IT Operations
      addresses: CVE-2026-18884
      evidence: Source identifies SQLi vulnerability
---

The WooCommerce Lottery plugin for WordPress, in all versions up to and including 2.2.9, contains a critical security vulnerability identified as CVE-2026-18884. This flaw is a time-based SQL injection vulnerability originating from insufficient escaping and a lack of prepared statements within the plugin's code. Specifically, the 'orderby' and 'order' GET parameters are improperly sanitized before being used in SQL queries. An unauthenticated attacker can exploit this by injecting malicious SQL commands into these parameters, forcing the database to perform time-delayed operations. By measuring the response time of the web server, an attacker can incrementally infer and exfiltrate data from the underlying WordPress database, including sensitive user information, configuration data, or authentication tokens. Given the prevalence of WordPress and the nature of the WooCommerce ecosystem, this vulnerability poses a significant risk to the integrity and confidentiality of affected e-commerce environments.

## Attack Chain

1. Attacker performs reconnaissance to identify sites running the WooCommerce Lottery plugin.
2. Attacker crafts an HTTP GET request targeting a page utilizing the plugin's sorting functionality.
3. Attacker injects a time-based SQL payload (e.g., SLEEP() or BENCHMARK()) into the 'orderby' or 'order' query parameters.
4. The web server receives the request and processes the malicious parameter through the vulnerable plugin code.
5. The database executes the injected command, causing a measurable time delay in the server's response.
6. Attacker observes the response time variance to confirm the vulnerability and begins automated data exfiltration.
7. Attacker successfully extracts sensitive database tables, such as user credentials or customer transaction history.

## Impact

Successful exploitation allows unauthenticated attackers to bypass application-level authentication and interact directly with the WordPress backend database. Potential damage includes full exfiltration of customer records, PII, and administrative credentials, leading to site takeover or financial data theft.

## Recommendation

* Update the WooCommerce Lottery plugin to the latest version available beyond 2.2.9 immediately to remediate CVE-2026-18884.
* Monitor web server access logs for anomalous GET requests containing SQL syntax patterns such as 'ORDER BY', 'SLEEP', 'BENCHMARK', or case-conversion functions in the query string.
* Deploy a Web Application Firewall (WAF) to block requests containing SQL injection payloads targeting 'orderby' or 'order' parameters.
