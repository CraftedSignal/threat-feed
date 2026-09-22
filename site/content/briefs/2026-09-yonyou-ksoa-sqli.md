---
title: CVE-2026-94491 SQL Injection in Yonyou KSOA
slug: 2026-09-yonyou-ksoa-sqli
description: Yonyou KSOA 9.0 is vulnerable to unauthenticated remote SQL injection via the address argument in the /cardcase/search_list.jsp endpoint.
date: "2026-09-22T02:32:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yonyou:ksoa:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - Yonyou
products:
  - KSOA (9.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument address can lead to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-94491
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94491
rules:
  - title: Detects CVE-2026-94491 Exploitation - SQL Injection via search_list.jsp
    description: Detects exploitation attempts against Yonyou KSOA by identifying SQL injection payloads in the address parameter of the /cardcase/search_list.jsp endpoint.
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
    - action: Deploy WAF rule to block identified SQLi payloads against the vulnerable endpoint
      owner: SOC
      due: 24h
      evidence: CVE-2026-94491 publicly available exploit
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to /cardcase/search_list.jsp
      owner: IT Operations
      addresses: CVE-2026-94491
      evidence: Unauthenticated remote exploit capability
---

CVE-2026-94491 is a critical SQL injection vulnerability discovered in Yonyou KSOA 9.0. The vulnerability resides within the /cardcase/search_list.jsp file, where the address argument fails to properly sanitize user-supplied input. An unauthenticated remote attacker can leverage this flaw to inject arbitrary SQL commands, potentially leading to unauthorized data exfiltration or modification within the application database. Public proof-of-concept exploit code is currently available, significantly increasing the risk of exploitation. As of the current disclosure date, the vendor has not responded to vulnerability reports or issued a security patch, leaving deployments exposed. Defenders should restrict network access to the affected web application components and monitor logs for anomalous SQL syntax patterns associated with this specific URI.

## Impact

Successful exploitation of CVE-2026-94491 grants an attacker the ability to execute unauthorized database queries. This can lead to full compromise of the KSOA application database, resulting in the exfiltration of sensitive organizational data, manipulation of business records, or potential further compromise of the underlying server infrastructure if database permissions are misconfigured. Given the lack of a vendor patch, the impact remains elevated for all organizations utilizing Yonyou KSOA 9.0.

## Recommendation

* Monitor web server logs for requests to /cardcase/search_list.jsp containing SQL injection payloads within the address parameter.
* Implement Web Application Firewall (WAF) rules to block suspicious HTTP requests targeting the /cardcase/search_list.jsp endpoint with typical SQL injection indicators (e.g., UNION, SELECT, OR, SLEEP).
* Isolate the Yonyou KSOA application from the public internet if it does not require external access, or restrict access via IP whitelisting to known trusted networks.
* Engage with the vendor's support channels to pressure the release of an official security update.
