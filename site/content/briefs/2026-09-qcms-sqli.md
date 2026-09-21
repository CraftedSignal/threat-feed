---
title: SQL Injection Vulnerability in QCMS Content Detail Page
slug: 2026-09-qcms-sqli
description: QCMS versions up to 6.0.6 are vulnerable to remote SQL injection via the ID argument in the self_Tmp function, allowing attackers to execute arbitrary database commands.
date: "2026-09-21T02:25:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:qcms:qcms:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sqli
  - remote-code-execution
vendors:
  - QCMS
products:
  - QCMS (<= 6.0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
cves:
  - id: CVE-2026-94110
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94110
rules:
  - title: Detects CVE-2026-94110 Exploitation - SQL Injection in QCMS
    description: Detects potential SQL injection attempts targeting the ID parameter on the QCMS Content Detail Page, accounting for the lack of URL decoding by the router.
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
    - action: Deploy WAF rule to block suspicious SQL injection patterns
      owner: SOC
      due: 24h
      evidence: Exploit has been disclosed publicly
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate all public-facing instances of QCMS version 6.0.6 or earlier
      owner: IT Operations
      addresses: CVE-2026-94110
      evidence: Vulnerability affects QCMS up to 6.0.6
---

A critical SQL injection vulnerability has been identified in QCMS versions up to 6.0.6. The flaw resides in the self_Tmp function within the file Lib/Config/Controllers.php, which handles the Content Detail Page component. Attackers can exploit this via a remote, unauthenticated request by injecting malicious SQL code into the ID argument. 

Defenders should note that the QCMS router does not perform URL decoding on the incoming REQUEST_URI before routing occurs. Consequently, exploit payloads must be crafted using literal spaces rather than URL-encoded entities (like %20), as the latter are not interpreted correctly by the routing logic. This vulnerability was disclosed publicly, and given the lack of a vendor patch, organizations utilizing QCMS must implement compensating controls at the network perimeter or application firewall level to inspect and sanitize the ID parameter in incoming requests to the Content Detail Page.

## Impact

Successful exploitation allows remote attackers to execute arbitrary SQL commands against the backend database. This may lead to unauthorized data exfiltration, modification of application content, or potential full database compromise. As the vulnerability is publicly disclosed and exploitable remotely, the risk to public-facing QCMS deployments is high.

## Recommendation

* Deploy Web Application Firewall (WAF) rules to detect and block requests to the Content Detail Page containing SQL injection patterns in the ID parameter.
* Implement strict input validation for the ID parameter in the application front-end or via a reverse proxy to ensure it conforms to expected alphanumeric formats.
* Monitor web server access logs for anomalous requests containing literal space characters within query strings targeting the identified path.
