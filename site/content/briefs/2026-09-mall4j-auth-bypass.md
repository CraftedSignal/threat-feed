---
title: Authentication Bypass in mall4j via Password Reset Endpoint
slug: 2026-09-mall4j-auth-bypass
description: An unauthenticated remote code execution vulnerability in mall4j through 4.0 allows attackers to reset arbitrary storefront passwords via the PUT /user/updatePwd endpoint.
date: "2026-09-29T00:23:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mall4j:mall4j:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve-2026-102361
vendors:
  - mall4j
products:
  - mall4j (<= 4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The endpoint allows unauthenticated attackers to reset any storefront account password.
    confidence_band: high
cves:
  - id: CVE-2026-102361
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102361
rules:
  - title: Detects CVE-2026-102361 Exploitation - Unauthorized Password Reset Request
    description: Detects exploitation attempts against CVE-2026-102361 where unauthenticated users attempt to access the updatePwd endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web server access logs for any PUT requests to /user/updatePwd
      owner: SOC
      due: 24h
      evidence: Source document identifies the vulnerable endpoint
  mitigation_plan:
    - priority: immediate
      action: Upgrade mall4j to a version beyond 4.0 once available
      owner: IT Operations
      addresses: CVE-2026-102361
      evidence: Vulnerability affects versions through 4.0
---

The mall4j application up to version 4.0 contains a critical missing authentication vulnerability in the PUT /user/updatePwd API endpoint. This flaw allows an unauthenticated remote attacker to reset the password for any storefront account by sending a specially crafted request to the application. By supplying a target username in the JSON request body, the application fails to verify the current user's session or identity, directly overwriting the account password with a value provided by the attacker. This vulnerability enables immediate account takeover, granting unauthorized access to storefront order history, personal information, and administrative functionality associated with the compromised account. Organizations utilizing mall4j should verify their exposure and implement access controls or blocking rules for this specific API endpoint until patches are applied.

## Impact

Successful exploitation results in full account takeover of any storefront user, including administrative accounts. This leads to the exposure of sensitive customer data, order details, and potential financial fraud. The vulnerability affects all deployments of mall4j up to version 4.0, representing a high risk to e-commerce storefronts.

## Recommendation

* Prioritize updating all instances of mall4j to a patched version beyond 4.0 immediately.
* Monitor web application logs for unauthorized POST or PUT requests to the /user/updatePwd endpoint from external or unexpected internal IP addresses.
* Implement temporary ingress restrictions or WAF rules to block access to /user/updatePwd from unauthorized sources.
