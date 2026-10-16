---
title: Authentication Bypass in ZKEACMS via JWT Forgery
slug: 2026-10-zkeacms-auth-bypass
description: ZKEACMS versions through 4.4 contain a hard-coded HMAC-SHA256 signing key in JwtBearerDefaults.cs, allowing unauthenticated attackers to forge JWT bearer tokens and bypass authentication.
date: "2026-10-16T18:47:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zkeacms:zkeacms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - jwt
  - cve-2026-111633
vendors:
  - ZKEACMS
products:
  - ZKEACMS (<= 4.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: ZKEACMS through 4.4 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge REST API JWT bearer tokens using a hard-coded HMAC-SHA256 signing key.
    confidence_band: high
cves:
  - id: CVE-2026-111633
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111633
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ZKEACMS to a version beyond 4.4 to remove the hard-coded signing key.
      owner: IT Operations
      due: 24h
      evidence: Source states ZKEACMS through 4.4 contains the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to REST API endpoints using WAF or firewall rules.
      owner: IT Operations
      addresses: CVE-2026-111633
      evidence: Source identifies API endpoints as the primary target for unauthorized access.
---

ZKEACMS versions up to 4.4 contain a critical security vulnerability involving a hard-coded HMAC-SHA256 signing key located within the JwtBearerDefaults.cs file. This flaw allows unauthenticated remote attackers to generate and sign their own JWT bearer tokens. By crafting a token with the 'Name' claim set to 'admin', an attacker can successfully bypass authentication controls when interacting with the application's REST API. Successful exploitation provides administrative-level access to the ApiAuthorize endpoints, which are protected by the JWT authentication mechanism. This access allows an attacker to perform unauthorized actions including the modification of articles and product listings, as well as the unauthorized extraction of user form submissions stored within the system. Given the nature of the hard-coded key, any instance of ZKEACMS up to version 4.4 is vulnerable if the application utilizes the default JWT authentication configuration.

## Impact

The exploitation of CVE-2026-111633 results in full authentication bypass and unauthorized administrative access to the ZKEACMS REST API. Impacted sectors include organizations using ZKEACMS for content management and e-commerce platforms. Successful exploitation allows for the compromise of site integrity through the unauthorized modification of content and products, as well as the compromise of data privacy through the exfiltration of sensitive form submissions. The ease of exploitation via the static hard-coded key poses a significant risk to the availability, integrity, and confidentiality of the targeted application data.

## Recommendation

1. Upgrade all ZKEACMS instances to a version later than 4.4 that remediates the use of hard-coded cryptographic keys.
2. If an immediate upgrade is not possible, disable the REST API or implement network-level access controls to restrict access to ApiAuthorize endpoints to trusted internal IP ranges.
3. Audit web server logs for high volumes of API requests containing JWT tokens that deviate from standard issued tokens or show unusual administrative activity from unrecognized sources.
4. Perform an integrity check on articles and product data to identify any unauthorized modifications potentially performed via the compromised API.
