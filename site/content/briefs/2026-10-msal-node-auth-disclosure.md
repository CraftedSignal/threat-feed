---
brief_id: brief-2026-10-24-msal-node-auth-disclosure
event_id: brief-2026-10-24-msal-node-auth-disclosure
revision: 1
activity_at: "2026-10-24T15:55:02Z"
title: 'Microsoft Authentication Library for Node.js: Information disclosure via origin validation error (CVE-2026-109461)'
slug: 2026-10-msal-node-auth-disclosure
description: An origin validation error in the msal-node library allows an attacker to intercept sensitive parameters during the authorization code flow, potentially leading to unauthorized information disclosure.
date: "2026-10-24T15:55:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against GHSA-xcx6-jx8p-x3h5
cpes:
  - cpe:2.3:a:microsoft:microsoft_authentication_library_for_node.js:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - cloud
  - web-application
  - supply-chain
vendors:
  - Microsoft
products:
  - msal-node (>= 5.0.0-beta.0, < 7.1.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Origin validation error in Microsoft Authentication Library (MSAL) for Node.js allows an unauthorized attacker to disclose information over a network.
    confidence_band: high
cves:
  - id: CVE-2026-109461
    cvss: 5.9
    epss: 0.00348
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-xcx6-jx8p-x3h5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109461
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-109461
action_plan:
  priority: elevated
  owners:
    - Application Security
    - IT Operations
  immediate_actions:
    - action: Upgrade @azure/msal-node to version 7.1.0 or later
      owner: IT Operations
      due: 48h
      evidence: Patches - Version 7.1.0 and higher are patched.
  hunt_leads:
    - lead: Identify applications running affected versions of @azure/msal-node in production environments
      technique_id: T1552
      data_needed:
        - Software Bill of Materials (SBOM) or dependency audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability affects msal-node >= 5.0.0-beta.0, < 7.1.0
  mitigation_plan:
    - priority: immediate
      action: Enforce validation of input parameters in acquireTokenByCode calls
      owner: Application Security
      addresses: CVE-2026-109461
      evidence: Workarounds - Ensure you pass in only the auth_code to acquireTokenByCode
---

CVE-2026-109461 is an origin validation error in the Microsoft Authentication Library (MSAL) for Node.js. The vulnerability exists within the library's authorization code flow, where improper verification of the communication source allows an unauthorized attacker to potentially disclose sensitive parameters to an attacker-controlled endpoint. The issue affects versions starting from 5.0.0-beta.0 up to, but not including, 7.1.0.

## Impact

Successful exploitation allows for the disclosure of sensitive information transmitted during the authorization code flow. The confidentiality of tokens or authorization parameters may be compromised if an attacker can induce the library to send data to an unauthorized endpoint.

## Recommendation

* Upgrade the `@azure/msal-node` package to version 7.1.0 or higher immediately.
* As a temporary mitigation, ensure that only the `auth_code` is passed to the `acquireTokenByCode` function in the application logic.
* Audit applications utilizing MSAL Node for authorization code flows to identify potential exposure points where the validation logic may be bypassed.
