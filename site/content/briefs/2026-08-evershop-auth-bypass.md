---
title: EverShop Unauthenticated Account Takeover via Improper Authorization
slug: 2026-08-evershop-auth-bypass
description: An improper authorization vulnerability in EverShop versions prior to 2.2.1 allows unauthenticated attackers to hijack customer accounts by exploiting an incorrectly configured API route.
date: "2026-08-20T23:21:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application
  - privilege-escalation
  - account-takeover
vendors:
  - EverShop
products:
  - EverShop (< 2.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: An unauthenticated request carrying a known customer uuid can therefore overwrite that customer's email address and password.
    confidence_band: high
cves:
  - id: CVE-2026-72843
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72843
rules:
  - title: Detects CVE-2026-72843 Exploitation - Unauthorized Account Update
    description: Detects HTTP POST requests to the EverShop updateCustomer API route which could indicate exploitation of the unauthenticated update vulnerability
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1565.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch EverShop to version 2.2.1
      owner: IT Operations
      due: 24h
      evidence: 'Version 2.2.1 changes the route to ''access'': ''private''.'
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /api/update-customer/ at the WAF level
      owner: IT Operations
      addresses: CVE-2026-72843
      evidence: Route is improperly configured as public
---

EverShop versions prior to 2.2.1 contain a critical authorization flaw in the customer update API route. The file `packages/evershop/src/modules/customer/api/updateCustomer/route.json` incorrectly declares the update route with "access": "public", which causes the administrative authentication middleware to skip validation entirely. Additionally, no session-based middleware exists to ensure the caller has authorization to modify the requested account.

The corresponding handler in `updateCustomer.js` retrieves customer records using a UUID provided in the URL path. It then performs unvalidated write operations on that record, including updating credentials and email addresses. Because the application fails to verify ownership of the record, an unauthenticated attacker who identifies a valid customer UUID - often discoverable through order confirmation emails or administrative interfaces - can overwrite account details and gain full control over any registered customer profile, effectively locking out the legitimate user.

## Attack Chain

1. Attacker harvests a target customer UUID from leaked sources such as order confirmation emails or exposed administrative logs.
2. Attacker crafts an unauthenticated HTTP POST request targeting the vulnerable `/api/update-customer/:uuid` endpoint.
3. The EverShop application receives the request, failing to trigger the administrative middleware due to the 'public' route configuration.
4. The `updateCustomer` handler executes, identifying the customer record associated with the supplied UUID in the URL path.
5. The application parses the malicious JSON body provided in the request, which contains updated email and password values.
6. The application performs a write operation to the database, overwriting the legitimate user's credentials with attacker-provided data.
7. The application returns a 200 OK response containing the modified customer record.
8. Attacker uses the updated credentials to log into the victim's account, completing the account takeover and denying access to the original owner.

## Impact

Successful exploitation allows for full unauthorized access to any user account within the EverShop instance. This leads to immediate account takeover, potential data exfiltration of customer information linked to the profile, and complete lockout of the legitimate owner. Given the 9.8 CVSS score and the ease of identifying UUIDs, this vulnerability poses a severe risk to any organization operating an internet-facing EverShop store.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Patch the EverShop installation to version 2.2.1 or later to enforce 'private' access on the updateCustomer route.
* Monitor webserver logs for unauthorized POST requests to `/api/update-customer/` that originate from unexpected IP addresses or occur without corresponding authentication headers.
* Audit administrative logs for unusual UUID enumeration patterns or high volumes of profile update requests originating from single source IPs.
* Deploy the provided Sigma rule to webserver logs to identify potential exploitation attempts.
