---
title: UI Misrepresentation Vulnerability in better-auth Device Authorization
slug: 2026-10-better-auth-ui-misrepresentation
description: The better-auth library's deviceAuthorization plugin fails to display client_id and scope information, enabling attackers to deceive authenticated users into authorizing malicious device codes.
date: "2026-10-12T18:37:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:better-auth:better-auth:*:*:*:*:*:*:*:*
tags:
  - web-application-security
  - authentication-bypass
  - cve-2026-109346
vendors:
  - better-auth
products:
  - better-auth (1.3.8-beta.3 to < 1.7.0-rc.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Attackers can start a device request via /device/code, trick signed-in users into approving the code, then redeem it at /device/token for a live session token.
    confidence_band: high
cves:
  - id: CVE-2026-109346
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109346
action_plan:
  priority: elevated
  owners:
    - Application Security
    - IT Operations
  immediate_actions:
    - action: Upgrade better-auth to 1.7.0-rc.3 or later
      owner: IT Operations
      due: 48h
      evidence: Source specifies 1.7.0-rc.3 as the fixed version
  mitigation_plan:
    - priority: immediate
      action: Upgrade better-auth to 1.7.0-rc.3 or later
      owner: IT Operations
      addresses: CVE-2026-109346
      evidence: NVD vulnerability details
---

The better-auth library, specifically versions 1.3.8-beta.3 through 1.6.x (prior to 1.7.0-rc.3), contains a UI misrepresentation vulnerability within its deviceAuthorization plugin. This flaw stems from the plugin's failure to include the requesting client_id and scope when rendering the device authorization prompt to the user. Consequently, a user is presented with an ambiguous request that lacks the context necessary to verify the legitimacy of the authorization attempt. An attacker can exploit this lack of transparency by initiating a malicious device code flow and tricking an already signed-in user into granting authorization. Once the user approves the request, the attacker can leverage the authorized code to obtain a valid session token via the /device/token endpoint, leading to unauthorized account access.

## Impact

Successful exploitation results in unauthorized account access and potential session hijacking. Because the attack relies on misleading an authenticated user, it can bypass standard security expectations regarding authorization prompts. The scope of impact is limited to applications using the vulnerable deviceAuthorization plugin within the identified version range of better-auth.

## Recommendation

1. Upgrade the better-auth dependency to version 1.7.0-rc.3 or later to remediate CVE-2026-109346.
2. Review application logs for anomalous spikes in authorization requests to the /device/code endpoint that do not correlate with legitimate user-driven workflows.
3. Audit device authorization workflows to ensure all relevant metadata, including client identification and requested scopes, is explicitly displayed to users prior to approval.
