---
title: Authentication Bypass in open-wearables
slug: 2026-08-open-wearables-auth-bypass
description: An unauthenticated remote code execution vulnerability (CVE-2026-78154) in open-wearables versions 0.6.2 and earlier allows attackers to bypass authentication in the invitation code redemption endpoint.
date: "2026-08-24T01:40:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - cve-2026-78154
  - web-application-vulnerability
vendors:
  - the-momentum
products:
  - open-wearables (0.6.2)
cves:
  - id: CVE-2026-78154
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78154
  - https://github.com/the-momentum/open-wearables/issues/1274
rules:
  - title: Detect Exploitation of CVE-2026-78154 - Unauthorized Access to Invitation Endpoint
    description: Detects potential exploitation attempts by monitoring HTTP requests to the user invitation code redemption route.
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
    - action: Review infrastructure for open-wearables instances.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78154 vulnerability identification.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /api/routes/v1/user_invitation_code.py via WAF or internal network segmentation.
      owner: IT Operations
      addresses: CVE-2026-78154
      evidence: Source identification of vulnerable code path.
---

A vulnerability has been identified in the open-wearables application, specifically affecting versions up to and including 0.6.2. The flaw exists within the `redeem_invitation_code` function located in `backend/app/api/routes/v1/user_invitation_code.py`. An attacker can exploit this vulnerability by manipulating the `code` argument provided to the public invitation-code redemption endpoint. This action results in missing authentication, allowing unauthenticated remote parties to interact with critical functionality intended only for authorized users. The project maintainers have been notified via an issue report but have not provided a patch as of the reporting date. This vulnerability is classified as CWE-287 (Improper Authentication) and CWE-306 (Missing Authentication for Critical Function).

## Attack Chain

1. Attacker identifies a target running the open-wearables application (version 0.6.2 or earlier).
2. Attacker interacts with the web interface to identify the public invitation-code redemption endpoint.
3. Attacker crafts a malicious HTTP request targeting `backend/app/api/routes/v1/user_invitation_code.py`.
4. Attacker injects or manipulates the `code` parameter within the request to bypass intended verification logic.
5. The application fails to validate the identity of the requester due to the missing authentication check.
6. The backend processes the invitation code without requiring valid user credentials.
7. Attacker gains unauthorized access to the invitation redemption process or underlying account features.

## Impact

Successful exploitation of CVE-2026-78154 allows for unauthorized interaction with the invitation-code redemption endpoint. Given the nature of the vulnerability, this could lead to unauthorized account creation or access to features gated by invitation codes. Impacted sectors include any organization or individual utilizing the open-wearables platform for user management or registration.

## Recommendation

Prioritized actions for detection and remediation:
- Inventory all assets running open-wearables and verify current versioning.
- Implement access control lists (ACLs) or WAF rules to restrict traffic to the `/api/routes/v1/user_invitation_code.py` endpoint until a patch is available.
- Monitor webserver logs for unexpected high volumes of requests to the invitation redemption endpoint, specifically looking for anomalous `code` parameter values.
- Disable the public invitation-code redemption endpoint if not required for business operations.
