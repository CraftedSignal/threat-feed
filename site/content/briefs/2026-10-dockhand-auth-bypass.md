---
title: Authentication Bypass in Dockhand via Static Extension Path Traversal
slug: 2026-10-dockhand-auth-bypass
description: Dockhand versions prior to 1.0.45 allow unauthenticated remote attackers to perform full account takeover by exploiting an authentication bypass flaw in the global hook that incorrectly permits requests ending in static extensions.
date: "2026-10-13T20:38:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:dockhand:dockhand:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - api-vulnerability
  - account-takeover
  - cve-2026-110130
vendors:
  - Dockhand
products:
  - Dockhand (< 1.0.45)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Unauthenticated remote attackers can send a PUT request to /api/users/<id>.js to reset the admin's or any user's password and take over the account.
    confidence_band: high
cves:
  - id: CVE-2026-110130
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110130
rules:
  - title: Detect CVE-2026-110130 Exploitation - Unauthorized PUT Request to User API
    description: Detects exploitation of CVE-2026-110130 by identifying unauthenticated PUT requests to the user API that use a .js extension to bypass authentication
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Dockhand to version 1.0.45 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure states version 1.0.45 contains the fix
  hunt_leads:
    - lead: Search web logs for PUT requests to /api/users/ matching the .js extension pattern
      technique_id: T1550
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies /api/users/<id>.js as the exploitation vector
  mitigation_plan:
    - priority: immediate
      action: Upgrade Dockhand to 1.0.45
      owner: IT Operations
      addresses: CVE-2026-110130
      evidence: Patch available in 1.0.45
---

Dockhand versions prior to 1.0.45 are affected by a critical authentication bypass vulnerability (CVE-2026-110130) located in the global authentication hook mechanism. The vulnerability stems from an insecure implementation where the application skips authentication checks for any HTTP request path ending in a static-asset extension, such as .js. 

Defenders must note that this bypass extends to the /api/* routing namespace. Because the user-mutation handlers in these versions fail open for unauthenticated callers, an attacker can craft a PUT request to specific API endpoints by appending a static extension (e.g., /api/users/&lt;id>.js). This allows unauthenticated remote actors to interact with sensitive user-management functions, such as resetting the password for any account including administrative users, ultimately leading to total system compromise and account takeover.

## Impact

Successful exploitation results in full account takeover, including administrative access to the Dockhand platform. This enables unauthorized actors to manage system configurations, exfiltrate sensitive data, and perform destructive actions within the application environment. The severity is marked as critical (CVSS 10.0), given the ease of exploitation and the high level of access granted to an attacker.

## Recommendation

* Patch the application immediately by upgrading Dockhand to version 1.0.45 or later.
* Implement web application firewall (WAF) rules to inspect and block PUT requests to /api/users/ routes that contain file extensions in the URL path.
* Audit webserver and application logs for suspicious PUT requests targeting the /api/users/ endpoint, specifically those ending in .js extensions.
* Deploy the Sigma rules in this brief to detect anomalous API access patterns if direct patching is delayed.
