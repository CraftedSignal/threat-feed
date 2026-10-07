---
title: Hardcoded Default Administrative Password in Homer
slug: 2026-10-homer-hardcoded-credentials
description: Fresh deployments of Homer use a hardcoded default password for the admin account, allowing unauthenticated remote attackers to gain full administrative access via CVE-2026-62252.
date: "2026-10-07T16:57:01Z"
lastmod: "2026-10-07T16:57:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:sipcapture:homer-app:*:*:*:*:*:*:*:*
tags:
  - cve-2026-62252
  - authentication
  - web-application
  - authentication-bypass
  - cve-2026-62253
  - sipcapture
vendors:
  - sipcapture
products:
  - homer-app (< 0.0.0-20260625091610-b2e942031ff8)
  - homer-app (< 0.0.0-20260625093330-5e90809657c9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This vulnerability allows an unauthenticated remote attacker to gain full administrative access to any exposed, fresh Homer instance by authenticating with the default credentials.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: Any attacker who can reach a freshly deployed Homer instance gains immediate full administrative access using the publicly documented default password.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can read/write all configuration, users, database connections, and stored VoIP call data.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6xp5-7rcx-xfgx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62252
  - https://github.com/advisories/GHSA-rqcc-94gv-wjm9
rules:
  - title: Detect CVE-2026-62252 Exploitation - Authentication with Default Credentials
    description: Detects unauthorized attempts to authenticate to Homer using the default 'admin'/'sipcapture' credentials.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
  - title: Detect Unauthenticated Access to Homer Admin API
    description: Detects unauthorized attempts to access protected Homer administrative endpoints (CVE-2026-62253)
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Homer to version 0.0.0-20260625091610-b2e942031ff8 or later.
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version 0.0.0-20260625091610-b2e942031ff8 as the fix.
  hunt_leads:
    - lead: Identify all internet-exposed Homer instances.
      technique_id: T1078
      data_needed:
        - External network scan results
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Any exposed instance is vulnerable to immediate takeover.
  mitigation_plan:
    - priority: immediate
      action: Patch to 0.0.0-20260625091610-b2e942031ff8.
      owner: IT Operations
      addresses: CVE-2026-62252
      evidence: Official fix version provided in advisory.
updates:
  - at: "2026-10-07T16:57:19Z"
    level: L2
    summary: 'added detection rule: Detect Unauthenticated Access to Homer Admin API'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-rqcc-94gv-wjm9
---

Homer versions prior to 0.0.0-20260625091610-b2e942031ff8 contain a critical vulnerability (CVE-2026-62252) involving the use of hardcoded credentials. During the bootstrap process of a fresh deployment configured with internal authentication, the application automatically initializes an 'admin' account using a hardcoded SHA-256 hash that corresponds to the plaintext password 'sipcapture'. 

The application lacks a first-login forced-password-change mechanism or any restrictive policy to prevent immediate unauthorized access. An attacker who can reach the login endpoint of a freshly deployed instance can perform a simple authentication request to obtain an administrative JSON Web Token (JWT). This vulnerability (CWE-798) grants the attacker full administrative control over the capture server, enabling them to manipulate packet capture settings, access sensitive session data, or further compromise the underlying host.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable Homer instances over the network.
2. Attacker probes the endpoint '/api/v3/auth' to confirm the Homer instance is using internal authentication.
3. Attacker sends a POST request to '/api/v3/auth' with the username 'admin' and password 'sipcapture'.
4. The application validates the password against the hardcoded `DefaultInternalAuthPasswordHash` and returns an administrative JWT.
5. Attacker utilizes the returned token in the 'Authorization' header of subsequent requests.
6. Attacker calls '/api/v3/users' or other administrative APIs to manage users or access stored packet capture data.
7. Attacker maintains administrative persistence by modifying system configurations or creating new administrative accounts.

## Impact

Successful exploitation results in full administrative compromise of the Homer application. Attackers can view sensitive metadata and session traffic, export captured data, or modify system configurations. Any organization running a fresh instance of Homer that has not been patched or manually secured is at risk of immediate takeover.

## Recommendation

Prioritized actions for security teams:
- Immediately upgrade all Homer deployments to version 0.0.0-20260625091610-b2e942031ff8 or later to remediate CVE-2026-62252.
- Scan perimeter-facing web infrastructure for HTTP traffic directed at /api/v3/auth, focusing on requests using the default 'admin' username.
- Deploy the webserver-category Sigma rule below to detect and block unauthorized authentication attempts.
- Audit existing Homer installations for administrative users created shortly after deployment to ensure password rotation has been enforced.
