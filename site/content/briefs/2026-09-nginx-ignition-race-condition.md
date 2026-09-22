---
title: Unauthenticated Admin Account Creation in nginx-ignition via TOCTOU Race Condition
slug: 2026-09-nginx-ignition-race-condition
description: An unauthenticated time-of-check to time-of-use (TOCTOU) race condition in the nginx-ignition onboarding API allows remote attackers to create administrative accounts on fresh or reset instances.
date: "2026-09-22T01:52:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lucasdillmann:nginx-ignition:*:*:*:*:*:*:*:*
tags:
  - webserver
  - authentication-bypass
  - race-condition
  - cve-2026-61628
vendors:
  - lucasdillmann
products:
  - nginx-ignition (< 0.0.0-20260621194639-0586b4e55ab)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker who can reach an instance in its pre-onboarding state can create an administrator account for themselves.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.002
    technique_name: 'Create Account: Domain Account'
    evidence: The race additionally allows minting multiple admin accounts from a single concurrent burst, aiding persistence/stealth.
    confidence_band: high
cves:
  - id: CVE-2026-61628
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-pxcx-fv34-x9p5
rules:
  - title: Detect Exploitation of CVE-2026-61628 - Multiple Onboarding Requests
    description: Detects a burst of POST requests to the onboarding finish endpoint within a short timeframe, which may indicate an attempt to exploit the TOCTOU race condition.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy Sigma rule to detect onboarding spikes
      owner: Detection Engineering
      due: 24h
      evidence: Source describes race condition exploitation via concurrent requests
  mitigation_plan:
    - priority: immediate
      action: Upgrade nginx-ignition to version 0.0.0-20260621194639-0586b4e55ab
      owner: IT Operations
      addresses: CVE-2026-61628
      evidence: Source identifies this version as the patch release
---

The nginx-ignition project, prior to version 0.0.0-20260621194639-0586b4e55ab, is vulnerable to an unauthenticated administrative account creation vulnerability (CVE-2026-61628). The vulnerability exists in the `POST /api/users/onboarding/finish` endpoint, which is explicitly registered as anonymous. The handler performs a check-then-act pattern (TOCTOU) to verify if the system onboarding process has already been completed. 

Because the application lacks an atomic guard, database-level unique constraint, or mutex between the state verification (`OnboardingCompleted`) and the account creation (`Save`), an unauthenticated remote attacker can exploit a race condition during the installation window. By sending concurrent requests, an attacker can bypass the intent of a single-admin setup and mint multiple administrative accounts, each returning a valid JWT with full ReadWrite permissions. This effectively grants an attacker full control over the nginx-ignition instance, including the ability to manage hosts, routes, and certificates, which can be further abused to facilitate SSRF or arbitrary command execution via the managed nginx server.

## Attack Chain

1. Attacker monitors for newly deployed or reset instances of nginx-ignition, identifiable via the onboarding status check endpoint.
2. Attacker prepares a series of concurrent HTTP POST requests to `/api/users/onboarding/finish` containing a malicious username and password.
3. The target instance receives the concurrent requests before the legitimate administrator completes the initial setup.
4. Each request passes the initial `OnboardingCompleted` check because the state has not been finalized yet.
5. The server proceeds to `Save` each request as a separate administrator user with full ReadWrite permissions.
6. The server returns valid administrative JWTs to the attacker for each successful registration.
7. Attacker uses a valid administrative JWT to gain full control over the nginx server configuration and system settings.

## Impact

Successful exploitation results in full administrative takeover of the nginx-ignition application. This allows an attacker to manipulate server configurations, redirect traffic, steal credentials, and potentially achieve arbitrary command execution on the underlying host. The TOCTOU race condition also facilitates the creation of multiple persistence accounts from a single concurrent burst, hindering incident response and remediation efforts.

## Recommendation

1. Upgrade nginx-ignition to version 0.0.0-20260621194639-0586b4e55ab or later to resolve CVE-2026-61628.
2. Implement atomic database constraints for user creation to prevent concurrent account registration in the onboarding handler.
3. Restrict network access to the onboarding API endpoints until the legitimate administrator completes the setup process.
4. Enable server-side logging for all requests to `/api/users/onboarding/finish` to monitor for anomalous bursts of POST requests.
