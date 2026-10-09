---
title: Vikunja Broken Access Control and Privilege Escalation via Link Share
slug: 2026-10-vikunja-privilege-escalation
description: A broken access control vulnerability in Vikunja allows read-only project members to retrieve sensitive link-share hashes and escalate their privileges to the permission level of those shares.
date: "2026-10-09T21:25:02Z"
lastmod: "2026-10-09T21:25:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vikunja:api:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - access-control
  - web-application
  - authentication-bypass
  - oidc
  - identity-takeover
  - vulnerability
vendors:
  - Vikunja
products:
  - Vikunja API (<= 2.5.0)
  - Vikunja API (>= 1.0.0, <= 2.3.0)
  - Vikunja API (= 2.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A read-only member can therefore mint a write- or admin-level token for the project and perform writes they are not entitled to.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The vulnerability allows an attacker to gain unauthorized access to a local account via the OIDC authentication flow.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: A narrowly scoped API token with only oauth.authorize can be converted into normal session credentials for the same user.
    confidence_band: high
cves:
  - id: CVE-2026-91985
    cvss: 7.5
    epss: 0.00432
references:
  - https://github.com/advisories/GHSA-qfwc-vx6f-3g6g
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91985
  - https://github.com/advisories/GHSA-xv7q-fvmc-jx96
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62367
  - https://github.com/advisories/GHSA-v3p6-34mc-hj7v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57458
rules:
  - title: Detect Exploitation of CVE-2026-57458 - OAuth Token Minting via Scoped API Key
    description: Detects the specific sequence of initiating an OAuth authorization flow using a scoped API token, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1550.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Vikunja API to 2.6.0 or later
      owner: IT Operations
      addresses: CVE-2026-91985
      evidence: Source advisory recommends upgrading to resolve the broken access control.
updates:
  - at: "2026-10-09T21:25:20Z"
    level: L1
    summary: added coverage for Vikunja API (>= 1.0.0, <= 2.3.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-xv7q-fvmc-jx96
  - at: "2026-10-09T21:25:51Z"
    level: L2
    summary: 'added detection rule: Detect Exploitation of CVE-2026-57458 - OAuth Token Minting via Scoped API Key'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-v3p6-34mc-hj7v
---

Vikunja API versions up to and including 2.5.0 contain a broken access control vulnerability (CVE-2026-91985) that allows authenticated read-only project members to escalate privileges. The vulnerability exists in the single-share read endpoints for both v1 and v2 APIs. While these endpoints properly restrict access based on project read permissions, they incorrectly include the share's internal `hash` field in the response.

This `hash` is a bearer credential that can be used against the unauthenticated `POST /shares/{share}/auth` endpoint to obtain a JWT associated with the share's specific permission level (e.g., read-write or admin). Because these share IDs are small sequential integers, a read-only member can identify and query existing shares, extract the hashes, and generate tokens that bypass project-level member restrictions. This effectively allows an attacker to perform write or administrative actions for which they are not authorized, exceeding their intended read-only role.

## Attack Chain

1. Attacker is granted read-only access to a project by an owner.
2. Attacker enumerates available link shares for the project by guessing sequential share IDs.
3. Attacker sends an authenticated GET request to `/api/v1/projects/{project}/shares/{share}`.
4. The application returns the full share object, including the sensitive `hash` field, despite the attacker only having read-only permissions.
5. Attacker submits the intercepted `hash` to the unauthenticated `POST /api/v1/shares/{hash}/auth` endpoint.
6. The server validates the hash and returns a valid link-share JWT with the share's defined permission level (e.g., read-write).
7. Attacker uses the generated link-share JWT to perform unauthorized write operations against the project, bypassing their own user-level 403 restriction.

## Impact

The vulnerability results in unauthorized privilege escalation and information exposure (CWE-862, CWE-639, CWE-200). A read-only member can escalate their access to the level of any existing link share. If an admin-level link share exists, the attacker can manage project settings and other shares, even if they remain restricted from general user management. This compromises the integrity of project data and the security model of shared workspaces.

## Recommendation

Update the Vikunja API to the latest version (patch for CVE-2026-91985). If immediate patching is not possible, restrict the creation of link shares with elevated permissions for projects containing untrusted or read-only members. Detection teams should monitor for anomalous usage of link-share authentication endpoints or unusual patterns of access to share-read APIs by standard users.
