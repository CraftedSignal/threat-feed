---
title: OAuth State CSRF Vulnerability in Hatchet
slug: 2026-09-hatchet-oauth-csrf
description: Hatchet versions before 0.91.1 contain an OAuth state CSRF vulnerability that allows unauthenticated attackers to hijack sessions by exploiting improper session state clearing during callback processing.
date: "2026-09-21T19:51:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hatchet:hatchet:*:*:*:*:*:*:*:*
vendors:
  - Hatchet
products:
  - Hatchet (< 0.91.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    evidence: The vulnerability allows an unauthenticated attacker to bind an already-authenticated victim's session cookie to an attacker-controlled OAuth identity.
    confidence_band: med
cves:
  - id: CVE-2026-61687
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-phg3-3g28-wq9v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61687
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Hatchet to version 0.91.1 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies fix in version 0.91.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Hatchet 0.91.1
      owner: IT Operations
      addresses: CVE-2026-61687
      evidence: Advisory recommends upgrade for affected versions
---

Hatchet versions v0.86.26 and earlier are susceptible to an OAuth state CSRF vulnerability, tracked as CVE-2026-61687. The issue resides in the `ValidateOAuthState` function, which handles the verification of the `state` parameter during OAuth callbacks. When an OAuth flow completes successfully, the application incorrectly clears the session-specific `oauth_state_<integration>` key by setting it to an empty string instead of removing the key from the session store. 

Because of this logic, subsequent requests containing an empty `state` parameter are incorrectly validated against the existing empty string value in the session. An attacker can exploit this to bind an already-authenticated victim's session cookie to an attacker-controlled OAuth identity. This leads to account fixation or full account takeover, depending on the application context. The vulnerability affects deployments utilizing Google, GitHub, or Slack integrations.

## Impact

The vulnerability allows an unauthenticated attacker to perform account takeover or session fixation against users who have previously performed an OAuth flow within their session. This affects any Hatchet deployment where OAuth integrations are enabled. Successful exploitation requires the victim to have an active session and the attacker to induce the victim to perform an action that triggers the flawed callback logic.

## Recommendation

* Upgrade all Hatchet deployments to version 0.91.1 or later to implement proper session state key removal.
* Audit application logs for abnormal OAuth callback patterns, specifically requests where the `state` parameter is absent or empty in conjunction with successful authentication events.
* Restrict OAuth callback endpoints to trusted domains and ensure that the `state` parameter is strictly validated for non-empty, cryptographically strong values.
