---
title: Pre-Authentication Trust Boundary Vulnerability in Zyxel Social Login
slug: 2026-08-zyxel-captive-portal-bypass
description: A pre-authentication trust-boundary flaw in Zyxel network devices, tracked as CVE-2026-8508, allows unauthenticated attackers to bypass captive portal authentication via crafted POST requests to the social_login.cgi endpoint.
date: "2026-08-16T18:43:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Zyxel
products:
  - WAX650S
  - FWA7 Series
  - Security Router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-8508 is a pre-authentication trust-boundary flaw in Zyxel captive-portal social login.
    confidence_band: high
cves:
  - id: CVE-2026-8508
    cvss: 6.5
    epss: 0.00544
references:
  - https://sploitus.com/exploit?id=33D18165-2055-57DB-8186-A2F92B5C5BB5
rules:
  - title: Detect CVE-2026-8508 Exploitation Attempt - Unauthorized POST to social_login.cgi
    description: Detects potential exploitation attempts of CVE-2026-8508 by monitoring for unauthenticated POST requests to the social_login.cgi endpoint.
    platform: sigma
    severity: medium
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit Zyxel device fleet for vulnerable firmware versions.
      owner: IT Operations
      due: 48h
      evidence: Advisory lists 39 models across 3 categories.
  mitigation_plan:
    - priority: immediate
      action: Apply firmware patches provided by Zyxel for CVE-2026-8508.
      owner: IT Operations
      addresses: CVE-2026-8508
      evidence: Vendor advisory guidance.
---

CVE-2026-8508 is a pre-authentication trust-boundary vulnerability affecting the social_login.cgi component in Zyxel network devices. The vulnerability was identified during research into the WAX650S access point (V7.10(ABRM.4)C0), where the backend improperly trusted user-supplied fields, specifically the 'fb_user' parameter, submitted during the social login flow. An unauthenticated attacker can craft a POST request to '/cgi-bin/social_login.cgi' to trigger the issuance of a guest authentication cookie without performing the legitimate Facebook-side identity validation.

Zyxel released an advisory on August 4, 2026, confirming that the flaw impacts 39 models, including 36 access points, two FWA7 series devices, and one security router. The vulnerability enables an attacker with network adjacency to bypass captive portal restrictions, potentially granting unauthorized access to the network or services protected by the captive portal.

## Impact

Successful exploitation allows unauthenticated attackers with network adjacency to bypass captive portal authentication. This grants the attacker a valid guest authentication cookie, enabling unauthorized network access. The vulnerability affects 39 distinct Zyxel models, increasing the risk surface for enterprise and public-facing deployments utilizing Zyxel captive portal social login features.

## Recommendation

* Prioritize patching all affected Zyxel devices as identified in the manufacturer's August 4, 2026, advisory.
* Monitor logs for anomalous POST requests directed at '/cgi-bin/social_login.cgi' originating from the guest or public-facing network segments.
* Deploy network-level access control to restrict access to management and CGI interfaces from untrusted or public network interfaces.
* Verify firmware versions across the 36 affected access points, FWA7 series, and the impacted security router model.
