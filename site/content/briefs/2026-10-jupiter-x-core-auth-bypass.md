---
brief_id: brief-2026-10-28-jupiter-x-core-auth-bypass
event_id: brief-2026-10-28-jupiter-x-core-auth-bypass
revision: 1
activity_at: "2026-10-28T04:39:36Z"
title: 'Jupiter X Core: Authentication bypass via Twitter/X Social Login (CVE-2026-106013)'
slug: 2026-10-jupiter-x-core-auth-bypass
description: The Jupiter X Core WordPress plugin contains an authentication bypass vulnerability (CVE-2026-106013) that allows unauthenticated attackers to hijack administrative accounts by exploiting a flaw in the OAuth callback handling for X (formerly Twitter) social login.
date: "2026-10-28T04:39:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:artbees:jupiter_x_core:*:*:*:*:*:wordpress:*:*
vendors:
  - Artbees
products:
  - Jupiter X Core (<= 4.61.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can leverage this logic flaw to gain unauthorized administrative access to the WordPress site.
    confidence_band: high
cves:
  - id: CVE-2026-106013
    cvss: 9.8
    kev_status: "false"
references:
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/1ad42de2-9ed1-4cf6-a031-22789be4cbe2
  - https://plugins.trac.wordpress.org/changeset/3759312/jupiterx-core/trunk/includes/extensions/raven/includes/modules/forms/classes/social-login-handler/twitter.php
  - https://sploitus.com/exploit?id=CVE-2026-106013&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-106013 Exploitation - Twitter Callback Authentication
    description: Detects potential exploitation attempts of CVE-2026-106013 by monitoring HTTP requests to the WordPress Twitter/X social login callback endpoint
    platform: sigma
    severity: critical
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
    - action: Update Jupiter X Core to version > 4.61.0
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to and including 4.61.0
    - action: Disable Twitter/X Social Login if patching is delayed
      owner: IT Operations
      due: immediate
      evidence: Mitigation for unpatched systems
  hunt_leads:
    - lead: Search web server logs for high frequency of requests to the Twitter social login handler from a single source IP
      technique_id: T1190
      data_needed:
        - Web access logs (cs-uri-stem, c-ip)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation relies on manipulating the callback handler
  mitigation_plan:
    - priority: immediate
      action: Upgrade Jupiter X Core plugin to version 4.61.1 or higher
      owner: IT Operations
      addresses: CVE-2026-106013
      evidence: Fix for the logic error in verify_twitter_callback
---

CVE-2026-106013 is an authentication bypass vulnerability in the Jupiter X Core plugin for WordPress (versions up to and including 4.61.0). The vulnerability is located within the `verify_twitter_callback` function. During the OAuth callback process, the plugin fails to assign the visitor's obtained OAuth access token to the TwitterOAuth client after a successful token exchange. Consequently, the plugin performs a verification request using the site administrator's pre-configured X application credentials. The API returns the profile of the X application owner, and the plugin incorrectly uses that identity to authenticate a corresponding user within the WordPress site, typically resulting in administrative account takeover.

## Impact

Successful exploitation allows an unauthenticated attacker to gain unauthorized administrative access to the WordPress site. The attacker must target a site that has configured the "Twitter/X Social Login" feature within the Jupiter X Core plugin.

## Recommendation

* Immediately update the Jupiter X Core plugin to the latest available patched version.
* If an update is not immediately feasible, disable the "Twitter/X Social Login" functionality within the plugin settings to mitigate the risk of account takeover.
* Audit WordPress administrator logs for unexpected login events originating from the Twitter callback URL.
