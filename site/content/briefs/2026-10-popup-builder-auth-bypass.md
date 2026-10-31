---
brief_id: brief-2026-10-31-popup-builder-auth-bypass
event_id: brief-2026-10-31-popup-builder-auth-bypass
revision: 1
activity_at: "2026-10-31T07:51:10Z"
title: 'Popup Builder: Authorization bypass and arbitrary popup deletion (CVE-2026-89270)'
slug: 2026-10-popup-builder-auth-bypass
description: The Popup Builder WordPress plugin contains an authorization bypass vulnerability (CVE-2026-89270) that allows unauthenticated attackers to bulk delete published popups via a crafted GET request.
date: "2026-10-31T07:51:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:sygnoos:popup_builder:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - webserver
vendors:
  - Sygnoos
products:
  - Popup Builder (<= 4.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The vulnerability makes it possible for unauthenticated attackers to trash all published popups on the site with a single unauthenticated GET request.
    confidence_band: high
cves:
  - id: CVE-2026-89270
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89270
rules:
  - title: Detect CVE-2026-89270 Exploitation - Unauthenticated Popup Trashing
    description: Detects exploitation of CVE-2026-89270 by monitoring for GET requests containing the sg_popup_preview_id parameter targeting the plugin functionality.
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
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Popup Builder to the version addressing CVE-2026-89270
      owner: IT Operations
      due: 24h
      evidence: Plugin is vulnerable in all versions up to 4.4.5.
  hunt_leads:
    - lead: Search for unexpected GET requests containing sg_popup_preview_id in web access logs
      technique_id: T1190
      data_needed:
        - Web server access logs (uri_query)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit involves an unauthenticated GET request containing the sg_popup_preview_id parameter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Popup Builder plugin to version > 4.4.5
      owner: IT Operations
      addresses: CVE-2026-89270
      evidence: Vulnerability affects versions up to 4.4.5.
---

The Popup Builder plugin for WordPress (versions 4.4.5 and below) is affected by an authorization bypass vulnerability. The plugin fails to verify user authorization, enabling unauthenticated attackers to perform administrative actions. A secondary flaw in the 'SGPopup::find()' method causes the system to erroneously select all published popups when the 'sg_popup_preview_id' parameter is provided, resulting in the deletion of all site popups simultaneously.

## Impact
Successful exploitation results in the unauthorized mass deletion of all published popups on the affected WordPress site, leading to potential service disruption and loss of marketing content.

## Recommendation
- Update the Popup Builder plugin to the latest secure version immediately.
- Review WordPress access logs for anomalous GET requests containing the 'sg_popup_preview_id' parameter.
- If the patch cannot be applied immediately, restrict access to the WordPress administrative interface and plugin-specific endpoints.
