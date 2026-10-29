---
brief_id: brief-2026-10-29-bricks-theme-auth-bypass
event_id: brief-2026-10-29-bricks-theme-auth-bypass
revision: 1
activity_at: "2026-10-29T23:07:57Z"
title: 'Bricks Theme: Unauthenticated data disclosure in REST API (CVE-2026-119325)'
slug: 2026-10-bricks-theme-auth-bypass
description: Bricks Theme versions 2.4 and earlier are vulnerable to an unauthenticated broken access control flaw allowing attackers to enumerate and disclose draft or unpublished post content via the load_popup_content REST endpoint.
date: "2026-10-29T23:07:57Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "3"
  rating: A3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Pending environment validation of the REST API endpoint.
cpes:
  - cpe:2.3:a:bricks:theme:*:*:*:*:*:*:*:*
vendors:
  - Bricks
products:
  - Bricks Theme (<= 2.4)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The vulnerability allows attackers to enumerate and disclose confidential content from any unpublished post on the site.
    confidence_band: high
cves:
  - id: CVE-2026-119325
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119325
rules:
  - title: Detects CVE-2026-119325 Exploitation - Unauthorized REST API Access to load_popup_content
    description: Detects potential exploitation of CVE-2026-119325 by monitoring for unauthenticated GET requests to the load_popup_content endpoint.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all WordPress sites to identify instances running Bricks Theme <= 2.4.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-119325 affects Bricks Theme <= 2.4.
  hunt_leads:
    - lead: Search web logs for high volumes of GET requests to /wp-json/bricks/v1/load_popup_content.
      technique_id: T1083
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker can enumerate popupId values to disclose confidential content.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Bricks Theme to the latest secure version once released.
      owner: IT Operations
      addresses: CVE-2026-119325
      evidence: Bricks Theme 2.4 and before is vulnerable.
---

Bricks Theme for WordPress, in versions 2.4 and earlier, contains a broken access control vulnerability in the 'load_popup_content' REST API endpoint. The vulnerability allows anonymous users to access content that should be restricted, specifically draft and unpublished pages. There is no validation of user capabilities or post status checks when processing the 'popupId' parameter.

## Attack Chain
1. Attacker interacts with the 'bricks_regenerate_query_nonce' action to obtain a valid public nonce.
2. Attacker makes an unauthenticated HTTP GET request to the '/wp-json/bricks/v1/load_popup_content' endpoint.
3. Attacker specifies a 'popupId' parameter in the query string.
4. Attacker systematically iterates or increments the 'popupId' value to request unauthorized content.
5. The application fails to perform authorization or status checks on the requested resource.
6. The application returns the content of the draft or unpublished post to the attacker.

## Impact
Unauthorized disclosure of draft, private, or unpublished website content, which may include sensitive information intended for internal review or future release.

## Recommendation
- Update Bricks Theme to a version later than 2.4 once a patch is released by the vendor.
- Implement access control monitoring on WordPress REST API endpoints to identify anomalous requests to 'load_popup_content'.
- Restrict access to the WordPress REST API for unauthenticated users if it is not required for site functionality.
