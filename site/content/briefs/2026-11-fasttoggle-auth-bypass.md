---
brief_id: brief-2026-11-06-fasttoggle-auth-bypass
event_id: brief-2026-11-06-fasttoggle-auth-bypass
revision: 1
activity_at: "2026-11-06T09:28:53Z"
title: 'Drupal Fasttoggle: Authorization bypass vulnerability (CVE-2026-118569)'
slug: 2026-11-fasttoggle-auth-bypass
description: The Fasttoggle module for Drupal contains an authorization bypass vulnerability (CVE-2026-118569) allowing authenticated users with the "use fasttoggle" permission to modify the publication status, promotion, or stickiness of arbitrary nodes and comments without appropriate access checks.
date: "2026-11-06T09:28:53Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:drupal:fasttoggle:*:*:*:*:*:*:*:*
vendors:
  - Drupal
products:
  - fasttoggle (< 4.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An account holding use fasttoggle... could publish, unpublish, promote or make sticky any node on the site
    confidence_band: high
cves:
  - id: CVE-2026-118569
    epss: 0.00138
    kev_status: "false"
references:
  - https://www.drupal.org/sa-contrib-2026-282
  - https://vulners.com/cve/CVE-2026-118569
  - https://sploitus.com/exploit?id=DF7B3EB8-42D9-5890-85B3-8D3147E6F963
  - https://sploitus.com/exploit?id=DF7B3EB8-42D9-5890-85B3-8D3147E6F963&utm_source=rss&utm_medium=rss
iocs:
  - type: hash_sha256
    value: 2e3d6fbb7f8e134e29058b615f041ad6f40d4149e9e825d3d13743ac9d55d75f
ioc_counts:
  hash_sha256: 1
rules:
  - title: Detect Exploitation of CVE-2026-118569 - Fasttoggle Authorization Bypass
    description: Detects attempts to access the fasttoggle controller endpoint with suspicious entity IDs or actions by non-privileged accounts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Drupal Fasttoggle module to 4.1.1
      owner: IT Operations
      due: 24h
      evidence: SA-CONTRIB-2026-282
  hunt_leads:
    - lead: Identify users with the "use fasttoggle" permission who have accessed the site recently
      technique_id: T1068
      data_needed:
        - Drupal user access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The module relies on this permission to enable the authorization bypass
---

The Fasttoggle module for Drupal contains an authorization bypass vulnerability (CVE-2026-118569) where the module controller fails to verify entity access before modifying content state. Any user possessing the "use fasttoggle" permission can manipulate the publication status, promotion, or stickiness of any node or comment on the Drupal site. The flaw also functions as an information oracle for node existence because requesting a non-existent entity ID returns a 400 status code. The vulnerability does not provide remote code execution, SQL injection, or site-wide administrative access, but it enables the unauthorized publication of internal drafts and comments.

## Attack Chain
1. Attacker authenticates as a low-privileged user possessing the "use fasttoggle" permission.
2. Attacker enumerates node IDs (nids) by sending requests to the `/fasttoggle/node/{nid}/{action}` endpoint.
3. Attacker identifies targets based on response codes (400 for non-existent IDs, 200 for existing nodes).
4. Attacker performs targeted HTTP POST/GET requests to the vulnerable endpoint.
5. The Fasttoggle controller loads the targeted entity without invoking `$node->access('update')`.
6. The controller flips the flag (e.g., status, promote, sticky) and saves the entity.
7. The target node or comment state is modified, making private drafts or comments publicly visible.

## Impact
Successful exploitation allows unauthorized users to publish internal drafts, approve their own comments, or manipulate the promotion and stickiness of content. These actions are not recorded in the Drupal revision history and lack logging within the 4.1.0 module version, preventing traditional audit trail identification.

## Recommendation
- Upgrade the Fasttoggle module to version 4.1.1 or later to implement missing entity access checks and CSRF protections.
- Audit existing "use fasttoggle" permissions for all user roles to restrict access to trusted editors only.
- Review Drupal site content for unexpected status changes or visibility of drafts.
