---
brief_id: brief-2026-11-07-alchemycms-auth-bypass
event_id: brief-2026-11-07-alchemycms-auth-bypass
revision: 1
activity_at: "2026-11-07T12:48:51Z"
title: 'AlchemyCMS: Navigation data disclosure via missing authorization (CVE-2026-86777)'
slug: 2026-11-alchemycms-auth-bypass
description: An authorization vulnerability in AlchemyCMS allows unauthenticated attackers to retrieve sensitive navigation node data through the /api/nodes endpoint, facilitating information gathering.
date: "2026-11-07T12:48:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - cpe:2.3:a:alchemycms:alchemy_cms:*:*:*:*:*:*:*:*
vendors:
  - AlchemyCMS
products:
  - AlchemyCMS (< 7.4.16, 8.x < 8.3.6)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Unauthenticated navigation data disclosure in AlchemyCMS via the /api/nodes endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-86777
    cvss: 5.3
    epss: 0.0056
    kev_status: "false"
references:
  - https://github.com/AlchemyCMS/alchemy_cms/security/advisories/GHSA-wppq-8h64-w78r
  - https://sploitus.com/exploit?id=71F07999-5E1B-5D54-9690-849A898A817C
  - https://sploitus.com/exploit?id=71F07999-5E1B-5D54-9690-849A898A817C&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-86777 Exploitation - Unauthenticated Access to /api/nodes
    description: Detects unauthorized HTTP GET requests to the /api/nodes endpoint which may indicate exploitation of CVE-2026-86777.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch AlchemyCMS to version 7.4.16 or 8.3.6
      owner: IT Operations
      due: 48h
      evidence: Remediation section of the advisory
  hunt_leads:
    - lead: Identify excessive 200 OK responses to /api/nodes from unknown or external IP addresses
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The API endpoint facilitates reconnaissance by exposing navigation structure.
  mitigation_plan:
    - priority: immediate
      action: Apply access controls to /api/nodes to require authentication
      owner: IT Operations
      addresses: CVE-2026-86777
      evidence: Missing authorization is the root cause of the vulnerability
---

CVE-2026-86777 is a missing authorization vulnerability (CWE-862) in AlchemyCMS. The issue resides in the /api/nodes endpoint, which fails to properly enforce authorization checks, allowing unauthenticated users to access navigation node information. This can result in the exposure of restricted or unpublished page metadata, site structures, and internal navigation URLs.

## Impact
Successful exploitation allows unauthenticated attackers to perform reconnaissance by retrieving navigation structures, multilingual site hierarchies, and names or URLs of unpublished pages, which may provide sensitive context for further targeting.

## Recommendation
- Upgrade AlchemyCMS instances to version 7.4.16 or 8.3.6 immediately to resolve the missing authorization flaw.
- Implement access controls or network-level restrictions on the /api/nodes endpoint if immediate patching is not possible.
