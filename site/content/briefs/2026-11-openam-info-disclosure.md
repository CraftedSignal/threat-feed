---
brief_id: brief-2026-11-08-openam-info-disclosure
event_id: brief-2026-11-08-openam-info-disclosure
revision: 2
activity_at: "2026-11-08T07:19:03Z"
revision_history:
  - revision: 2
    at: "2026-11-08T07:19:03Z"
    checksum: sha256:abc1c9b0d313d17a10748796a8a6daed0e5d13327a6a66218bd7f15480637e1a
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-123551&utm_source=rss&utm_medium=rss
title: 'OpenAM: Unauthenticated information disclosure via Liberty ID-FF (CVE-2026-123551)'
slug: 2026-11-openam-info-disclosure
description: OpenAM versions 14.0.0 through 16.1.3 contain an information disclosure vulnerability that allows unauthenticated attackers to hijack sessions by capturing iPlanetDirectoryPro tokens via WebSocket endpoints.
date: "2026-11-08T06:55:29Z"
lastmod: "2026-11-08T07:18:26Z"
type: advisory
claim_state: <nil>
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:openam:openam:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-123551&utm_source=rss&utm_medium=rss
vendors:
  - OpenAM
products:
  - OpenAM (14.0.0 - 16.1.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can bypass the agent-only check through an unvalidated internal forward on legacy Liberty ID-FF endpoints.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550.002
    technique_name: Pass the Hash
    evidence: Attackers can ... collecting iPlanetDirectoryPro tokens to hijack user and administrator sessions.
    confidence_band: high
cves:
  - id: CVE-2026-123551
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123551
  - https://sploitus.com/exploit?id=CVE-2026-123551&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch OpenAM to version 16.1.4 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-123551 vulnerability in versions < 16.1.4
  hunt_leads:
    - lead: Identify unauthenticated requests to legacy Liberty ID-FF endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability involves unvalidated internal forward on legacy Liberty ID-FF endpoints.
  mitigation_plan:
    - priority: immediate
      action: Disable or restrict access to legacy Liberty ID-FF endpoints
      owner: IT Operations
      addresses: CVE-2026-123551
      evidence: Vulnerability is limited to legacy Liberty ID-FF endpoints.
updates:
  - at: "2026-11-08T07:18:26Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-123551&utm_source=rss&utm_medium=rss
---

OpenAM contains an information disclosure vulnerability (CVE-2026-123551) affecting versions 14.0.0 through 16.1.3. An unvalidated internal forward on legacy Liberty ID-FF endpoints allows unauthenticated attackers to bypass agent-only restrictions. Successful exploitation permits the retrieval of live iPlanetDirectoryPro session tokens through the notification WebSocket, enabling session hijacking of both standard users and administrators.

## Impact
Successful exploitation allows unauthenticated attackers to steal active session tokens. This leads to complete session hijacking, providing unauthorized access to the privileges and data associated with the compromised user or administrator account.

## Recommendation
- Upgrade OpenAM to version 16.1.4 or later to remediate the vulnerability.
- Implement access control lists at the web application firewall or load balancer layer to restrict access to legacy Liberty ID-FF endpoints.
- Audit WebSocket notification traffic for unauthorized or anomalous subscription requests.
