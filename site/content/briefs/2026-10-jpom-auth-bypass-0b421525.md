---
brief_id: brief-2026-10-31-jpom-auth-bypass-0b421525
event_id: brief-2026-10-31-jpom-auth-bypass-0b421525
revision: 3
activity_at: "2026-11-02T17:51:47Z"
revision_history:
  - revision: 2
    at: "2026-11-02T15:52:01Z"
    checksum: sha256:bfdd0fbc374589fe7a1cd29219b06b8bc7d4e97433a9f5882781693307ba6a2c
    summary: added coverage for Jpom (<= 2.11.12)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - qa_status
      - references
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120461
  - revision: 3
    at: "2026-11-02T17:51:47Z"
    checksum: sha256:f1803b0bf3c0b6f097ab4dae6fae1cc59a51bd3dd7a0d5019257f210381c725e
    summary: added coverage for Jpom (<= 2.11.12)
    changed_fields:
      - action_plan
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120460
title: 'Jpom: Authentication bypass and command execution (CVE-2026-120201)'
slug: 2026-10-jpom-auth-bypass-0b421525
description: Jpom versions 2.10.0 through 2.11.12 contain an authentication bypass vulnerability that allows unauthenticated attackers to gain super-administrator access and execute commands.
date: "2026-10-31T22:05:24Z"
lastmod: "2026-11-02T17:49:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Action plan derived from technical vulnerability description
cpes:
  - cpe:2.3:a:jpom:jpom:*:*:*:*:*:*:*:*
vendors:
  - Jpom
products:
  - Jpom (2.10.0 through 2.11.12)
  - Jpom (<= 2.11.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users with SSH command execute permission in one workspace can supply foreign template and node IDs to run commands on other workspaces SSH hosts.
    confidence_band: high
cves:
  - id: CVE-2026-120201
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-120461
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-120460
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120201
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120461
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120460
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Jpom to a version later than 2.11.12.
      owner: IT Operations
      due: 48h
      evidence: Jpom through 2.11.12 contains a cross-workspace authorization bypass vulnerability
  hunt_leads:
    - lead: Identify suspicious cross-workspace SSH command execution
      technique_id: T1068
      data_needed:
        - Jpom application access logs
        - Jpom audit logs for node/ssh_command/batch requests
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated users can supply foreign template and node IDs to run commands on other workspaces SSH hosts.
    - lead: Identify API requests involving Docker asset management where the user does not have administrative rights for the target workspace.
      technique_id: T1068
      data_needed:
        - Jpom application audit logs
        - API access logs
        - Docker management endpoint activity
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers... can control containers, images, volumes and networks... by supplying foreign Docker asset ids.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Jpom to the latest version after 2.11.12
      owner: IT Operations
      addresses: CVE-2026-120461
      evidence: Jpom through 2.11.12 contains a cross-workspace authorization bypass.
    - priority: immediate
      action: Upgrade Jpom to version 2.11.13 or higher.
      owner: IT Operations
      addresses: CVE-2026-120460
      evidence: Jpom through 2.11.12 contains a cross-workspace authorization bypass
updates:
  - at: "2026-11-02T15:51:25Z"
    level: L2
    summary: added coverage for Jpom (<= 2.11.12)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120461
  - at: "2026-11-02T17:49:28Z"
    level: L2
    summary: added coverage for Jpom (<= 2.11.12)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120460
---

Jpom versions 2.10.0 through 2.11.12 are vulnerable to an authentication bypass. Unauthenticated attackers can gain super-administrator access by injecting query conditions into the JPOM-USER-TOKEN header. By providing a value such as 'is not null', the underlying Hutool Condition parser processes the input as an operator. Once access is gained, attackers can execute commands using Jpom's script features.
