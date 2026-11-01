---
brief_id: brief-2026-11-01-gitea-archived-repo-bypass
event_id: brief-2026-11-01-gitea-archived-repo-bypass
revision: 1
activity_at: "2026-11-01T20:09:55Z"
title: 'Gitea: Archived repository metadata authorization bypass (CVE-2026-116296)'
slug: 2026-11-gitea-archived-repo-bypass
description: Gitea versions 28.2.0 and earlier fail to enforce archival read-only status on milestone, release, and label API routes, allowing write-collaborators to modify or delete sensitive project metadata.
date: "2026-11-01T20:09:55Z"
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
  - cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*
tags:
  - webserver
  - authorization-bypass
  - cve-2026-116296
vendors:
  - Gitea
products:
  - Gitea (<= v28.2.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Users with write-collaborator access to an archived repository could still create, modify, and delete milestones, releases, and labels through the API, completely bypassing the archival immutability guarantee.
    confidence_band: high
cves:
  - id: CVE-2026-116296
    kev_status: "false"
references:
  - https://github.com/go-gitea/gitea/security/advisories/GHSA-6h2f-c8jm-84hc
  - https://sploitus.com/exploit?id=30B5F992-F9A7-5310-8FA7-953D5ACF6CE8
  - https://sploitus.com/exploit?id=30B5F992-F9A7-5310-8FA7-953D5ACF6CE8&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Gitea Archived Repository Metadata Tampering (CVE-2026-116296)
    description: Detects potential exploitation of CVE-2026-116296 by monitoring API requests to milestones, releases, or labels on archived Gitea repositories.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
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
    - action: Upgrade Gitea to v28.2.1 or later on all instances.
      owner: IT Operations
      due: 48h
      evidence: 'Status: Patched - upgrade to Gitea v28.2.1 or later'
  hunt_leads:
    - lead: Search webserver logs for write-methods (POST, PATCH, DELETE) to milestone, release, or label API endpoints targeted at archived repositories.
      technique_id: T1068
      data_needed:
        - webserver access logs containing cs-uri-stem and sc-status
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This is a classic 'sibling gap' in an incomplete security patch. The middleware check is never performed, and the database write proceeds regardless of archive status.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Gitea to v28.2.1 or later.
      owner: IT Operations
      addresses: CVE-2026-116296
      evidence: 'Patched version: v28.2.1+'
---

Gitea repositories configured as "archived" are intended to be permanently read-only. However, due to a missing authorization check (CWE-862) in the API middleware, users with write-collaborator access can bypass these restrictions. While previous security patches (PR #39839) secured Issues and Wikis, the API routes for Milestones, Releases, and Labels remained unprotected. This vulnerability is fixed in Gitea v28.2.1.

## Impact
Users with write-collaborator privileges can tamper with historical project data, including deleting or modifying milestones and releases, which compromises the integrity of repositories intended to serve as audit-grade snapshots.

## Recommendation
- Upgrade all Gitea instances running versions <= v28.2.0 to v28.2.1 or later.
- Audit logs for API write activity on repositories marked as archived to identify potential unauthorized modifications.
