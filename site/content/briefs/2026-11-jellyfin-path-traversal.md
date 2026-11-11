---
brief_id: brief-2026-11-11-jellyfin-path-traversal
event_id: brief-2026-11-11-jellyfin-path-traversal
revision: 1
activity_at: "2026-11-11T05:59:54Z"
title: 'Jellyfin: Path traversal vulnerability (CVE-2026-126499)'
slug: 2026-11-jellyfin-path-traversal
description: Jellyfin versions prior to 12.0 contain a path traversal vulnerability in API endpoints that allows unauthenticated attackers to delete or move arbitrary directories by manipulating library names.
date: "2026-11-11T05:59:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment.
cpes:
  - cpe:2.3:a:jellyfin:jellyfin:*:*:*:*:*:*:*:*
vendors:
  - Jellyfin
products:
  - Jellyfin (< 12.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Unauthenticated attackers can supply names like .. or absolute paths before setup completes to recursively delete the data directory and jellyfin.db.
    confidence_band: high
cves:
  - id: CVE-2026-126499
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-126499
rules:
  - title: Detects CVE-2026-126499 Exploitation - Path Traversal in Library API
    description: Detects attempts to use path traversal sequences in Jellyfin library API endpoints to access unauthorized directories.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Jellyfin to version 12.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Jellyfin before 12.0 contains a path traversal vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Jellyfin to version 12.0.
      owner: IT Operations
      addresses: CVE-2026-126499
      evidence: Source advises upgrade for Jellyfin before 12.0.
---

Jellyfin versions before 12.0 are affected by a path traversal vulnerability in the 'DELETE /Library/VirtualFolders' and 'POST /Library/VirtualFolders/Name' endpoints. This flaw allows attackers, particularly during the initial setup phase, to supply path traversal sequences (e.g., '..') or absolute paths as library names. Successful exploitation results in the unauthorized deletion or movement of critical application data, including the 'jellyfin.db' database and the entire application data directory.

## Impact
Successful exploitation allows unauthenticated attackers to perform arbitrary file system operations, leading to potential data loss or denial of service by destroying the application database and configuration environment.

## Recommendation
- Upgrade Jellyfin to version 12.0 or later immediately.
- Audit existing library configurations for suspicious or non-standard naming conventions if the instance was exposed during setup.
- Restrict network access to the Jellyfin API, especially during initial instance initialization, to trusted management networks only.
