---
brief_id: brief-2026-11-03-dockhand-path-traversal
event_id: brief-2026-11-03-dockhand-path-traversal
revision: 1
activity_at: "2026-11-03T16:00:34Z"
title: 'Dockhand: Path traversal vulnerability (CVE-2026-121448)'
slug: 2026-11-dockhand-path-traversal
description: Dockhand versions prior to 1.0.54 are vulnerable to path traversal via double-encoded input in the /api/stacks/[name]/env/raw endpoint, allowing authenticated attackers to read, overwrite, or delete sensitive .env files.
date: "2026-11-03T16:00:34Z"
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
  validation_status: Verified against CVE-2026-121448
cpes:
  - cpe:2.3:a:dockhand:dockhand:*:*:*:*:*:*:*:*
vendors:
  - Dockhand
products:
  - Dockhand (< 1.0.54)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can send %252e%252e sequences to /api/stacks/[name]/env/raw to disclose cross-environment secrets
    confidence_band: high
cves:
  - id: CVE-2026-121448
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121448
rules:
  - title: Detect CVE-2026-121448 Exploitation - Path Traversal in Dockhand
    description: Detects exploitation attempts against CVE-2026-121448 by monitoring for double-encoded directory traversal sequences in the stack name path
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Dockhand to 1.0.54
      owner: IT Operations
      due: 48h
      evidence: Dockhand before 1.0.54 contains a path traversal vulnerability
  hunt_leads:
    - lead: Search web logs for double-encoded path traversal characters
      technique_id: T1083
      data_needed:
        - webserver access logs (cs-uri-stem)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can send %252e%252e sequences
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 1.0.54
      owner: IT Operations
      addresses: CVE-2026-121448
      evidence: Dockhand before 1.0.54 contains a path traversal vulnerability
---

Dockhand versions prior to 1.0.54 contain a path traversal vulnerability. Authenticated users can exploit this by providing double-encoded input (e.g., %252e%252e) within the stack name parameter of the /api/stacks/[name]/env/raw endpoint. This allows unauthorized access to sensitive .env files located outside the intended stack root directory.

## Impact
Successful exploitation allows authenticated attackers to disclose cross-environment secrets, overwrite critical configuration files, or poison deployment variables by deleting or modifying .env files.

## Recommendation
- Upgrade Dockhand to version 1.0.54 or later immediately.
- Audit logs for the /api/stacks/ endpoint to identify attempts containing encoded dot-dot sequences.
- Rotate secrets contained within any .env files that may have been accessible during the period of exposure.
