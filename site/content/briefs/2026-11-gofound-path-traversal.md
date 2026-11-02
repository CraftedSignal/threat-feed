---
brief_id: brief-2026-11-02-gofound-path-traversal
event_id: brief-2026-11-02-gofound-path-traversal
revision: 1
activity_at: "2026-11-02T15:50:49Z"
title: 'GoFound: Path traversal arbitrary directory deletion (CVE-2026-120444)'
slug: 2026-11-gofound-path-traversal
description: GoFound versions 1.4.1 and earlier are vulnerable to unauthenticated path traversal via the database parameter, allowing attackers to delete arbitrary directories on the host file system.
date: "2026-11-02T15:50:49Z"
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
cpes:
  - cpe:2.3:a:gofound:gofound:*:*:*:*:*:*:*:*
vendors:
  - GoFound
products:
  - GoFound (<= 1.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can leverage '..' sequences to traverse the file system, ultimately triggering an os.RemoveAll operation.
    confidence_band: high
cves:
  - id: CVE-2026-120444
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120444
rules:
  - title: Detects CVE-2026-120444 Exploitation - Path Traversal in GoFound API
    description: Detects exploitation attempts against CVE-2026-120444 by monitoring for path traversal sequences in the database parameter of GoFound API endpoints
    platform: sigma
    severity: high
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy the provided Sigma rule to monitor for traversal attempts targeting the /api/db/create and /api/db/drop endpoints
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms path traversal vulnerability via these specific endpoints
  mitigation_plan:
    - priority: immediate
      action: Upgrade GoFound to a version post-1.4.1
      owner: IT Operations
      addresses: CVE-2026-120444
      evidence: Source identifies 1.4.1 and earlier as affected
---

GoFound through version 1.4.1 contains a path traversal vulnerability in the database parameter. An unauthenticated attacker can exploit this via crafted GET requests to the /api/db/create and /api/db/drop endpoints. By injecting dot-dot-slash (../) sequences into the parameter, the application performs an os.RemoveAll operation on directories outside the intended data directory, leading to arbitrary directory deletion.

## Impact

Successful exploitation allows unauthenticated attackers to delete arbitrary directories on the server hosting the GoFound application, potentially resulting in system instability, data loss, or denial of service depending on the target path.

## Recommendation

- Upgrade GoFound to a version beyond 1.4.1 once a security update is released by the maintainers.
- Audit access logs for requests to /api/db/create and /api/db/drop containing path traversal characters.
- Restrict network access to the GoFound API management endpoints to authorized management IP addresses only.
