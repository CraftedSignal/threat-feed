---
brief_id: brief-2026-10-22-youdatasum-cpas-path-traversal
event_id: brief-2026-10-22-youdatasum-cpas-path-traversal
revision: 1
activity_at: "2026-10-22T14:16:13Z"
title: YouDataSum CPAS Audit Management System Path Traversal (CVE-2024-58396)
slug: 2026-10-youdatasum-cpas-path-traversal
description: YouDataSum CPAS Audit Management System V4 contains a path traversal vulnerability in the fileId parameter, allowing unauthenticated remote file retrieval.
date: "2026-10-22T14:16:13Z"
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
  validation_status: Source-verified vulnerability and CVE details
cpes:
  - cpe:2.3:a:youdatasum:cpas_audit_management_system:4:*:*:*:*:*:*:*
vendors:
  - YouDataSum
products:
  - CPAS Audit Management System (V4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: YouDataSum CPAS Audit Management System V4 contains a path traversal vulnerability that allows unauthenticated attackers to read arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2024-58396
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58396
rules:
  - title: Detect CVE-2024-58396 Exploitation - Path Traversal
    description: Detects exploitation of CVE-2024-58396 by identifying GET requests to the vulnerable endpoint containing path traversal sequences in the fileId parameter.
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
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch or upgrade YouDataSum CPAS Audit Management System V4
      owner: IT Operations
      due: 48h
      evidence: Vulnerability (CVE-2024-58396) exists in version 4
  hunt_leads:
    - lead: Search web server logs for requests to /cpasm4/plugInManController/downPlugs containing ../ or ..%2f
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Shadowserver observed exploitation in the wild since 2025-01-13
  mitigation_plan:
    - priority: immediate
      action: Apply security patch for CVE-2024-58396
      owner: IT Operations
      addresses: CVE-2024-58396
      evidence: NVD advisory
---

YouDataSum CPAS Audit Management System V4 contains a path traversal vulnerability in the /cpasm4/plugInManController/downPlugs endpoint. Unauthenticated attackers can exploit the fileId parameter by injecting path traversal sequences (e.g., ../) to read arbitrary files from the underlying file system. The Shadowserver Foundation observed active exploitation of this vulnerability beginning January 13, 2025.

## Impact
Successful exploitation allows unauthenticated attackers to read arbitrary files on the server hosting the CPAS Audit Management System. This can lead to the exposure of sensitive configuration files, credentials, or system files such as /etc/passwd.

## Recommendation
- Inventory all instances of YouDataSum CPAS Audit Management System V4.
- Patch or upgrade the affected system immediately, following guidance from YouDataSum.
- Deploy the provided Sigma rule to detect exploitation attempts targeting the identified endpoint.
- Review web server access logs for requests containing suspicious path traversal sequences (e.g., ../, ..%2f) directed at the /cpasm4/plugInManController/downPlugs endpoint.
