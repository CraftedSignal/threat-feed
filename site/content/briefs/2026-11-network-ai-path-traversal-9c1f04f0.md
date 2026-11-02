---
brief_id: brief-2026-11-02-network-ai-path-traversal-9c1f04f0
event_id: brief-2026-11-02-network-ai-path-traversal-9c1f04f0
revision: 1
activity_at: "2026-11-02T05:17:32Z"
title: 'Network-AI: Path traversal in InputSanitizer (CVE-2026-120313)'
slug: 2026-11-network-ai-path-traversal-9c1f04f0
description: Network-AI versions prior to 5.15.5 contain a path traversal vulnerability in InputSanitizer.sanitizePath() that allows attackers to escape the base directory via sibling-directory paths.
date: "2026-11-02T05:17:32Z"
lastmod: "2026-11-02T05:17:42Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:network-ai:network-ai:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - vulnerability
  - authentication-bypass
  - cve-2026-120314
  - webserver
vendors:
  - Network-AI
products:
  - Network-AI (< 5.15.5)
  - Network-AI (5.14.0 <= version < 5.15.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Network-AI before 5.15.5 contains a path traversal vulnerability in InputSanitizer.sanitizePath() that allows attackers to escape the base directory using sibling-directory paths.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can supply paths whose directory name shares a string prefix with the base... to read, list, or write files outside the sandbox.
    confidence_band: high
cves:
  - id: CVE-2026-120313
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120314
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120313
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120314
rules:
  - title: Detects CVE-2026-120314 Exploitation - Unauthorized Task Management Requests
    description: Detects potential exploitation of CVE-2026-120314 where JSON-RPC requests are made to task management endpoints without expected authorization headers.
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
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Inventory all instances of Network-AI in the environment and determine if secret configuration is active.
      owner: IT Operations
      due: 24h
      evidence: Source documentation on missing auth vulnerability.
  hunt_leads:
    - lead: Hunt for file access attempts containing directory traversal sequences (e.g., ../) or sibling-directory prefixes targeting paths outside the application sandbox.
      technique_id: T1083
      data_needed:
        - Application audit logs
        - Filesystem access telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaw exists due to an unanchored startsWith check, allowing attackers to escape the intended base directory
    - lead: Search web logs for POST requests to /tasks/ endpoints originating from untrusted or external IP addresses.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The source identifies specific endpoints (tasks/send, tasks/get, tasks/cancel) as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Network-AI to 5.15.5 or later
      owner: IT Operations
      addresses: CVE-2026-120313
      evidence: Network-AI before 5.15.5 contains a path traversal vulnerability
    - priority: immediate
      action: Upgrade Network-AI to 5.15.5 or later.
      owner: IT Operations
      addresses: CVE-2026-120314
      evidence: Source states affected range is from 5.14.0 before 5.15.5.
updates:
  - at: "2026-11-02T05:17:42Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-120314 Exploitation - Unauthorized Task Management Requests'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120314
---

Network-AI versions prior to 5.15.5 are susceptible to a path traversal vulnerability located in the InputSanitizer.sanitizePath() function. The vulnerability arises from an unanchored "startsWith" check used during input validation. By providing a sibling-directory path that shares a string prefix with the intended base directory, an attacker can bypass these checks to access, list, or write files outside of the configured sandbox.

## Impact
Unauthorized access allows attackers to read, list, or write files on the host filesystem that are outside of the restricted sandbox directory.

## Recommendation
- Upgrade Network-AI to version 5.15.5 or later.
- Implement strict input validation or use established path-canonicalization libraries that do not rely on unanchored prefix comparisons for path isolation.
- Audit file system access logs for operations targeting directories outside of the designated application storage path.
