---
brief_id: brief-2026-11-03-sonicwall-gms-file-read
event_id: brief-2026-11-03-sonicwall-gms-file-read
revision: 1
activity_at: "2026-11-03T20:15:44Z"
title: 'SonicWall GMS: Unauthenticated internal file read (CVE-2026-109593)'
slug: 2026-11-sonicwall-gms-file-read
description: SonicWall GMS 9.5.2 and earlier is vulnerable to an unauthenticated arbitrary file read vulnerability (CVE-2026-109593) which allows attackers to access sensitive internal files via network-accessible interfaces.
date: "2026-11-03T20:15:44Z"
type: advisory
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
  validation_status: Verified CVE and vendor reference
cpes:
  - cpe:2.3:a:sonicwall:gms:*:*:*:*:*:*:*:*
vendors:
  - SonicWall
products:
  - GMS (<= 9.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker with network access to the SonicWall GMS 9.5.2 and earlier versions may be able to read internal GMS files
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: read internal GMS files, potentially exposing sensitive information
    confidence_band: high
cves:
  - id: CVE-2026-109593
    cvss: 9.1
    kev_status: "false"
references:
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0019
  - https://sploitus.com/exploit?id=CVE-2026-109593
  - https://sploitus.com/exploit?id=CVE-2026-109593&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all SonicWall GMS instances and confirm versions
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109593 affects GMS version 9.5.2 and earlier
  hunt_leads:
    - lead: Search GMS web logs for repeated HTTP requests to internal paths or suspicious parameter values indicative of path traversal
      technique_id: T1190
      data_needed:
        - GMS web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated attacker with network access can read internal GMS files
  mitigation_plan:
    - priority: immediate
      action: Patch GMS to the latest secure version provided by SonicWall
      owner: IT Operations
      addresses: CVE-2026-109593
      evidence: SNWLID-2026-0019
---

SonicWall has disclosed an unauthenticated file read vulnerability (CVE-2026-109593) affecting SonicWall GMS version 9.5.2 and earlier. An attacker with network access to the GMS instance can read internal files, potentially leading to unauthorized information disclosure. Public proof-of-concept exploit code has been identified. Organizations should identify GMS instances and prepare for remediation.

## Impact
The vulnerability allows an unauthenticated, network-adjacent attacker to read internal files. This exposure can provide attackers with sensitive information, such as configuration details, credentials, or other system data, which may be leveraged to compromise the GMS instance further or pivot into the managed environment.

## Recommendation
- Identify all instances of SonicWall GMS 9.5.2 or earlier within the environment.
- Apply security patches provided by SonicWall as documented in SNWLID-2026-0019.
- Restrict network access to GMS management interfaces to trusted IP ranges only.
- Review web server and application access logs for abnormal file access patterns or high volumes of requests targeting internal paths on the GMS appliance.
