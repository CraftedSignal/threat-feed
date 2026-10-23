---
brief_id: brief-2026-10-23-velocloud-orchestrator-sqli
event_id: brief-2026-10-23-velocloud-orchestrator-sqli
revision: 2
activity_at: "2026-10-23T11:27:22Z"
revision_history:
  - revision: 2
    at: "2026-10-23T11:27:22Z"
    checksum: sha256:3fd51ff95fad8b64f4aeae451d1cd816cf03a0ceab4c1f4f7c334d9592cf394e
    summary: new product
    changed_fields:
      - affected_products
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/arista-velocloud-orchestrator-cve-2026-114625
title: 'Arista VeloCloud Orchestrator: SQL Injection Privilege Escalation (CVE-2026-114625)'
slug: 2026-10-velocloud-orchestrator-sqli
description: Arista VeloCloud Orchestrator (VCO) is under active exploitation by attackers using a critical SQL injection vulnerability (CVE-2026-114625) to escalate from low-privilege tenant accounts to superuser operator status.
date: "2026-10-23T10:36:30Z"
lastmod: "2026-10-23T11:26:29Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: almost certain
qa_status:
  verdict: pass
  validation_status: Source-documented IOCs and vulnerability data verified
cpes:
  - cpe:2.3:a:arista:velocloud_orchestrator:*:*:*:*:*:*:*:*
vendors:
  - Arista
products:
  - VeloCloud Orchestrator (< 5.2.3.18, 6.1.3.10, 6.4.2.12)
  - VeloCloud Orchestrator (< 5.2.3.18, < 6.1.3.10, < 6.4.2.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: On an affected system, any authenticated user can gain operator privileges and masquerade as a local superuser operator user.
    confidence_band: high
cves:
  - id: CVE-2026-114625
    cvss: 9.9
    kev_status: "false"
references:
  - https://www.securityweek.com/attackers-exploit-third-velocloud-orchestrator-zero-day-in-four-months/
  - https://pwn.watch/i/arista-velocloud-orchestrator-cve-2026-114625
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114625
  - https://advisories.ncsc.nl/2026/ncsc-2026-0385.html
iocs:
  - type: ip
    value: 74.82.197.86
  - type: ip
    value: 38.54.50.151
ioc_counts:
  ip: 2
rules:
  - title: Detect CVE-2026-114625 Exploitation - Potential SQL Injection
    description: Detects potential SQL injection attempts against VeloCloud Orchestrator by monitoring for common SQL meta-characters or keywords in URI queries associated with authenticated sessions.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block 74.82.197.86 and 38.54.50.151 at network edge
      owner: SOC
      due: immediate
      evidence: Source notes observation of these IPs in attacks
  hunt_leads:
    - lead: Identify authenticated sessions with unusual request velocity or payload signatures
      technique_id: T1068
      data_needed:
        - VCO web access logs
        - Backend application logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Arista notes investigation of high-request rates and unusual path components as key indicators
  mitigation_plan:
    - priority: immediate
      action: Upgrade VeloCloud Orchestrator to version 5.2.3.18, 6.1.3.10, or 6.4.2.12
      owner: IT Operations
      addresses: CVE-2026-114625
      evidence: Arista advisory specifies these versions as remediations
updates:
  - at: "2026-10-23T11:26:29Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/arista-velocloud-orchestrator-cve-2026-114625
---

Arista Networks has released security patches for CVE-2026-114625, a critical-severity SQL injection vulnerability in the VeloCloud Orchestrator (VCO) on-premises management tool. The vulnerability enables an authenticated user with low-level tenant role privileges to escalate to a superuser operator, granting unauthorized access to privileged internal functionality. Arista has confirmed active exploitation in the wild.

## Impact

Successful exploitation results in the compromise of the VCO host, allowing attackers to access internal-only management functionality, masquerade as a superuser, and impact the confidentiality, integrity, and availability of the orchestrator and its managed data.

## Recommendation

- Upgrade on-premises VCO installations immediately to version 5.2.3.18, 6.1.3.10, 6.4.2.12, or later.
- Block inbound traffic from malicious IP addresses 74.82.197.86 and 38.54.50.151 at the network perimeter.
- Review VCO web access, backend, and database logs for anomalous request patterns originating from existing authenticated sessions.
- Restrict access to the VCO web interface to trusted management networks until patches are applied.
