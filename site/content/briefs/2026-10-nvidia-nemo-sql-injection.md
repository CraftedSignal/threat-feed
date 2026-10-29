---
brief_id: brief-2026-10-27-nvidia-nemo-sql-injection
event_id: brief-2026-10-27-nvidia-nemo-sql-injection
revision: 2
activity_at: "2026-10-29T20:15:56Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:15:56Z"
    checksum: sha256:e73d7d7b11e8eb0d95a737a2a0035f7e0f58d7fe08340d51b0b3f4513638e4ad
    summary: severity → critical; added CVE-2026-65145
    changed_fields:
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-65145
title: NVIDIA NeMo Agent Toolkit SQL injection (CVE-2026-65151)
slug: 2026-10-nvidia-nemo-sql-injection
description: NVIDIA NeMo Agent Toolkit is vulnerable to a SQL injection flaw that may allow an unauthorized attacker to perform data tampering, cause a denial of service, or facilitate unauthorized information disclosure.
date: "2026-10-27T13:50:57Z"
lastmod: "2026-10-29T20:13:49Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:nvidia:nemo_agent_toolkit:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - nvidia
vendors:
  - NVIDIA
products:
  - NeMo Agent Toolkit
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NVIDIA NeMo Agent Toolkit contains vulnerability where an attacker could cause a SQL injection issue.
    confidence_band: high
cves:
  - id: CVE-2026-65151
    cvss: 8.4
    kev_status: "false"
  - id: CVE-2026-65145
    cvss: 10
    epss: 0.00526
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65151
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65145
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all NeMo Agent Toolkit deployments for rapid patching when a vendor update is released
      owner: IT Operations
      due: 48h
      evidence: Vulnerability (CVE-2026-65151) identified in NeMo Agent Toolkit
  hunt_leads:
    - lead: Monitor web access logs for common SQL injection patterns targeting toolkit-specific endpoints
      technique_id: T1190
      data_needed:
        - Web application logs
        - WAF logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows SQL injection which often leaves traces in web traffic
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or configuration changes provided by NVIDIA once released
      owner: IT Operations
      addresses: CVE-2026-65151
      evidence: NVD disclosure of CVE-2026-65151
updates:
  - at: "2026-10-29T20:13:49Z"
    level: L3
    summary: severity → critical; added CVE-2026-65145
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-65145
---

NVIDIA has disclosed a vulnerability in the NeMo Agent Toolkit that allows for SQL injection (CVE-2026-65151). Successful exploitation can lead to unauthorized data tampering, denial of service, and information disclosure. No specific version ranges or remediation steps were provided in the initial NVD advisory; organizations should monitor NVIDIA for patch releases.

## Impact
Successful exploitation may result in data tampering, denial of service (DoS), and information disclosure.

## Recommendation
- Monitor NVIDIA security advisories for patches addressing CVE-2026-65151.
- Inventory all instances of NVIDIA NeMo Agent Toolkit in your environment.
- Implement strict input validation and parameterized queries for web interfaces interacting with the toolkit until a patch is applied.
