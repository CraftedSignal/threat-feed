---
brief_id: brief-2026-10-31-lxd-authentication-bypass
event_id: brief-2026-10-31-lxd-authentication-bypass
revision: 1
activity_at: "2026-10-31T18:40:10Z"
title: 'Canonical LXD and MicroCloud: Authentication bypass (CVE-2026-112816)'
slug: 2026-10-lxd-authentication-bypass
description: An authentication bypass vulnerability (CVE-2026-112816) in the Canonical LXD HTTPS interface allows attackers to impersonate trusted clients via crafted TLS certificate chains, granting unauthorized control over clusters, containers, and host systems.
date: "2026-10-31T18:40:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source-verified version thresholds and vulnerability mechanics
tags:
  - authentication-bypass
  - v4-10.0-cvss
  - lxd
  - microcloud
  - vulnerability
vendors:
  - Canonical
products:
  - LXD (< 4.0.15/5.0.11/5.21.9/6.10.1)
  - MicroCloud (< 2.1.5/3.4.1)
affected_os:
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LXD API-ye erişebilen saldırgan, güvenilen bir istemcinin açık sertifikasını kullanarak hazırlanmış bir zincirle o istemciyi taklit edebilir.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552.004
    technique_name: Private Keys
    evidence: LXD API-ye erişebilen saldırgan, güvenilen bir istemcinin açık sertifikasını kullanarak hazırlanmış bir zincirle o istemciyi taklit edebilir.
    confidence_band: high
cves:
  - id: CVE-2026-112816
    kev_status: "false"
references:
  - https://ubuntu.com/security/CVE-2026-112816
  - https://sploitus.com/exploit?id=3306F82C-C708-5D34-9D91-84D815CF7BB6
  - https://sploitus.com/exploit?id=3306F82C-C708-5D34-9D91-84D815CF7BB6&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all hosts running vulnerable versions of LXD/MicroCloud and schedule emergency maintenance
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is critical (CVSS 10.0) with a public PoC available
  hunt_leads:
    - lead: Analyze LXD audit logs for unexpected or anomalous client certificate connection requests to the API
      technique_id: T1190
      data_needed:
        - LXD daemon logs
        - LXD API audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Successful exploitation occurs via the HTTPS interface using crafted certificate chains
  mitigation_plan:
    - priority: immediate
      action: Update LXD to 6.10.1 (or other track-specific safe versions) and MicroCloud to 3.4.1
      owner: IT Operations
      addresses: CVE-2026-112816
      evidence: Canonical minimum safe version thresholds
  gaps:
    - Lack of specific SIEM correlation rule for this authentication bypass pattern
---

CVE-2026-112816 is a critical vulnerability in the Canonical LXD HTTPS interface caused by improper validation of client TLS certificate chains. An attacker with network access to the LXD API can craft a certificate chain that mimics a trusted client, effectively bypassing authentication. This vulnerability impacts both LXD and MicroCloud environments. Canonical has released patches for multiple stable release tracks as of October 29, 2026.

## Impact

Successful exploitation allows an unauthenticated attacker to gain control over the LXD/MicroCloud cluster, managed containers, virtual machines, and the underlying host system.

## Recommendation

1. Audit all systems running Canonical LXD or MicroCloud to identify versions currently below the minimum safe thresholds: LXD (4.0.15, 5.0.11, 5.21.9, 6.10.1) and MicroCloud (2.1.5, 3.4.1).
2. Plan a maintenance window for patching, as `snap refresh` operations may restart services and cause temporary disruption to container or VM workloads.
3. Restrict network access to the LXD HTTPS API to only authorized management subnets and trusted administrative clients using firewall or network security group policies.
4. Perform post-patching validation by verifying package versions and ensuring cluster service health.
5. Prior to patching, perform an investigation of LXD audit logs for signs of unauthorized API access or anomalous client certificate usage.
