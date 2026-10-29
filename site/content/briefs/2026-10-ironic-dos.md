---
brief_id: brief-2026-10-29-ironic-dos
event_id: brief-2026-10-29-ironic-dos
revision: 1
activity_at: "2026-10-29T15:29:15Z"
title: 'OpenStack Ironic: Conductor denial-of-service via gzip bomb (CVE-2026-115638)'
slug: 2026-10-ironic-dos
description: The OpenStack Ironic Conductor service is vulnerable to a denial-of-service attack due to improper handling of maliciously crafted compressed configuration drive files.
date: "2026-10-29T15:29:15Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of patch versions
cpes:
  - cpe:2.3:a:openstack:ironic:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - cloud
  - openstack
vendors:
  - OpenStack
products:
  - Ironic (>=16.2.0 <29.1.1, >=30.0.0 <32.1.1, >=33.0.0 <35.1.1, >=36.0.0 <39.0.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: The OpenStack Ironic Conductor service is vulnerable to a denial-of-service (DoS) attack through the processing of specially crafted gzip bomb configdrive files.
    confidence_band: high
cves:
  - id: CVE-2026-115638
    cvss: 4.3
    epss: 0.00212
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/433
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenStack Ironic to the specified non-vulnerable versions.
      owner: IT Operations
      due: 72h
      evidence: OSSA-2026-049 advisory guidelines
  hunt_leads:
    - lead: Identify Ironic Conductor service crashes or resource spikes associated with configdrive processing.
      technique_id: T1499.001
      data_needed:
        - Ironic Conductor service logs
        - System resource monitoring (CPU/RAM) for conductor hosts
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Conductor service instability reported via gzip bomb configdrive
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ironic Conductor to patched versions listed in the brief.
      owner: IT Operations
      addresses: CVE-2026-115638
      evidence: OSSA-2026-049 advisory
---

A vulnerability (CVE-2026-115638) exists in the OpenStack Ironic Conductor service where processing a specifically crafted 'gzip bomb' within a configdrive can cause excessive resource consumption. This leads to instability or failure of the conductor service. The vulnerability affects multiple versions of Ironic as specified in the OSSA-2026-049 advisory.

## Impact
Successful exploitation allows an attacker to trigger a denial-of-service condition on the Ironic Conductor, potentially disrupting bare metal provisioning and management operations.

## Recommendation
- Update OpenStack Ironic to the patched versions as recommended in OSSA-2026-049:
 - Upgrade 16.2.x series to >= 29.1.1
 - Upgrade 30.0.x series to >= 32.1.1
 - Upgrade 33.0.x series to >= 35.1.1
 - Upgrade 36.0.x series to >= 39.0.1
- Monitor Ironic Conductor logs for unexpected process crashes, memory exhaustion errors, or high CPU utilization during configuration drive submission tasks.
