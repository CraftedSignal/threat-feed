---
brief_id: brief-2026-10-26-soem-memory-safety
event_id: brief-2026-10-26-soem-memory-safety
revision: 1
activity_at: "2026-10-26T09:41:24Z"
title: 'SOEM: Out-of-bounds memory read vulnerability (CVE-2026-82947)'
slug: 2026-10-soem-memory-safety
description: The Simple Open EtherCAT Master (SOEM) library version 2.0.0 and earlier fails to validate length and offset fields in device messages, allowing a malicious device to trigger out-of-bounds memory reads.
date: "2026-10-26T09:41:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation for crash logging
cpes:
  - cpe:2.3:a:openethercatsociety:soem:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-safety
  - industrial-control-systems
vendors:
  - OpenEtherCATsociety
products:
  - SOEM (<= 2.0.0)
cves:
  - id: CVE-2026-82947
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82947
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  hunt_leads:
    - lead: Monitor for repeated segmentation faults or crashes of services utilizing the SOEM library.
      technique_id: T1499
      data_needed:
        - Application crash logs
        - System event logs (e.g., dmesg, Windows Event Log)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This can cause the master to access invalid memory locations, potentially disclosing sensitive information or causing crashes.
  mitigation_plan:
    - priority: immediate
      action: Identify and inventory all deployments of SOEM 2.0.0 or earlier.
      owner: IT Operations
      addresses: CVE-2026-82947
      evidence: SOEM version 2.0.0 and earlier contains multiple vulnerabilities
---

CVE-2026-82947 involves a memory safety vulnerability in the SOEM frame processing logic. An attacker-controlled device can provide manipulated length and offset values within EtherCAT messages. Because the master does not validate these inputs against allocated buffer sizes, it performs out-of-bounds reads. This flaw can lead to sensitive information disclosure or a denial-of-service condition via application crashes.

## Impact

Successful exploitation may result in the disclosure of memory contents to an attacker or an unexpected crash of the master process.

## Recommendation

Identify systems utilizing the SOEM library version 2.0.0 or earlier. Monitor for unusual application crashes or logs indicative of memory access violations in the EtherCAT master service. Upgrade to a patched version once released by the maintainers.
