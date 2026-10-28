---
brief_id: brief-2026-10-28-apache-qpid-proton-c-buffer-overflow
event_id: brief-2026-10-28-apache-qpid-proton-c-buffer-overflow
revision: 1
activity_at: "2026-10-28T22:24:34Z"
title: 'Apache Qpid Proton C: Stack buffer overflow read in TLS certificate validation (CVE-2026-115942)'
slug: 2026-10-apache-qpid-proton-c-buffer-overflow
description: Apache Qpid Proton C versions through 0.40.0 contain a stack buffer overflow read vulnerability triggered by misconfigured wildcard TLS certificates.
date: "2026-10-28T22:24:34Z"
lastmod: "2026-10-28T22:24:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source-confirmed vulnerability details.
cpes:
  - cpe:2.3:a:apache:qpid_proton:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Qpid Proton C (<= 0.40.0)
cves:
  - id: CVE-2026-115942
    kev_status: unknown
  - id: CVE-2026-105042
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/432
  - https://seclists.org/oss-sec/2026/q4/430
  - https://issues.apache.org/jira/browse/PROTON-2976
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Apache Qpid Proton C to version 0.41.1
      owner: IT Operations
      due: 72h
      evidence: Users are recommended to upgrade to version 0.41.1, which fixes the issue.
  hunt_leads:
    - lead: Monitor application logs for recurring segmentation faults or abrupt termination of services linked against libqpid-proton
      data_needed:
        - Application crash logs
        - System auditd or service manager logs (e.g., systemd)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A message body that is deeply nested and decoded by pn_message_body() could overflow the stack and cause a crash.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Qpid Proton C 0.41.1
      owner: IT Operations
      addresses: CVE-2026-105042
      evidence: Users are recommended to upgrade to version 0.41.1, which fixes the issue.
updates:
  - at: "2026-10-28T22:24:48Z"
    level: L2
    summary: added coverage for Qpid Proton C (<= 0.40.0)
    sources:
      - oss-security
    source_urls:
      - https://seclists.org/oss-sec/2026/q4/430
---

Apache Qpid Proton C versions through 0.40.0 are affected by a stack buffer overflow read caused by the verification of non-compliant wildcard TLS certificates. The issue does not affect certificates issued to the RFC9525 standard. Version 0.41.1 has been released to fix this issue by only accepting certificates that comply with the RFC9525 standard.
