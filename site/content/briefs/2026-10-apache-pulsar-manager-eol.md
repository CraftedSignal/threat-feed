---
brief_id: brief-2026-10-21-apache-pulsar-manager-eol
event_id: brief-2026-10-21-apache-pulsar-manager-eol
revision: 1
activity_at: "2026-10-21T21:36:00Z"
title: 'Apache Pulsar Manager: Missing authentication and administrative credential disclosure (CVE-2026-105944)'
slug: 2026-10-apache-pulsar-manager-eol
description: Apache Pulsar Manager is vulnerable to missing authentication and authorization, leading to potential administrative credential disclosure, and will not receive patches due to the project reaching end-of-life status.
date: "2026-10-21T21:36:00Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source verified against Apache security mailing list archive
cpes:
  - cpe:2.3:a:apache:pulsar_manager:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - eol
  - authentication-bypass
vendors:
  - Apache
products:
  - Pulsar Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: 'CVE-2026-105944: Apache Pulsar Manager: Missing authentication and authorization and disclosure of the Pulsar admin...'
    confidence_band: high
cves:
  - id: CVE-2026-105944
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/297
  - https://lists.apache.org/thread/hol3z7fzhjntwvrv8xqqwx4l4d2jx796
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Architecture
  immediate_actions:
    - action: Inventory and decommission all instances of Apache Pulsar Manager
      owner: IT Operations
      due: 48h
      evidence: Project has reached end of life and will not be fixed
  mitigation_plan:
    - priority: immediate
      action: Isolate remaining Pulsar Manager instances via network segmentation
      owner: Network Engineering
      addresses: CVE-2026-105944
      evidence: No patch available due to EOL status
---

The Apache Pulsar PMC has confirmed that Apache Pulsar Manager suffers from missing authentication and authorization, resulting in the potential exposure of Pulsar administrative credentials (CVE-2026-105944). Apache Pulsar Manager has reached its end-of-life (EOL) and has been retired; consequently, the Apache Pulsar PMC has explicitly stated that no security patches will be issued for this vulnerability. Users are advised to discontinue the use of this software and migrate to alternative solutions.

## Impact

Successful exploitation allows unauthenticated attackers to bypass security controls and gain access to sensitive administrative credentials, which could lead to full compromise of the Pulsar cluster management interface.

## Recommendation

- Identify all instances of Apache Pulsar Manager within the environment via software asset inventory.
- Plan and execute an immediate migration away from Apache Pulsar Manager as the software is EOL and will remain vulnerable.
- Restrict network access to any remaining instances of Pulsar Manager as an interim compensating control to prevent unauthorized access.
