---
brief_id: brief-2026-10-27-hirdb-auth-bypass
event_id: brief-2026-10-27-hirdb-auth-bypass
revision: 1
activity_at: "2026-10-27T10:57:15Z"
title: 'Hitachi HiRDB Server: Missing Authentication for Critical Function (CVE-2026-82116)'
slug: 2026-10-hirdb-auth-bypass
description: A missing authentication vulnerability in Hitachi HiRDB Server allows unauthenticated actors to access critical database functions, warranting immediate patching.
date: "2026-10-27T10:57:15Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: No detection artifacts or IOCs provided in source; monitoring vendor security portal for patch availability is required
cpes:
  - cpe:2.3:a:hitachi:hirdb_server:*:*:*:*:*:*:*:*
vendors:
  - Hitachi
products:
  - HiRDB Server (10-00 <= v < 10-12-01)
  - HiRDB Server (09-00 <= v <= 09-66-22)
  - HiRDB Server with Additional Function (09-00 <= v <= 09-66/V)
  - HiRDB Server 9(32) (09-02 <= v <= 09-66-22)
  - HiRDB Server with Additional Function 9(32) (09-00 <= v <= 09-66-/V)
cves:
  - id: CVE-2026-82116
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82116
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Hitachi HiRDB Server installations
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82116 affects multiple versions of HiRDB Server
  mitigation_plan:
    - priority: immediate
      action: Apply security patches provided by Hitachi for HiRDB Server
      owner: IT Operations
      addresses: CVE-2026-82116
      evidence: Vulnerability requires patching to address missing authentication
---

CVE-2026-82116 identifies a vulnerability where critical database functions in Hitachi HiRDB Server lack proper authentication checks. This flaw allows unauthorized, unauthenticated users to interact with sensitive database operations. The vulnerability affects multiple versions of the HiRDB Server product line, including Version 10 and Version 9 branches.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.8, indicating a critical risk of unauthorized access or modification to data managed by the database server. No specific exploitation incidents have been publicly documented at this time.

## Recommendation

Inventory all deployments of Hitachi HiRDB Server within the environment to identify versions within the affected ranges. Prioritize the application of official patches provided by Hitachi for the affected HiRDB Server 10 and 9 branches immediately.
