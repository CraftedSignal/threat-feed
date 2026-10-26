---
brief_id: brief-2026-10-26-iflytek-astron-agent-vuln
event_id: brief-2026-10-26-iflytek-astron-agent-vuln
revision: 1
activity_at: "2026-10-26T17:45:11Z"
title: 'iFlytek astron-agent: Incomplete blacklist in DDL Whitelist Handler (CVE-2026-116339)'
slug: 2026-10-iflytek-astron-agent-vuln
description: A vulnerability in iFlytek astron-agent versions up to 1.1.2 allows remote attackers to manipulate the DDL Whitelist Handler via core/memory/database/api/v1/exec_ddl.py due to an incomplete blacklist implementation.
date: "2026-10-26T17:45:11Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:iflytek:astron-agent:*:*:*:*:*:*:*:*
vendors:
  - iFlytek
products:
  - astron-agent (<= 1.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely. The exploit has been publicly disclosed and may be utilized.
    confidence_band: high
cves:
  - id: CVE-2026-116339
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116339
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the astron-agent management interface to known, trusted management segments.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is remotely exploitable.
  hunt_leads:
    - lead: Identify and audit all exposed instances of iFlytek astron-agent.
      technique_id: T1190
      data_needed:
        - Asset inventory/service discovery logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability affects iFlytek astron-agent versions up to 1.1.2.
    - lead: Monitor web server or application logs for requests targeting core/memory/database/api/v1/exec_ddl.py.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves the DDL Whitelist Handler at core/memory/database/api/v1/exec_ddl.py.
  mitigation_plan:
    - priority: immediate
      action: Isolate internet-facing astron-agent instances.
      owner: IT Operations
      addresses: CVE-2026-116339
      evidence: Remote exploitation path identified.
---

CVE-2026-116339 identifies a vulnerability in iFlytek astron-agent versions up to 1.1.2. The issue exists within the DDL Whitelist Handler component, specifically in the file core/memory/database/api/v1/exec_ddl.py. An incomplete blacklist implementation allows for remote manipulation of the handler, which may facilitate unauthorized actions. The vendor has not responded to disclosure attempts, and public exploit disclosure has been observed.

## Impact

The vulnerability allows for remote interaction with the DDL Whitelist Handler, potentially resulting in unauthorized DDL execution or security bypasses caused by the incomplete blacklist logic.

## Recommendation

Inventory all instances of iFlytek astron-agent. As no patch is currently available from the vendor, restrict network access to the astron-agent management interfaces to trusted IP addresses only and monitor for anomalous HTTP requests targeting the DDL API endpoint.
