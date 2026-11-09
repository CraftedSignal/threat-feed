---
brief_id: brief-2026-11-09-logseq-auth-bypass
event_id: brief-2026-11-09-logseq-auth-bypass
revision: 1
activity_at: "2026-11-09T07:31:57Z"
title: 'Logseq: Authentication bypass in Local HTTP API (CVE-2026-124573)'
slug: 2026-11-logseq-auth-bypass
description: Logseq versions 2.0.1 and 2.0.2 contain an authentication bypass vulnerability in the Local HTTP API that allows remote, unauthenticated access to the application.
date: "2026-11-09T07:31:57Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:logseq:logseq:2.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:logseq:logseq:2.0.2:*:*:*:*:*:*:*
vendors:
  - Logseq
products:
  - Logseq (2.0.1, 2.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation results in missing authentication. The attack may be performed from remote. The exploit has been made public and could be used.
    confidence_band: high
cves:
  - id: CVE-2026-124573
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124573
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable the Local HTTP API feature in Logseq 2.0.1 and 2.0.2
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects the function validate-auth-token of the component Local HTTP API
  hunt_leads:
    - lead: Monitor for unexpected inbound network connections to the port used by the Logseq Local HTTP API
      technique_id: T1190
      data_needed:
        - Network firewall or host-based firewall logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The attack may be performed from remote.
  mitigation_plan:
    - priority: immediate
      action: Disable the Local HTTP API if not strictly required
      owner: IT Operations
      addresses: CVE-2026-124573
      evidence: Vulnerability in Local HTTP API allows unauthenticated remote access
---

A vulnerability exists in the Logseq Local HTTP API component, specifically within the 'validate-auth-token' function located in 'src/electron/electron/server.cljs'. The flaw allows for missing authentication, permitting remote attackers to interact with the API without valid credentials. This vulnerability has an existing public exploit. As of the time of reporting, the vendor has not responded to the initial issue disclosure.

## Impact

The vulnerability allows remote, unauthenticated access to the Logseq Local HTTP API, which may lead to unauthorized data access or manipulation within the application depending on the API's capabilities.

## Recommendation

* Inventory all instances of Logseq running with the Local HTTP API enabled.
* Disable the Local HTTP API feature in affected versions (2.0.1 and 2.0.2) until a patch is released by the vendor.
* Restrict network access to the Local HTTP API port to only trusted local interfaces if the feature must remain enabled.
