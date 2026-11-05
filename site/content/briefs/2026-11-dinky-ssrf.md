---
brief_id: brief-2026-11-05-dinky-ssrf
event_id: brief-2026-11-05-dinky-ssrf
revision: 1
activity_at: "2026-11-05T00:06:06Z"
title: 'DataLinkDC Dinky: Server-side request forgery (CVE-2026-122009)'
slug: 2026-11-dinky-ssrf
description: A server-side request forgery vulnerability in DataLinkDC Dinky (<= 1.2.5) allows remote attackers to manipulate the _authority argument to trigger unauthorized requests from the server.
date: "2026-11-05T00:06:06Z"
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
  - cpe:2.3:a:datalinkdc:dinky:*:*:*:*:*:*:*:*
vendors:
  - DataLinkDC
products:
  - Dinky (<= 1.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This manipulation of the argument _authority causes server-side request forgery. The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-122009
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122009
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory Dinky instances running version 1.2.5 or earlier
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects Dinky up to 1.2.5
  hunt_leads:
    - lead: Identify unusual outbound HTTP requests initiated by the Dinky server process
      technique_id: T1190
      data_needed:
        - Proxy logs
        - Firewall logs
        - Flow logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Manipulation of _authority causes SSRF
  mitigation_plan:
    - priority: immediate
      action: Restrict network access for the Dinky server to only necessary external services
      owner: IT Operations
      addresses: CVE-2026-122009
      evidence: SSRF allows interaction with unauthorized internal services
---

A vulnerability has been identified in DataLinkDC Dinky versions up to 1.2.5 affecting the FlinkWebURITemplateProxyServlet.getNewTargetUri function within the flink_web Proxy Endpoint. An attacker can exploit this via the _authority argument to achieve server-side request forgery (SSRF). The exploit has been publicly disclosed and may be actively targeted.

## Impact

The SSRF vulnerability allows an unauthenticated remote attacker to force the Dinky server to perform unauthorized HTTP requests. This could lead to information disclosure from internal network resources or interaction with unauthorized internal services.

## Recommendation

* Inventory all instances of Dinky to identify versions 1.2.5 or earlier.
* Monitor network logs for unusual outbound requests originating from the Dinky application server, specifically requests directed toward internal IP ranges or restricted local services.
* Apply security patches or updates provided by the vendor once available for the affected versions.
