---
brief_id: brief-2026-11-08-ibm-api-connect-auth-bypass-afa064d3
event_id: brief-2026-11-08-ibm-api-connect-auth-bypass-afa064d3
revision: 1
activity_at: "2026-11-08T04:51:30Z"
title: 'IBM API Connect: Improper authorization information disclosure (CVE-2026-17334)'
slug: 2026-11-ibm-api-connect-auth-bypass-afa064d3
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to an improper authorization flaw that allows remote authenticated attackers to access sensitive information via user-controlled keys.
date: "2026-11-08T04:51:30Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source information regarding vulnerability range verified against NVD data.
cpes:
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.1.2:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A remote authenticated attacker can leverage user-controlled keys to bypass authorization controls and access sensitive information stored within the application.
    confidence_band: high
cves:
  - id: CVE-2026-17334
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17334
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and inventory all IBM API Connect instances within the environment.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects IBM API Connect versions 12.1.0.0 through 12.1.1.2.
  hunt_leads:
    - lead: Identify authenticated users accessing unusual key-related endpoints or data resources.
      technique_id: T1592
      data_needed:
        - API access logs
        - Authentication logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows authenticated attackers to use user-controlled keys for sensitive information access.
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM API Connect to the next available patched version upon vendor release.
      owner: IT Operations
      addresses: CVE-2026-17334
      evidence: Product is vulnerable in versions 12.1.0.0 through 12.1.1.2.
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a vulnerability involving improper authorization when handling user-controlled keys. This flaw allows a remote authenticated attacker to bypass intended authorization controls and retrieve sensitive information. No specific exploit code or active exploitation instances were detailed in the disclosure.

## Impact

Successful exploitation of this vulnerability results in the unauthorized disclosure of sensitive data managed by the API Connect instance. The vulnerability carries a CVSS v3.1 base score of 8.5.

## Recommendation

* Inventory all deployed instances of IBM API Connect to identify versions 12.1.0.0 through 12.1.1.2.
* Monitor IBM support channels for the release of an official security patch addressing CVE-2026-17334.
* Review API access logs for anomalous request patterns originating from authenticated user accounts, specifically focusing on unauthorized access to keys or administrative endpoints.
