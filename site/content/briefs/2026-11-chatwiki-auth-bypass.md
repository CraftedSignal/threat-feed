---
brief_id: brief-2026-11-06-chatwiki-auth-bypass
event_id: brief-2026-11-06-chatwiki-auth-bypass
revision: 1
activity_at: "2026-11-06T21:29:04Z"
title: 'ChatWiki: Authentication bypass in getLibRawFileOnePage (CVE-2026-124027)'
slug: 2026-11-chatwiki-auth-bypass
description: ChatWiki before version 2.10.0 contains an authentication bypass vulnerability in the GET /manage/getLibRawFileOnePage route, allowing unauthenticated attackers to enumerate parameters and access unauthorized tenant documents.
date: "2026-11-06T21:29:04Z"
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
  validation_status: Needs environment validation of threshold
cpes:
  - cpe:2.3:a:chatwiki:chatwiki:*:*:*:*:*:*:*:*
vendors:
  - ChatWiki
products:
  - ChatWiki (< 2.10.0)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Attackers can enumerate sequential admin_user_id and file id query parameters, bypassing the ownership check, to retrieve PDF-rendered pages of any tenant's knowledge-base documents.
    confidence_band: high
cves:
  - id: CVE-2026-124027
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124027
rules:
  - title: Detect Potential Document Enumeration via ChatWiki
    description: Detects suspicious sequential access to the getLibRawFileOnePage endpoint which may indicate exploitation of CVE-2026-124027
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ChatWiki to 2.10.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-124027 advisory
  hunt_leads:
    - lead: Identify unauthorized access to management endpoints
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows retrieval of any tenant document via parameter enumeration
  mitigation_plan:
    - priority: immediate
      action: Upgrade ChatWiki to version 2.10.0 or later
      owner: IT Operations
      addresses: CVE-2026-124027
      evidence: NVD vulnerability details
---

ChatWiki versions prior to 2.10.0 contain a missing authentication vulnerability in the 'GET /manage/getLibRawFileOnePage' route. This vulnerability allows an unauthenticated attacker to retrieve PDF-rendered pages of documents belonging to any tenant. By enumerating 'admin_user_id' and 'file_id' query parameters, an attacker can bypass authorization checks to access data across the platform.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive knowledge-base documents from other tenants, leading to unauthorized information disclosure and potential cross-tenant data leakage.

## Recommendation

* Upgrade all ChatWiki instances to version 2.10.0 or later to remediate the missing authentication flaw in the 'getLibRawFileOnePage' endpoint.
* Audit access logs for high-frequency 'GET' requests to '/manage/getLibRawFileOnePage' originating from unauthenticated sessions or unauthorized IP addresses, specifically looking for sequential enumeration of query parameters.
