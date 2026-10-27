---
brief_id: brief-2026-10-25-zylon-privategpt-ssrf
event_id: brief-2026-10-25-zylon-privategpt-ssrf
revision: 2
activity_at: "2026-10-27T01:10:17Z"
revision_history:
  - revision: 2
    at: "2026-10-27T01:10:17Z"
    checksum: sha256:cefd40689b97990dba10b490a6e922cd49589c4bf3838aff7029e12ef190cee3
    summary: poc_available
    changed_fields:
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=C6AF2BC8-649C-546B-AB5D-8F0A5C3CDEDD&utm_source=rss&utm_medium=rss
title: 'Zylon PrivateGPT: Server-side request forgery (CVE-2026-116000)'
slug: 2026-10-zylon-privategpt-ssrf
description: A server-side request forgery vulnerability in Zylon PrivateGPT versions 1.0.0 and 1.0.1 allows remote attackers to perform unauthorized requests via the URI Artifact Loader component.
date: "2026-10-25T04:25:53Z"
lastmod: "2026-10-27T01:09:25Z"
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
  validation_status: Needs environment validation of the affected path in deployed PrivateGPT instances.
cpes:
  - cpe:2.3:a:zylon:privategpt:1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:zylon:privategpt:1.0.1:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=C6AF2BC8-649C-546B-AB5D-8F0A5C3CDEDD&utm_source=rss&utm_medium=rss
tags:
  - ssrf
  - vulnerability
  - webserver
vendors:
  - Zylon
products:
  - PrivateGPT (1.0.0, 1.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Performing a manipulation of the argument Value results in server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-116000
    cvss: 7.3
    epss: 0.00288
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116000
  - https://sploitus.com/exploit?id=C6AF2BC8-649C-546B-AB5D-8F0A5C3CDEDD&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all Zylon PrivateGPT instances in the environment.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects Zylon PrivateGPT 1.0.0/1.0.1.
  hunt_leads:
    - lead: Monitor web server access logs for unusual requests to URI-loading endpoints containing suspicious URI schemes (e.g., file://, gopher://, or internal 10/172/192 IP addresses) in the Value parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Performing a manipulation of the argument Value results in server-side request forgery.
  mitigation_plan:
    - priority: immediate
      action: Implement strict egress filtering on servers hosting PrivateGPT to block connections to private address spaces (RFC 1918) and non-essential external domains.
      owner: IT Operations
      addresses: CVE-2026-116000
      evidence: Vulnerability allows SSRF; egress filtering mitigates impact.
updates:
  - at: "2026-10-27T01:09:25Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=C6AF2BC8-649C-546B-AB5D-8F0A5C3CDEDD&utm_source=rss&utm_medium=rss
---

A server-side request forgery (SSRF) vulnerability exists in the URI Artifact Loader component of Zylon PrivateGPT, specifically within the `load_file_from_uri` function of `private_gpt/server/ingest/uri_loader.py`. The vulnerability arises from improper handling of the `Value` argument, which can be manipulated by a remote attacker to force the server to make unintended network requests. Public exploit code for this vulnerability is available. The vendor has not responded to vulnerability disclosures.

## Impact

Successful exploitation allows a remote attacker to perform SSRF, potentially accessing internal services, scanning private network segments, or exfiltrating sensitive data from the host environment or internal network accessible to the PrivateGPT server.

## Recommendation

Prioritize the identification and isolation of internet-facing Zylon PrivateGPT instances. Given the lack of a vendor response or patch, restrict network access to these instances using egress filtering to prevent unauthorized internal requests.
