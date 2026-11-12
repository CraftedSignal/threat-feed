---
brief_id: brief-2026-11-06-geonode-rce
event_id: brief-2026-11-06-geonode-rce
revision: 2
activity_at: "2026-11-12T01:01:34Z"
revision_history:
  - revision: 2
    at: "2026-11-12T01:01:34Z"
    checksum: sha256:c599e320b186971392ffbadce126bdc2efed648cb48a786351977edaf058762c
    summary: poc_available
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=4878B28A-06DB-55BF-AC02-829329F6D394&utm_source=rss&utm_medium=rss
title: 'GeoNode: OS command injection via file upload (CVE-2026-33050)'
slug: 2026-11-geonode-rce
description: GeoNode versions prior to 5.1.0 are vulnerable to OS command injection via a malicious layer name in uploaded vector files, allowing authenticated attackers to achieve remote code execution.
date: "2026-11-06T21:14:33Z"
lastmod: "2026-11-12T01:00:59Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:geonode:geonode:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=4878B28A-06DB-55BF-AC02-829329F6D394&utm_source=rss&utm_medium=rss
vendors:
  - GeoNode
products:
  - GeoNode (< 5.1.0)
  - GeoNode (5.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Arbitrary OS commands can be executed on the GeoNode by uploading a vector file with a crafted layer name.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements.
    confidence_band: high
cves:
  - id: CVE-2026-33050
    cvss: 8.8
    epss: 0.00653
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-9fpx-fr6j-2vh6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33050
  - https://sploitus.com/exploit?id=4878B28A-06DB-55BF-AC02-829329F6D394&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade GeoNode to version 5.1.0 or later
      owner: IT Operations
      due: 24h
      evidence: Patched version 5.1.0 is identified in the GitHub Advisory
  hunt_leads:
    - lead: Identify file upload requests to GeoNode containing shell metacharacters in parameters
      technique_id: T1190
      data_needed:
        - Web server access logs (HTTP POST requests to upload endpoints)
        - Application logs showing file processing activities
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability occurs during the processing of a vector file with a crafted layer name.
  mitigation_plan:
    - priority: immediate
      action: Apply GeoNode 5.1.0
      owner: IT Operations
      addresses: CVE-2026-33050
      evidence: GHSA-9fpx-fr6j-2vh6
updates:
  - at: "2026-11-12T01:00:59Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=4878B28A-06DB-55BF-AC02-829329F6D394&utm_source=rss&utm_medium=rss
---

GeoNode is vulnerable to OS command injection (CVE-2026-33050) when processing vector files. An attacker with low-level privileges can provide a crafted layer name within an uploaded vector file that is not properly neutralized, leading to the execution of arbitrary OS commands on the host server. The vulnerability is confirmed in versions prior to 5.1.0.

## Impact

Successful exploitation allows an authenticated attacker with file upload capabilities to execute arbitrary commands on the underlying server, resulting in a full compromise of confidentiality, integrity, and availability.

## Recommendation

- Upgrade GeoNode to version 5.1.0 or later immediately to apply the patch for CVE-2026-33050.
- Audit logs for unauthorized or unexpected file uploads and shell-execution patterns if GeoNode is exposed.
