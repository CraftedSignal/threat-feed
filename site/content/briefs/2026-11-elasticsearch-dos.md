---
brief_id: brief-2026-11-03-elasticsearch-dos
event_id: brief-2026-11-03-elasticsearch-dos
revision: 2
activity_at: "2026-11-05T07:46:27Z"
revision_history:
  - revision: 2
    at: "2026-11-05T07:46:27Z"
    checksum: sha256:40d48ddfe17c777a25c0efb5408c1a7a88e67be1d4509757f571b418dd664765
    summary: exploited:true; poc_available
    changed_fields:
      - claim_state
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=B248C171-9599-539D-A8C9-627438179A86&utm_source=rss&utm_medium=rss
title: 'Elasticsearch: Denial of service via uncontrolled recursion (CVE-2026-115290)'
slug: 2026-11-elasticsearch-dos
description: Elasticsearch contains an uncontrolled recursion vulnerability (CVE-2026-115290) that allows an unauthenticated attacker to trigger node termination via crafted serialized data with nested payloads.
date: "2026-11-03T20:01:41Z"
lastmod: "2026-11-05T07:43:08Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - low
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sploitus.com/exploit?id=B248C171-9599-539D-A8C9-627438179A86&utm_source=rss&utm_medium=rss
  observed_at: "2026-11-05T04:46:56Z"
  confidence: medium
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=B248C171-9599-539D-A8C9-627438179A86&utm_source=rss&utm_medium=rss
tags:
  - denial-of-service
  - cve-2026-115290
  - elasticsearch
vendors:
  - Elastic
products:
  - Elasticsearch
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: Uncontrolled Recursion (CWE-674) in Elasticsearch can lead to denial of service via Serialized Data with Nested Payloads (CAPEC-230).
    confidence_band: high
cves:
  - id: CVE-2026-115290
    cvss: 7.5
    epss: 0.00413
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115290
  - https://sploitus.com/exploit?id=B248C171-9599-539D-A8C9-627438179A86&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to Elasticsearch cluster interfaces to authorized segments only
      owner: IT Operations
      due: 24h
      evidence: An unauthenticated attacker with network access to the remote cluster server interface of a node can send a specially crafted request
  hunt_leads:
    - lead: Identify repeated node crashes or restarts in Elasticsearch server logs
      technique_id: T1499.001
      data_needed:
        - Elasticsearch server logs
        - Systemd/Process management logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated attacker... can send a specially crafted request that causes the node to terminate.
  mitigation_plan:
    - priority: immediate
      action: Apply patch for CVE-2026-115290 once provided by Elastic
      owner: IT Operations
      addresses: CVE-2026-115290
      evidence: NVD advisory CVE-2026-115290
updates:
  - at: "2026-11-05T07:43:08Z"
    level: L3
    summary: exploited:true; poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=B248C171-9599-539D-A8C9-627438179A86&utm_source=rss&utm_medium=rss
---

Elasticsearch is vulnerable to uncontrolled recursion (CWE-674) when processing serialized data containing nested payloads. An unauthenticated attacker with network access to the cluster interface of a node can send a specially crafted request to trigger the flaw. Successful exploitation leads to a denial of service (DoS) by causing the target node to terminate. This attack does not require authentication and can be repeated against any reachable nodes in the cluster.

## Impact
The vulnerability allows an unauthenticated remote attacker to cause a denial of service by forcing the termination of Elasticsearch nodes. The attack is repeatable against every node reachable over the network.

## Recommendation
- Upgrade Elasticsearch to a patched version once released by Elastic.
- Restrict network access to the Elasticsearch management/cluster interfaces to trusted IP ranges only via host or network firewalls to prevent unauthorized access by potential attackers.
- Monitor cluster logs and system metrics for unexpected node termination or recursive stack overflow errors during request processing.
