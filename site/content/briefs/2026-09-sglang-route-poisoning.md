---
title: Unauthenticated Routing Table Poisoning in SGLang
slug: 2026-09-sglang-route-poisoning
description: SGLang versions up to 0.5.19 in disaggregation mode expose an unauthenticated PUT /route endpoint allowing remote attackers to poison KV transfer tables and redirect sensitive data.
date: "2026-09-17T17:58:41Z"
lastmod: "2026-09-18T18:08:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:sglang:sglang:*:*:*:*:*:*:*:*
tags:
  - sglang
  - routing-poisoning
  - cve-2026-92972
  - denial-of-service
  - vulnerability
vendors:
  - SGLang
products:
  - SGLang (<= 0.5.19)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can supply arbitrary rank_ip and rank_port values to redirect decode workers to attacker-controlled endpoints, causing denial of service.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Unauthenticated attackers can reach the decode engine's POST /generate endpoint and submit arbitrary bootstrap_room values to exhaust prefill process memory until out-of-memory termination.
    confidence_band: high
cves:
  - id: CVE-2026-92972
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92972
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93688
rules:
  - title: Detect Unauthenticated PUT /route Request to SGLang
    description: Detects exploitation attempts against CVE-2026-92972 where an attacker sends a PUT request to the /route endpoint of the SGLang service.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to SGLang prefill bootstrap service ports
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92972 allows unauthenticated remote routing table manipulation.
  enrichment_needed:
    - item: SGLang deployment inventory
      owner: CTI
      reason: Identify which systems are configured in disaggregation mode.
      evidence: Only affected in prefill/decode disaggregation mode.
  mitigation_plan:
    - priority: immediate
      action: Upgrade SGLang to a version post-0.5.19
      owner: IT Operations
      addresses: CVE-2026-92972
      evidence: NVD vulnerability entry
updates:
  - at: "2026-09-18T18:08:39Z"
    level: L1
    summary: added coverage for SGLang (<= 0.5.19)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93688
---

SGLang versions through 0.5.19 are vulnerable to a critical routing table poisoning flaw when operating in prefill/decode disaggregation mode. The prefill bootstrap service exposes an unauthenticated PUT /route endpoint, which lacks access controls, allowing unauthorized actors to inject arbitrary 'rank_ip' and 'rank_port' values into the internal KV transfer routing table. By manipulating this table, attackers can redirect traffic destined for decode workers to attacker-controlled infrastructure. Successful exploitation results in a denial-of-service condition for the affected model pipeline and the exfiltration of sensitive KV transfer metadata, including session identifiers and internal tensor-parallel topology parameters. This vulnerability is particularly impactful for distributed inference deployments relying on the disaggregated architecture of SGLang.

## Impact

Successful exploitation enables attackers to intercept or disrupt model inference traffic. This can lead to the unauthorized disclosure of proprietary session metadata and internal topology information, as well as a complete denial of service for the disaggregated model inference cluster. The impact affects any organization utilizing SGLang in the specified disaggregation configuration.

## Recommendation

* Immediately upgrade SGLang to a version beyond 0.5.19 to address the unauthorized access to the routing configuration.
* Implement network-level access control lists (ACLs) to restrict access to the SGLang prefill bootstrap service ports to known-trusted internal management IPs only.
* Audit web access logs for PUT requests directed to the /route endpoint that originate from untrusted or external network segments.
* Monitor for unexpected network connections from decode worker nodes to unknown or unauthorized destination IP addresses.
