---
brief_id: brief-2026-11-12-joserfc-cpu-exhaustion-ghsa-jpxq-7h8p-2q76
event_id: brief-2026-11-12-joserfc-cpu-exhaustion-ghsa-jpxq-7h8p-2q76
revision: 1
activity_at: "2026-11-12T03:54:36Z"
title: 'joserfc: CPU exhaustion via unbounded JWE recipients array'
slug: 2026-11-joserfc-cpu-exhaustion-ghsa-jpxq-7h8p-2q76
description: An unauthenticated remote attacker can cause a denial-of-service by submitting a specially crafted JWE General JSON object containing an unbounded number of recipients, forcing the server to perform an excessive number of expensive RSA private-key decryption operations.
date: "2026-11-12T03:54:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: PoC confirmed linear scaling of CPU cost vs recipient count
tags:
  - denial-of-service
  - cwe-400
  - joserfc
  - python
  - cryptography
products:
  - joserfc (< 1.7.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: An unauthenticated network attacker who can send a JWE General JSON document to any endpoint that decrypts it with an RSA key can force the victim to perform an arbitrary, attacker-chosen number of RSA private-key decryption operations.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jpxq-7h8p-2q76
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Upgrade joserfc to version 1.7.5 or later.
      owner: Development Team
      due: 48h
      evidence: Vulnerability addressed in joserfc 1.7.5
  hunt_leads:
    - lead: Identify endpoints accepting JWE General JSON payloads and monitor for unusually long execution times or high CPU spikes associated with specific request URI paths.
      technique_id: T1499.001
      data_needed:
        - Web application logs (latency, status codes)
        - Application performance monitoring (APM) CPU metrics
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker forces the victim to perform an arbitrary number of RSA private-key decryption operations, causing near 1:1 ratio between recipient-count growth and decrypt-time growth.
  mitigation_plan:
    - priority: immediate
      action: Implement request size limits at the WAF or gateway.
      owner: Network Engineering
      addresses: joserfc (< 1.7.5)
      evidence: Linear scaling of request size (~396 bytes/recipient) allows for effective mitigation via payload size inspection.
---

The joserfc library version 1.7.4 and earlier is vulnerable to a CPU exhaustion Denial of Service (DoS) attack. The library's `decrypt_json()` function parses JWE General JSON Serialization objects without enforcing an upper bound on the number of entries in the `recipients` array. An attacker can craft a JWE payload with a large number of RSA-OAEP recipients, forcing the vulnerable application to perform an RSA private-key decryption operation for every recipient present. This behavior occurs unconditionally, even if `verify_all_recipients=False` is set, leading to high CPU usage relative to the size of the submitted request.

## Attack Chain

1. Attacker generates a valid JWE General JSON object using the victim's public RSA key.
2. Attacker adds an arbitrary, large number of recipients to the JWE `recipients` array.
3. Attacker sends the crafted JSON object to a target endpoint that uses `joserfc.jwe.decrypt_json()`.
4. `joserfc` parser iterates through the full `recipients` array without checking the count.
5. The library unconditionally invokes `decrypt_recipient()` for each entry in the list.
6. For each recipient, the library performs a computationally expensive RSA private-key decryption operation.
7. High CPU usage is sustained for the duration of these operations, resulting in service degradation or availability loss.

## Impact

Successful exploitation results in a Denial of Service (DoS) via resource exhaustion. The vulnerability is highly asymmetric, where relatively small malicious HTTP requests induce disproportionately high CPU load on the victim's server. No confidentiality or integrity impact was observed.

## Recommendation

Upgrade `joserfc` to version 1.7.5 or later. If upgrading is not immediately possible, implement a request-size limit at the Web Application Firewall (WAF) or application gateway level that corresponds to a reasonable number of recipients to mitigate the attack surface until the library is patched.
