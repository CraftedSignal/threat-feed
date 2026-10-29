---
brief_id: brief-2026-10-27-llama-cpp-heap-overflow
event_id: brief-2026-10-27-llama-cpp-heap-overflow
revision: 2
activity_at: "2026-10-29T15:38:20Z"
revision_history:
  - revision: 2
    at: "2026-10-29T15:38:20Z"
    checksum: sha256:c8b30c2e2a54e0bdc807665c358881d6bca4a80af37efd47a6f3452b6458ab69
    summary: added coverage for llama.cpp (b2877 through b11934)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119052
title: 'llama.cpp: Heap out-of-bounds write in llm_tokenizer_plamo2 (CVE-2026-116816)'
slug: 2026-10-llama-cpp-heap-overflow
description: A heap out-of-bounds write vulnerability in llama.cpp versions b5899 through b10260 allows attackers to achieve memory corruption or potential code execution via maliciously crafted GGUF model files.
date: "2026-10-27T01:52:36Z"
lastmod: "2026-10-29T15:37:47Z"
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
  validation_status: Source-confirmed vulnerability details.
cpes:
  - cpe:2.3:a:llama.cpp:llama.cpp:*:*:*:*:*:*:*:*
tags:
  - heap-overflow
  - vulnerability
  - code-execution
vendors:
  - llama.cpp
products:
  - llama.cpp (b5899 <= version < b10261)
  - llama.cpp (b2877 through b11934)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply BYTE-typed token text like <0x-1> whose negative parsed value writes token ids before the bytes_ buffer during model loading, causing crashes or potential code execution.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated remote attacker can exploit this by sending a command, such as SET_TENSOR, with a message length exceeding std::vector::max_size(). This triggers an uncaught std::length_error exception, leading to an immediate process abort and impacting availability for all connected clients.
    confidence_band: high
cves:
  - id: CVE-2026-116816
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-119052
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116816
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119052
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - Security Operations
  immediate_actions:
    - action: Upgrade llama.cpp to version b10261 or later.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is patched in versions starting from b10261.
    - action: Upgrade llama.cpp deployments to version b11935 or later.
      owner: IT Operations
      due: 72h
      evidence: Source confirms vulnerability in versions b2877 to b11934.
  hunt_leads:
    - lead: Monitor for application crashes involving processes that load GGUF models.
      technique_id: T1203
      data_needed:
        - Endpoint application error logs (e.g., Event ID 1000 on Windows, core dump logs on Linux)
        - Application-specific logs identifying GGUF model loading success or failure
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability causes crashes when processing malicious model files.
    - lead: Identify anomalous network traffic directed at llama.cpp ggml-rpc ports, specifically sequences following the HELLO handshake.
      technique_id: T1498
      data_needed:
        - Network flow logs or PCAP data
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The attack occurs after the HELLO handshake, specifically involving SET_TENSOR command lengths that are non-standard.
  mitigation_plan:
    - priority: immediate
      action: Update llama.cpp to b10261.
      owner: IT Operations
      addresses: CVE-2026-116816
      evidence: NVD advisory specifies version ranges.
    - priority: immediate
      action: Restrict access to the ggml-rpc server via host-based firewalls (iptables/nftables) or cloud security groups.
      owner: Security Operations
      addresses: CVE-2026-119052
      evidence: Vulnerability allows unauthenticated remote exploitation.
updates:
  - at: "2026-10-29T15:37:47Z"
    level: L2
    summary: added coverage for llama.cpp (b2877 through b11934)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119052
---

The llama.cpp library contains a heap out-of-bounds write vulnerability within the `llm_tokenizer_plamo2::build` function. An attacker can supply a crafted GGUF model file containing BYTE-typed token text with negative parsed values (e.g., `<0x-1>`). When the model is loaded, the application attempts to write token IDs into memory before the intended `bytes_` buffer, resulting in heap corruption.

## Impact

Successful exploitation may lead to application crashes or arbitrary code execution within the context of the llama.cpp process. The impact depends on the environment in which the model is being loaded.

## Recommendation

- Update llama.cpp to version b10261 or later immediately to incorporate the patch for CVE-2026-116816.
- Implement strict input validation or sandboxing for GGUF model files loaded from untrusted sources.
- Audit environments that ingest arbitrary GGUF models for unauthorized or unexpected process crashes, which may indicate exploitation attempts.
