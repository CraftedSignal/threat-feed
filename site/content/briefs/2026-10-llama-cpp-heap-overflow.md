---
brief_id: brief-2026-10-27-llama-cpp-heap-overflow
event_id: brief-2026-10-27-llama-cpp-heap-overflow
revision: 1
activity_at: "2026-10-27T01:52:36Z"
title: 'llama.cpp: Heap out-of-bounds write in llm_tokenizer_plamo2 (CVE-2026-116816)'
slug: 2026-10-llama-cpp-heap-overflow
description: A heap out-of-bounds write vulnerability in llama.cpp versions b5899 through b10260 allows attackers to achieve memory corruption or potential code execution via maliciously crafted GGUF model files.
date: "2026-10-27T01:52:36Z"
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
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply BYTE-typed token text like <0x-1> whose negative parsed value writes token ids before the bytes_ buffer during model loading, causing crashes or potential code execution.
    confidence_band: high
cves:
  - id: CVE-2026-116816
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116816
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade llama.cpp to version b10261 or later.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is patched in versions starting from b10261.
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
  mitigation_plan:
    - priority: immediate
      action: Update llama.cpp to b10261.
      owner: IT Operations
      addresses: CVE-2026-116816
      evidence: NVD advisory specifies version ranges.
---

The llama.cpp library contains a heap out-of-bounds write vulnerability within the `llm_tokenizer_plamo2::build` function. An attacker can supply a crafted GGUF model file containing BYTE-typed token text with negative parsed values (e.g., `<0x-1>`). When the model is loaded, the application attempts to write token IDs into memory before the intended `bytes_` buffer, resulting in heap corruption.

## Impact

Successful exploitation may lead to application crashes or arbitrary code execution within the context of the llama.cpp process. The impact depends on the environment in which the model is being loaded.

## Recommendation

- Update llama.cpp to version b10261 or later immediately to incorporate the patch for CVE-2026-116816.
- Implement strict input validation or sandboxing for GGUF model files loaded from untrusted sources.
- Audit environments that ingest arbitrary GGUF models for unauthorized or unexpected process crashes, which may indicate exploitation attempts.
