---
title: Heap-Based Buffer Overflow in CTranslate2 Binary Model Loader
slug: 2026-09-ctranslate2-buffer-overflow
description: A heap-based buffer overflow vulnerability in the CTranslate2 binary model loader allows attackers to achieve arbitrary code execution via maliciously crafted model files.
date: "2026-09-29T16:28:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opennmt:ctranslate2:*:*:*:*:*:*:*:*
vendors:
  - OpenNMT
products:
  - CTranslate2 (< 4.8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can craft malicious model files with oversized payload lengths to write past heap allocation boundaries, causing crashes or arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-102566
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102566
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade CTranslate2 to version 4.8.1 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies version 4.8.1 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 4.8.1 or later.
      owner: IT Operations
      addresses: CVE-2026-102566
      evidence: NVD advisory
---

CTranslate2 versions prior to 4.8.1 contain a heap-based buffer overflow vulnerability residing in the binary model loader. The flaw stems from a failure to correctly validate the payload length within a model file against the allocated heap buffer size. By crafting a malicious model file with an oversized payload, an attacker can trigger an out-of-bounds write beyond the intended heap allocation boundaries. This vulnerability is critical for applications utilizing the CTranslate2 engine for model inference, as it provides a path for remote code execution or application-level denial-of-service via process crashes. Defenders should identify all environments where CTranslate2 is deployed and prioritize upgrading to version 4.8.1 or later to mitigate the risk of arbitrary code execution stemming from model ingestion.

## Impact

Successful exploitation of this vulnerability allows for arbitrary code execution in the context of the process running the CTranslate2 library, or a denial-of-service condition if the overflow triggers a crash. The impact is significant for organizations performing model inference on untrusted or externally sourced machine learning models, potentially exposing the underlying host or container environment.

## Recommendation

- Upgrade all instances of CTranslate2 to version 4.8.1 or later immediately.
- Implement strict source validation for all model files processed by the CTranslate2 binary loader to prevent the ingestion of untrusted or malformed binary files.
- Monitor process integrity logs for crashes associated with model loading services using CTranslate2, as these may indicate exploitation attempts.
