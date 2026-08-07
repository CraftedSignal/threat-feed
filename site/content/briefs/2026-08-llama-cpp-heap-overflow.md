---
title: Heap Buffer Overflow in llama.cpp KV Cache Restoration
slug: 2026-08-llama-cpp-heap-overflow
description: A heap buffer overflow vulnerability in llama.cpp builds b4882 through b9058 allows attackers with write access to the slot_save_path directory to achieve arbitrary code execution via malicious KV cache state files.
date: "2026-08-06T23:30:22Z"
lastmod: "2026-08-07T01:30:06Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - ggerganov
products:
  - llama.cpp (b4882-b9058)
  - llama.cpp (b1886-b7445)
  - llama.cpp
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Exploitation can lead to heap memory corruption, model weight corruption, or arbitrary code execution via function pointer overwriting.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The vulnerability can be exploited to cause a denial-of-service condition via SIGSEGV.
    confidence_band: high
cves:
  - id: CVE-2026-43629
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43629
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70638
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43628
rules:
  - title: Detects CVE-2026-43628 Exploitation - Malicious dry_allowed_length Parameter
    description: Detects exploitation attempts against CVE-2026-43628 where the dry_allowed_length parameter is set to INT32_MIN in requests to completion endpoints.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade llama.cpp to build b9059 or later to address CVE-2026-43629
      owner: IT Operations
      due: 48h
      evidence: Source documentation of vulnerability in builds b4882 through b9058
  mitigation_plan:
    - priority: immediate
      action: Tighten filesystem permissions on the slot_save_path directory
      owner: IT Operations
      addresses: CVE-2026-43629
      evidence: Vulnerability requires write access to the slot_save_path directory
updates:
  - at: "2026-08-06T23:31:48Z"
    level: L1
    summary: OS android
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70638
  - at: "2026-08-07T01:30:06Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-43628 Exploitation - Malicious dry_allowed_length Parameter'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-43628
---

The llama.cpp project is affected by a heap buffer overflow vulnerability, identified as CVE-2026-43629, impacting builds from b4882 through b9058. The issue resides in the state_read_data() function, which is responsible for restoring the Key-Value (KV) cache state. During this process, the application performs size calculations for memory allocation without sufficient overflow checks. Specifically, the multiplication of the cell_count can result in an integer overflow, leading to an undersized tensor buffer allocation. An attacker who can write files to the configured slot_save_path directory can provide a crafted state file to trigger this overflow, writing arbitrary data beyond the allocated buffer boundaries. This allows for heap metadata corruption, model weight tampering, or arbitrary code execution through the overwriting of function pointers in memory.

## Impact

Successful exploitation of this vulnerability in environments utilizing llama.cpp for model inference allows local attackers with filesystem access to the application's storage paths to achieve code execution under the security context of the llama.cpp process. This poses a significant risk to servers hosting local LLM inference services where users or secondary processes have permissions to drop files into the llama.cpp working directory.

## Recommendation

1. Upgrade all llama.cpp installations currently running builds between b4882 and b9058 to build b9059 or later immediately.
2. Restrict write access to the directory designated for slot_save_path to only authorized users or service accounts to prevent the placement of malicious state files.
3. Audit filesystem permissions for all directories used by llama.cpp to ensure least privilege is applied to input/output paths.
