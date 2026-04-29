---
title: Ray Data Remote Code Execution via Parquet Arrow Extension Type Deserialization
slug: 2026-04-ray-parquet-rce
description: Ray Data is vulnerable to remote code execution via Parquet Arrow Extension Type Deserialization; specifically, a maliciously crafted Parquet file can trigger arbitrary code execution due to the unsafe deserialization of Arrow extension metadata, affecting Ray versions 2.49.0 through 2.54.0.
date: "2026-04-24T16:15:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - remote-code-execution
  - parquet
  - deserialization
  - cloudpickle
  - ray
vendors:
  - Ray
products:
  - Ray Data
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-mw35-8rx3-xf9r
rules:
  - title: Detect Ray Data Parquet Deserialization RCE
    description: Detects attempts to exploit the Ray Data Parquet deserialization vulnerability by searching for Parquet files with suspicious Arrow extension metadata containing potentially malicious cloudpickle payloads.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Process Execution from Ray Worker
    description: Detects suspicious processes spawned by Python interpreters likely running Ray workers, indicative of potential RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Ray Data, a component of the Ray distributed computing framework, is susceptible to remote code execution (RCE) due to unsafe deserialization of Parquet file metadata. The vulnerability stems from Ray's registration of custom Arrow extension types (`ray.data.arrow_tensor`, `ray.data.arrow_tensor_v2`, `ray.data.arrow_variable_shaped_tensor`) within PyArrow. When a Parquet file containing these extension types is processed, the `__arrow_ext_deserialize__` function is invoked, leading to the execution of arbitrary code through `cloudpickle.loads()` on the field's metadata, prior to any data being read.  This issue affects Ray versions 2.49.0 through 2.54.0, introduced in July 2025 via commit `f6d21db1a4`. Successful exploitation does not require authentication or network access to a Ray cluster. Instead, it hinges on the framework reading a maliciously crafted Parquet file, which can originate from various sources like cloud storage, HuggingFace datasets, or shared file systems.

## Attack Chain

1. An attacker crafts a Parquet file containing a column with a `ray.data.arrow_tensor`, `ray.data.arrow_tensor_v2`, or `ray.data.arrow_variable_shaped_tensor` extension type.
2. The attacker injects a malicious payload in the `ARROW:extension:metadata` field of the Parquet file, serialized using `cloudpickle`.
3. The attacker places the crafted Parquet file in a location accessible to a Ray Data pipeline, such as a HuggingFace dataset, a shared filesystem, or a cloud storage bucket.
4. A Ray Data pipeline, using functions like `ray.data.read_parquet()`, `pyarrow.parquet.read_table()`, or `pandas.read_parquet()`, attempts to read the Parquet file.
5. During schema parsing, PyArrow encounters the custom Arrow extension type and automatically calls the `__arrow_ext_deserialize__` method.
6. The `__arrow_ext_deserialize__` method invokes `_deserialize_with_fallback()`, which attempts to deserialize the metadata using `cloudpickle.loads()`.
7. The `cloudpickle.loads()` function executes the attacker's arbitrary code from the crafted Parquet metadata.
8. The attacker achieves arbitrary command execution as the user running the Ray worker process, potentially leading to full server compromise.

## Impact

This vulnerability affects Ray versions 2.49.0 through 2.54.0, impacting any process utilizing Ray Data that reads Parquet files. The global registration of extension types in PyArrow means that all Parquet reads within the affected process are vulnerable. An attacker can achieve arbitrary command execution as the Ray worker process user, leading to full server compromise, without requiring authentication or cluster access. Successful exploitation allows attackers to compromise systems by simply placing a malicious Parquet file in a location that a Ray Data pipeline processes.

## Recommendation

*   Upgrade Ray to a patched version beyond 2.54.0 to remediate the vulnerability, ensuring the fix addresses the `cloudpickle.loads()` call in the deserialization path.
*   Implement strict input validation and sanitization for Parquet files before processing them with Ray Data to prevent the execution of malicious payloads embedded in the `ARROW:extension:metadata` field.
*   Monitor for suspicious process execution originating from `python` processes using `cloudpickle.loads()` with the intent of arbitrary code execution.
*   Deploy the Sigma rule `Detect Ray Data Parquet Deserialization RCE` to detect exploitation attempts by monitoring for specific metadata within Parquet files.
