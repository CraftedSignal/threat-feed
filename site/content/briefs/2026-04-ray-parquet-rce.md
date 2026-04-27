---
title: Ray Data Remote Code Execution via Parquet Arrow Extension Type Deserialization
slug: 2026-04-ray-parquet-rce
description: Ray Data is vulnerable to remote code execution via Parquet Arrow Extension Type Deserialization; specifically, a maliciously crafted Parquet file can trigger arbitrary code execution due to the unsafe deserialization of Arrow extension metadata, affecting Ray versions 2.49.0 through 2.54.0.
date: "2026-04-24T16:15:00Z"
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

Ray Data, a component of the Ray distributed computing framework, is susceptible to remote code execution (RCE) due to unsafe deserialization of Parquet file metadata. The vulnerability stems from Ray's registration of custom Arrow extension types (`ray.data.arrow_tensor`, `ray.data.arrow_tensor_v2`, `ray.data.arrow_variable_shaped_tensor`) within PyArrow. When a Parquet file containing these extension types is processed, the `__arrow_ext_deserialize__` function is invoked, leading to the…
