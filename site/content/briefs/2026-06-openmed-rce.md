---
title: OpenMed RCE via Malicious Hugging Face Model Loading (CVE-2026-47117)
slug: 2026-06-openmed-rce
description: OpenMed before 1.5.2 is vulnerable to remote code execution (CVE-2026-47117) due to broad substring matching in the PII privacy-filter model loading path, allowing an unauthenticated attacker to execute arbitrary code by supplying a malicious Hugging Face model repository containing custom Transformers code.
date: "2026-06-02T16:20:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - rce
  - huggingface
vendors:
  - Hugging Face
products:
  - OpenMed
  - Transformers
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47117
rules:
  - title: Detect Suspicious OpenMed Model Loading via Hugging Face (CVE-2026-47117)
    description: Detects CVE-2026-47117 exploitation — Suspicious OpenMed model loading via Hugging Face by monitoring network connections for requests with potentially malicious model names.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - network_connection
      - windows
  - title: Detect Unusual Processes Spawned by OpenMed Service
    description: Detects unusual processes spawned by the OpenMed service, potentially indicating code execution following successful exploitation of CVE-2026-47117.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenMed before version 1.5.2 is susceptible to a critical remote code execution vulnerability (CVE-2026-47117) in its PII privacy-filter model loading mechanism. The vulnerability arises from insufficient validation of the `model_name` parameter, which is used to load Hugging Face models. An unauthenticated attacker can exploit this by crafting a malicious model repository hosted on Hugging Face. The attacker leverages the `trust_remote_code=True` setting during model loading and supplies a specially crafted `model_name` containing a substring match that points to their malicious repository. This repository includes custom Transformers code within either `config.json` or `tokenizer_config.json` via the `auto_map` functionality. The injected code is then executed with the same privileges as the OpenMed service process, potentially leading to complete system compromise.

## Attack Chain

1.  An unauthenticated attacker identifies an OpenMed instance running a version prior to 1.5.2.
2.  The attacker crafts a malicious Hugging Face model repository containing a custom Transformers code payload within the `config.json` or `tokenizer_config.json` file, using the `auto_map` feature to trigger code execution.
3.  The attacker crafts a request to the OpenMed server, targeting the PII privacy-filter functionality.
4.  The attacker includes a `model_name` parameter in the request that contains a substring matching a legitimate model name prefix, but redirects to the attacker's malicious repository (e.g., `attacker/foo-privacy-filter-bar`).
5.  OpenMed's privacy-filter dispatcher, due to the broad substring matching, routes the request to load the attacker-controlled model.
6.  The OpenMed service process loads the attacker's malicious model repository from Hugging Face, utilizing the `trust_remote_code=True` setting.
7.  The custom Transformers code within the malicious `config.json` or `tokenizer_config.json` is executed with the privileges of the OpenMed service process.
8.  The attacker achieves remote code execution, enabling them to perform arbitrary actions on the server, such as installing malware, stealing data, or pivoting to other systems.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to achieve remote code execution on the OpenMed server. Given the nature of OpenMed as a platform likely handling sensitive patient data, this could lead to severe data breaches, compliance violations, and reputational damage. The attacker could potentially gain complete control of the server and use it as a staging point for further attacks within the network.

## Recommendation

*   Immediately upgrade OpenMed to version 1.5.2 or later to patch CVE-2026-47117.
*   Implement input validation and sanitization on the `model_name` parameter used for loading Hugging Face models to prevent malicious model names.
*   Monitor network traffic for requests containing suspicious `model_name` parameters that might indicate an attempt to load models from untrusted sources. Deploy the Sigma rule "Detect Suspicious OpenMed Model Loading via Hugging Face (CVE-2026-47117)" to identify potential exploitation attempts.
*   Consider disabling the `trust_remote_code` option for Hugging Face model loading if it is not strictly necessary.
*   Implement a process creation monitoring rule to detect unusual processes spawned by the OpenMed service, referencing the Sigma rule "Detect Unusual Processes Spawned by OpenMed Service".
