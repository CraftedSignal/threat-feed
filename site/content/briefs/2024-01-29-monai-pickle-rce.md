---
title: MONAI Library Vulnerable to Arbitrary Code Execution via Pickle Deserialization
slug: 2024-01-29-monai-pickle-rce
description: The MONAI library is vulnerable to arbitrary code execution due to insecure deserialization of pickle files via the `algo_from_pickle` function, allowing attackers to execute arbitrary code by providing a malicious pickle file.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - monai
  - pickle
  - rce
  - insecure-deserialization
  - python
vendors:
  - MONAI
products:
  - MONAI
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://github.com/advisories/GHSA-89gg-p5r5-q6r4
rules:
  - title: Detect Suspicious Pickle Deserialization in MONAI
    description: Detects the execution of `algo_from_pickle` with a suspicious pickle file in MONAI, indicating a potential insecure deserialization attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Process Launched by Python Pickle
    description: Detects processes spawned by Python after deserializing a pickle file, indicating potential code execution from pickle deserialization
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The MONAI library, a PyTorch-based framework for medical image analysis, is susceptible to arbitrary code execution due to insecure deserialization of pickle files. The vulnerability resides within the `algo_from_pickle` function located in `monai/auto3dseg/utils.py`. This function directly employs `pickle.loads` without implementing any form of input validation, creating a critical security gap. An attacker can exploit this vulnerability by crafting a malicious pickle file containing embedded code that, when deserialized using the vulnerable function, leads to arbitrary code execution on the system. This vulnerability affects MONAI versions 1.5.1 and earlier. Defenders should implement checks for pickle files being processed by MONAI applications.

## Attack Chain

1.  Attacker crafts a malicious Python class with a `__reduce__` method to execute arbitrary commands.
2.  The malicious class is serialized into a pickle file using `pickle.dumps`.
3.  The attacker delivers the malicious pickle file (e.g., `attack_algo.pkl`) to the target system. Delivery method is not specified in the source.
4.  The vulnerable `algo_from_pickle` function is called with the path to the malicious pickle file as an argument.
5.  `algo_from_pickle` opens the pickle file in read-binary mode ("rb").
6.  The contents of the pickle file are read into the `data_bytes` variable.
7.  `pickle.loads(data_bytes)` is executed, deserializing the malicious pickle data.
8.  Due to the crafted `__reduce__` method within the malicious class, arbitrary code execution occurs, such as launching `calc.exe`.

## Impact

Successful exploitation of this vulnerability enables arbitrary code execution on the target system. This can lead to a complete compromise of the system, including data theft, modification, or destruction. The reported proof-of-concept uses calc.exe. This vulnerability affects MONAI versions 1.5.1 and earlier.

## Recommendation

*   Implement file integrity monitoring on MONAI installations to detect unauthorized modifications to the `monai/auto3dseg/utils.py` file.
*   Deploy the Sigma rule `Detect Suspicious Pickle Deserialization in MONAI` to detect exploitation attempts.
*   Upgrade to a patched version of MONAI that addresses the insecure deserialization vulnerability; versions later than 1.5.1 are not vulnerable.
*   Implement input validation and sanitization for any file paths passed to the `algo_from_pickle` function to prevent the processing of untrusted files.
