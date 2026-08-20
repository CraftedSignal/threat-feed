---
title: Integer Overflow in Darknet Convolutional Layer Initialization
slug: 2026-08-darknet-heap-overflow
description: An integer overflow vulnerability in the Darknet neural network framework's convolutional layer initialization allows for heap buffer under-allocation and subsequent out-of-bounds memory access via malicious configuration files.
date: "2026-08-20T19:19:27Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - hank-ai
products:
  - darknet
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Loading the crafted .cfg for inference or training is sufficient and no valid .weights file is required.
    confidence_band: high
cves:
  - id: CVE-2026-72852
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72852
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems running Darknet and audit source of configuration (.cfg) files.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-72852 indicates vulnerability in parsing untrusted .cfg files.
  mitigation_plan:
    - priority: immediate
      action: Patch darknet framework or implement file integrity controls on configuration directory.
      owner: IT Operations
      addresses: CVE-2026-72852
      evidence: Vulnerability in src-lib/convolutional_layer.cpp
---

The Darknet framework is vulnerable to an integer overflow during the initialization of convolutional layers, tracked as CVE-2026-72852. The vulnerability exists within `src-lib/convolutional_layer.cpp`, where heap buffer sizing for weights and outputs is calculated by multiplying configuration fields from a provided `.cfg` file using 32-bit integer arithmetic. If the product of these dimensions exceeds the `INT_MAX` limit, the integer wraps around, leading to the allocation of an undersized buffer.

An attacker can trigger this vulnerability by providing a crafted `.cfg` file that specifies dimensions (such as width, height, and number of filters) that force an integer wrap-around. When `forward_convolutional_layer` processes the layer, it re-calculates dimensions and performs memory operations (reads and writes) based on the full expected size, while the underlying buffer remains undersized. This results in out-of-bounds memory access, including heap buffer overflow reads and potential heap metadata corruption, which can lead to application crashes or arbitrary code execution.

## Impact

Successful exploitation allows for heap memory corruption by simply loading a malicious configuration file for inference or training. This impact is significant for environments where untrusted models or configurations are processed, as it can lead to remote code execution or complete system compromise depending on the context in which the Darknet application is running.

## Recommendation

Prioritize patching or updating the Darknet framework to a version that implements safe integer arithmetic (such as checking for overflows before memory allocation) in `src-lib/convolutional_layer.cpp`. Teams managing Darknet-based workloads should restrict the ability to load configuration files from untrusted sources.
