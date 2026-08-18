---
title: Arbitrary Code Execution in MONAI NumpyReader
slug: 2026-08-monai-rce
description: The MONAI library contains a hardcoded insecure deserialization vulnerability in NumpyReader, allowing arbitrary code execution when processing malicious .npy or .npz files.
date: "2026-08-18T20:57:21Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - NVIDIA
vendors:
  - NVIDIA
products:
  - MONAI (1.6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The allow_pickle=True parameter enables Python's pickle protocol during numpy loading, which is known to be unsafe for untrusted data, as it can execute arbitrary code during deserialization.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wg9g-w2j2-8pgr
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Research Engineering
  immediate_actions:
    - action: Upgrade MONAI to version 1.6.0 or later across all training and inference environments.
      owner: IT Operations
      due: 24h
      evidence: Affected packages < 1.6.0
  mitigation_plan:
    - priority: immediate
      action: Restrict read/write permissions on shared dataset repositories and storage locations.
      owner: IT Operations
      addresses: Dataset poisoning vector
      evidence: 'Impact: Dataset poisoning'
---

The `NumpyReader` class in the MONAI medical imaging framework (specifically `monai/data/image_reader.py`) contains a critical security flaw where `numpy.load` is invoked with `allow_pickle=True`. This parameter is hardcoded and cannot be overridden by end users via keyword arguments. Because the `LoadImage` transform automatically selects `NumpyReader` for all `.npy` and `.npz` files, any automated data pipeline or dataset processing workflow - including `PersistentDataset` or `CacheDataset` - becomes a vector for arbitrary code execution. The vulnerability stems from Python's pickle protocol, which can be leveraged to execute arbitrary code during the deserialization of untrusted objects within a data file. This vulnerability affects all MONAI versions prior to 1.6.0.

## Attack Chain

1. Attacker creates a malicious serialized Python object using the `__reduce__` method to define the payload (e.g., `os.system` commands).
2. Attacker writes this object to a `.npy` or `.npz` file using `np.save`.
3. Attacker poisons a shared research dataset or contributes the malicious file to a public repository, tutorial, or MONAI bundle.
4. Victim downloads or maps the malicious dataset to their local environment or server.
5. Victim initiates a MONAI data pipeline (e.g., training loop or inference script) that invokes `LoadImage`.
6. `LoadImage` identifies the file extension and triggers `NumpyReader.read()`.
7. `NumpyReader` calls `np.load(filename, allow_pickle=True)`.
8. Python deserializes the malicious payload, resulting in execution of attacker-supplied code within the process context.

## Impact

Successful exploitation results in arbitrary code execution on the server or workstation processing the medical data. This poses significant risks in clinical and research environments, potentially leading to unauthorized access to protected health information (PHI), lateral movement within institutional networks, and compromise of high-performance computing clusters used for medical image analysis.

## Recommendation

Prioritize immediate remediation and containment:
- Upgrade the MONAI library to version 1.6.0 or higher immediately.
- Audit all data pipelines and research environments for untrusted `.npy` or `.npz` file sources.
- Isolate high-performance computing environments where shared datasets are processed from sensitive network segments until updates are verified.
- Restrict filesystem access to dataset directories to prevent unauthorized modification by low-privileged users or external contributors.
