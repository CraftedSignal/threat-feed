---
title: Path Traversal Vulnerability in Hugging Face Accelerate
slug: 2026-08-accelerate-traversal
description: Hugging Face Accelerate versions 1.14.0 and earlier contain a path traversal vulnerability in checkpoint loading functions that allows arbitrary file reads or denial of service via named pipes.
date: "2026-08-11T01:37:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - python
vendors:
  - Hugging Face
products:
  - Accelerate (1.14.0)
cves:
  - id: CVE-2026-69112
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69112
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Update Hugging Face Accelerate to a version greater than 1.14.0.
      owner: IT Operations
      due: 48h
      evidence: Source states versions through 1.14.0 are affected.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict filesystem access controls for processes running Accelerate.
      owner: Security Engineering
      addresses: CVE-2026-69112
      evidence: Path traversal allows reading arbitrary files.
---

Hugging Face Accelerate versions up to and including 1.14.0 are affected by a path traversal vulnerability residing within the `load_checkpoint_in_model` and `load_checkpoint_and_dispatch` functions. The vulnerability arises because the library fails to properly sanitize the `weight_map` entries contained within sharded checkpoint index files. 

An attacker capable of providing a malicious checkpoint index can use relative path sequences such as `../` or absolute file paths to force the application to read files outside of the intended directory. Furthermore, by pointing a shard entry at a system named pipe, an attacker can trigger indefinite blocking of the process, resulting in a denial of service. This vulnerability poses a significant risk to environments where model checkpoints are sourced from untrusted or external contributors.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to read arbitrary files from the host system, potentially exposing sensitive configuration files, credentials, or other model data. Additionally, the ability to induce a denial of service via named pipes impacts the availability of machine learning inference or training workloads utilizing the affected library.

## Recommendation

* Update Hugging Face Accelerate to the latest patched version immediately.
* Implement strict validation of all externally sourced model checkpoint index files before processing them with Accelerate.
* Run model training and inference workloads in isolated, containerized environments with restricted filesystem permissions and read-only access to non-essential directories to limit the impact of path traversal.
