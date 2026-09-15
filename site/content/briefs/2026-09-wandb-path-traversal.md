---
title: Path Traversal in Weights & Biases wandb
slug: 2026-09-wandb-path-traversal
description: The Weights & Biases wandb library before version 0.29.0 is vulnerable to path traversal via the File.download function, allowing an attacker-controlled backend to write files to arbitrary locations.
date: "2026-09-15T03:38:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wandb:wandb:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - python
vendors:
  - Weights & Biases
products:
  - wandb (< 0.29.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker controlling the backend can supply file names with directory traversal sequences to write files outside the intended download directory
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: potentially enabling code execution through modification of shell startup files or Python import paths
    confidence_band: high
cves:
  - id: CVE-2026-91771
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91771
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade wandb to 0.29.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-91771
  mitigation_plan:
    - priority: immediate
      action: Update wandb to 0.29.0 or later
      owner: IT Operations
      addresses: CVE-2026-91771
      evidence: NVD advisory for CVE-2026-91771
---

Weights & Biases wandb versions prior to 0.29.0 contain a high-severity path traversal vulnerability in the File.download function. The library fails to validate filenames returned by server responses, allowing an attacker who controls the backend infrastructure to inject directory traversal sequences. By successfully manipulating the file path, the attacker can force the client-side wandb process to write files outside of the intended download directory. This creates a significant security risk, as the attacker may be able to achieve Remote Code Execution (RCE) by overwriting critical system files, such as shell configuration files (e.g., .bashrc, .zshrc) or files within Python site-packages that are loaded at runtime.

## Impact

Successful exploitation allows an attacker to achieve arbitrary file writes on the host system. Depending on the environment, this can result in total system compromise, exfiltration of sensitive information, or the execution of malicious code under the context of the user running the wandb library. This vulnerability affects any data science or machine learning pipeline utilizing vulnerable versions of wandb to pull artifacts from a backend server.

## Recommendation

* Upgrade the wandb library to version 0.29.0 or later immediately to include path validation in the File.download function.
* Restrict the use of untrusted or unverified backend servers for downloading artifacts via wandb.
* Monitor local file system activity for unexpected file writes originating from Python interpreter processes.
