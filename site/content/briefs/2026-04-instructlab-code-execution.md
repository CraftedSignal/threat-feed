---
title: InstructLab Arbitrary Code Execution via Malicious HuggingFace Model
slug: 2026-04-instructlab-code-execution
description: InstructLab is vulnerable to arbitrary code execution because the `linux_train.py` script hardcodes `trust_remote_code=True` when loading models from HuggingFace, allowing remote attackers to execute code by convincing a user to load a malicious model.
date: "2026-04-22T14:17:07Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve
  - code-execution
  - huggingface
  - instructlab
vendors:
  - Red Hat
products:
  - InstructLab
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6859
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6859
  - https://access.redhat.com/security/cve/CVE-2026-6859
  - https://bugzilla.redhat.com/show_bug.cgi?id=2459998
rules:
  - title: Detect InstructLab Loading Models with trust_remote_code Enabled
    description: Detects when the `linux_train.py` script is executed, and loads models with `trust_remote_code=True` which might indicate a vulnerability exploitation attempt (CVE-2026-6859).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Execution from /tmp by InstructLab
    description: Detects execution of files from the /tmp directory by InstructLab processes, which is often used for exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

InstructLab contains a critical vulnerability (CVE-2026-6859) in its `linux_train.py` script. The script unconditionally sets `trust_remote_code=True` when interacting with the HuggingFace model hub. This design flaw allows a remote attacker to inject arbitrary Python code into the training process. The attacker only needs to convince a user to execute the `ilab train`, `ilab download`, or `ilab generate` command while specifying a malicious model hosted on HuggingFace. Successful exploitation results in arbitrary code execution within the context of the InstructLab process, potentially leading to complete system compromise.

## Attack Chain

1.  Attacker creates a malicious model on the HuggingFace Hub. This model contains embedded Python code designed for malicious purposes.
2.  Attacker social engineers a user to execute `ilab train`, `ilab download`, or `ilab generate` commands.
3.  User executes the command, specifying the attacker's malicious model from the HuggingFace Hub.
4.  The `linux_train.py` script, due to the hardcoded `trust_remote_code=True`, downloads the malicious model.
5.  The script loads the model, triggering the execution of the attacker's embedded Python code.
6.  The attacker's code executes within the InstructLab process, allowing for arbitrary actions.
7.  The attacker achieves persistence by modifying system files or creating new services.
8.  The attacker gains full control of the compromised system, potentially exfiltrating data or causing further damage.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary Python code on the target system. This can lead to complete system compromise, allowing the attacker to steal sensitive data, install malware, or disrupt operations. While the number of affected systems is currently unknown, any system running a vulnerable version of InstructLab and interacting with the HuggingFace Hub is at risk.

## Recommendation

*   Deploy the Sigma rules provided below to detect suspicious process creation events related to InstructLab executing code from temporary directories or with unusual network activity.
*   Monitor process creation events for the execution of Python scripts with `trust_remote_code=True` within InstructLab's processes using the provided Sigma rule.
*   Implement strict controls and validation for models downloaded from HuggingFace, even if `trust_remote_code=True` is required.
*   Apply any available patches or updates for InstructLab to address CVE-2026-6859 as provided by Red Hat.
