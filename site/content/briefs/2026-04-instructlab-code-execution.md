---
title: InstructLab Arbitrary Code Execution via Malicious HuggingFace Model
slug: 2026-04-instructlab-code-execution
description: InstructLab is vulnerable to arbitrary code execution because the `linux_train.py` script hardcodes `trust_remote_code=True` when loading models from HuggingFace, allowing remote attackers to execute code by convincing a user to load a malicious model.
date: "2026-04-22T14:17:07Z"
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

InstructLab contains a critical vulnerability (CVE-2026-6859) in its `linux_train.py` script. The script unconditionally sets `trust_remote_code=True` when interacting with the HuggingFace model hub. This design flaw allows a remote attacker to inject arbitrary Python code into the training process. The attacker only needs to convince a user to execute the `ilab train`, `ilab download`, or `ilab generate` command while specifying a malicious model hosted on HuggingFace. Successful exploitation…
