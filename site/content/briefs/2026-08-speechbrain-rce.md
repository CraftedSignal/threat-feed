---
title: Arbitrary Code Execution in SpeechBrain via Insecure YAML Deserialization
slug: 2026-08-speechbrain-rce
description: SpeechBrain versions prior to 1.1.1 are vulnerable to arbitrary code execution when the Checkpointer component parses maliciously crafted CKPT.yaml files using PyYAML's unsafe loader.
date: "2026-08-27T21:10:08Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - SpeechBrain
products:
  - SpeechBrain
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: SpeechBrain before 1.1.1 contains an arbitrary code execution vulnerability that allows attackers to execute arbitrary code by supplying a crafted CKPT.yaml checkpoint metadata file.
    confidence_band: high
cves:
  - id: CVE-2026-10036
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10036
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade SpeechBrain to version 1.1.1 or higher.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-10036 remediation requires updating to version 1.1.1.
  mitigation_plan:
    - priority: immediate
      action: Restrict write permissions on directories scanned by SpeechBrain Checkpointer.
      owner: IT Operations
      addresses: CVE-2026-10036
      evidence: The attack requires writing a crafted CKPT.yaml file to a scanned directory.
---

SpeechBrain versions prior to 1.1.1 contain an arbitrary code execution vulnerability (CVE-2026-10036) stemming from the use of PyYAML's unsafe loader within the `Checkpointer.recover_if_possible()` method. When the library attempts to discover checkpoints, it iterates over available files and parses `CKPT.yaml` metadata. By placing a crafted YAML file containing malicious Python object construction tags, such as `!!python/object/apply`, into a directory monitored by the checkpointer, an attacker can force the application to instantiate arbitrary objects and execute code. The vulnerability is triggered during the candidate enumeration process, meaning the malicious payload is executed even if the checkpoint is not ultimately selected for recovery. This impact is significant for applications using SpeechBrain to process untrusted model checkpoints or operating in shared environments where checkpoint directories are accessible to attackers.

## Attack Chain

1. Attacker identifies a target application utilizing SpeechBrain for model checkpoint management.
2. Attacker gains write access to a directory that is scanned by the application's `Checkpointer` instance.
3. Attacker places a malicious file named `CKPT.yaml` into the target directory.
4. The malicious YAML includes payload tags such as `!!python/object/apply:os.system ['command_here']`.
5. The application calls `Checkpointer.recover_if_possible()` as part of its initialization or model loading lifecycle.
6. The `Checkpointer` enumerates files in the directory and invokes `yaml.load()` (unsafe loader) on the attacker-controlled `CKPT.yaml`.
7. The PyYAML parser interprets the embedded Python tags, resulting in the execution of the attacker's command with the privileges of the application process.
8. Final objective achieved: remote command execution within the application environment.

## Impact

Successful exploitation allows for full arbitrary code execution within the context of the Python process running the SpeechBrain framework. This can lead to unauthorized data exfiltration, system compromise, and the installation of persistent malicious implants on the host server. The vulnerability carries a CVSS v3.1 base score of 8.8, indicating high potential for exploitation in environments where checkpoint locations are not strictly protected or are populated by external sources.

## Recommendation

1. Upgrade SpeechBrain to version 1.1.1 or higher immediately to resolve CVE-2026-10036.
2. Audit all file paths used by the `Checkpointer` to ensure they are read-only for all users except the authorized service account.
3. Implement strict access control lists on directories where model checkpoints are stored to prevent unauthorized file placement.
4. Perform static analysis on codebases utilizing SpeechBrain to identify instances of PyYAML usage with the default `load()` function and enforce the use of `safe_load()`.
