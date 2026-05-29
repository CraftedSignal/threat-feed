---
title: Ouroboros-AI Remote Code Execution via Malicious .env File
slug: 2026-05-ouroboros-rce
description: A remote code execution vulnerability exists in Ouroboros-AI versions prior to 0.39.0, enabling attackers to inject malicious scripts via CLI path variables within a cloned repository's .env file, leading to arbitrary code execution when Ouroboros commands are executed.
date: "2026-05-29T21:23:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - vulnerability
  - supply_chain
vendors:
  - ouroboros-ai
products:
  - ouroboros-ai (< 0.39.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-c4m7-2gwp-vw76
  - https://github.com/Q00/ouroboros/pull/1078
rules:
  - title: Detect Suspicious Ouroboros-AI CLI Path Override
    description: Detects potential exploitation of CVE-2026-47211 by monitoring for Ouroboros-AI processes executing CLI tools from unusual paths.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Execution from Suspicious .env Path Override
    description: Detects potential exploitation of CVE-2026-47211 by monitoring for execution of scripts or binaries from paths defined in .env files within a project directory.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote code execution (RCE) vulnerability, identified as CVE-2026-47211, affects Ouroboros-AI versions prior to 0.39.0. This vulnerability allows an attacker to execute arbitrary code on a user's system by exploiting the application's behavior of loading environment variables from a local `.env` file. The attack involves tricking a user into cloning a repository containing a malicious `.env` file that overrides the path to the Ouroboros CLI or related backend tools. This can be achieved by setting variables such as `OUROBOROS_CLI_PATH` or `OPENCODE_CLI_PATH` to point to a malicious script. When the user then executes an Ouroboros command, the attacker's script is executed, leading to potential system compromise. The vulnerability has been patched in version 0.39.0.

## Attack Chain

1.  Attacker creates a malicious repository containing a crafted `.env` file.
2.  The malicious `.env` file includes variables like `OUROBOROS_CLI_PATH` that point to a malicious script within the repository.
3.  Attacker lures a victim into cloning the malicious repository.
4.  Victim navigates into the cloned repository directory.
5.  Victim executes an Ouroboros command such as `ouroboros init`, which triggers the application to load the local `.env` file.
6.  Ouroboros attempts to execute the CLI based on the path specified in the `.env` file.
7.  Instead of the legitimate CLI, the attacker-controlled malicious script is executed.
8.  The malicious script executes arbitrary commands on the victim's system, potentially leading to a full system compromise.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the victim's system. This can lead to a full system compromise, including data theft, installation of malware, and further propagation of the attack. The vulnerability affects any user who clones a malicious repository and executes Ouroboros commands within that directory. The risk is particularly high for users who frequently work with external code repositories.

## Recommendation

*   Upgrade Ouroboros-AI to version 0.39.0 or later to apply the patch that mitigates CVE-2026-47211.
*   If upgrading is not immediately possible, carefully inspect any `.env` file inside cloned repositories for unexpected `OUROBOROS_*_CLI_PATH` or `OPENCODE_CLI_PATH` overrides, as mentioned in the overview.
*   Implement process monitoring to detect execution of unusual scripts in the context of Ouroboros-AI processes, using the rule `Detect Suspicious Ouroboros-AI CLI Path Override`.
