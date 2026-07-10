---
title: BentoML Dockerfile Command Injection via bentofile.yaml
slug: 2024-01-bentoml-rce
description: BentoML is vulnerable to Dockerfile command injection via the `docker.system_packages` field in `bentofile.yaml`, allowing arbitrary command execution during `bentoml containerize` / `docker build`.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - docker
  - bentoml
  - CVE-2026-33744
vendors:
  - BentoML
products:
  - BentoML
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-jfjg-vc52-wqvf
rules:
  - title: Detect BentoML System Packages Command Injection
    description: Detects command injection attempts via the system_packages field in bentofile.yaml.  This rule identifies suspicious characters and commands commonly used in command injection attacks.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
  - title: Detect Docker Build Executing Suspicious Commands in /tmp
    description: Detects docker builds executing suspicious commands in the /tmp directory, which may indicate command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

BentoML is susceptible to a command injection vulnerability due to unsanitized input in the `docker.system_packages` field of the `bentofile.yaml` configuration file. This flaw allows an attacker to inject arbitrary commands into the Dockerfile `RUN` instruction during the containerization process. The vulnerability exists because the `system_packages` values, intended to be OS package names, are directly incorporated into shell commands without proper escaping or validation. All versions supporting the `docker.system_packages` feature in `bentofile.yaml` are affected, with version 1.4.36 confirmed to be vulnerable. Attackers can exploit this by crafting a malicious `bentofile.yaml` that executes arbitrary code during the `bentoml containerize` or `docker build` operations, potentially compromising CI/CD pipelines, BentoCloud infrastructure, or the broader BentoML ecosystem. This vulnerability is tracked as CVE-2026-33744.

## Attack Chain

1. An attacker crafts a malicious `bentofile.yaml` file containing a command injection payload within the `docker.system_packages` field.
2. A user clones or downloads the ML project containing the malicious `bentofile.yaml`.
3. The user executes the `bentoml build` command, which parses the `bentofile.yaml` and generates a Dockerfile.
4. The `bentoml containerize` command or `docker build` is executed using the generated Dockerfile.
5. During the Docker build process, the injected command from `system_packages` is executed as root within the container. Specifically, this occurs due to the unsanitized string formatting in `src/_bentoml_sdk/images.py`, where the package list is directly injected into the `apt-get install` command.
6. The injected command achieves arbitrary code execution on the system building the Docker image.
7. The attacker gains unauthorized access to the system or exfiltrates sensitive information.
8. The attacker potentially compromises CI/CD pipelines or cloud infrastructure if the build process is automated.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands with root privileges on the system building the Docker image. This could lead to complete system compromise, data exfiltration, or denial of service. The impact includes potentially malicious repositories spreading through the ML community, compromised CI/CD pipelines running `bentoml containerize` on pull requests, and potential remote code execution (RCE) on BentoCloud infrastructure if it builds images from user-supplied `bentofile.yaml`. The wide adoption of shared bentos and model repositories in the BentoML ecosystem amplifies the supply chain risk.

## Recommendation

*   Deploy the Sigma rule "Detect BentoML System Packages Command Injection" to identify attempts to exploit this vulnerability (rules).
*   Apply the input validation fix described in the advisory to `system_packages` in `build_config.py` (references).
*   Upgrade to a patched version of BentoML that includes the recommended fixes to prevent command injection (Affected Packages).
*   Monitor CI/CD pipelines for modifications to `bentofile.yaml` and implement strict code review processes (overview).
*   Scan existing BentoML projects and Bento repositories for malicious `bentofile.yaml` files (overview).
