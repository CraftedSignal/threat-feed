---
title: Arbitrary Code Execution via hydra.utils.instantiate
slug: 2026-08-hydra-rce
description: The hydra.utils.instantiate() function in hydra-core versions 1.3.3 and below is vulnerable to arbitrary code execution when processing untrusted configuration input, allowing attackers to hijack object instantiation.
date: "2026-08-22T01:17:02Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Meta
products:
  - hydra-core (1.3.3 and earlier)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: If an application passes untrusted config to instantiate(), an attacker who controls _target_ and its arguments can cause arbitrary code execution in the consuming process.
    confidence_band: high
cves:
  - id: CVE-2026-68508
    cvss: 7.8
references:
  - https://github.com/advisories/GHSA-2cp2-2r3c-7p7r
  - https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Application Security
  immediate_actions:
    - action: Inventory all internal applications using hydra-core to assess if they process external/untrusted config.
      owner: Application Security
      due: 72h
      evidence: Source indicates the vulnerability is limited to usage of hydra.utils.instantiate with untrusted config.
  mitigation_plan:
    - priority: immediate
      action: Upgrade hydra-core to 1.3.4 or higher
      owner: IT Operations
      addresses: CVE-2026-68508
      evidence: Remediation section advises upgrading to 1.3.4 for initial hardening.
---

Hydra is a framework used primarily for configuring complex applications, often in the machine learning and research domains. The library provides the `hydra.utils.instantiate()` function, which is designed to dynamically resolve and instantiate Python objects based on provided configuration structures. The vulnerability exists because `instantiate()` acts as a powerful object-construction engine; when a consuming application passes untrusted or semi-trusted configuration - such as model metadata or user-supplied CLI overrides - directly to this function, an attacker who can control the `_target_` field within the configuration can force the application to instantiate arbitrary Python callables. This facilitates arbitrary code execution within the security context of the parent process. This vulnerability (CVE-2026-68508) is a design-level risk common in frameworks that provide recursive instantiation capabilities without default sandboxing or strict allowlisting. Users are advised to upgrade to version 1.3.4, which introduces a blacklist for dangerous targets, or to migrate to the allowlist-based model found in the 1.4 development branch.

## Attack Chain

1. Attacker identifies an application or research tool that consumes external data (e.g., model metadata or config files) and uses Hydra to process it.
2. Attacker prepares a malicious configuration file containing a crafted `_target_` key targeting a dangerous Python callable.
3. Attacker triggers the application to load the malicious configuration (e.g., via file upload, model import, or CLI argument).
4. The application reads the external data and passes the dictionary structure into `hydra.utils.instantiate()`.
5. Hydra resolves the malicious `_target_` string into a Python class or function pointer.
6. Hydra invokes the callable with the attacker-controlled arguments provided in the configuration.
7. The target callable executes, leading to arbitrary system commands or unauthorized logic execution within the host process.

## Impact

Successful exploitation allows for execution of code within the privileges of the target process. This may result in unauthorized access to sensitive data (e.g., environment variables, API keys, training data), unauthorized modification of file systems, or process disruption. The severity is dependent on the role of the process - services running with elevated privileges or on sensitive infrastructure face the highest risk.

## Recommendation

* Upgrade the `hydra-core` package to version 1.3.4 or higher to benefit from the built-in blacklist of dangerous targets (CVE-2026-68508).
* For applications handling untrusted inputs, implement a strict application-side allowlist for `_target_` keys before passing data to `hydra.utils.instantiate()`.
* Audit application code to identify call sites where external data, CLI overrides, or user-provided configuration files reach the `instantiate()` function.
* Monitor for anomalous file access or network connections originating from AI/ML research pipelines or model-loading services.
