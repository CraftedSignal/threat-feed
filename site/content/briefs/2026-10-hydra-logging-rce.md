---
title: Arbitrary Code Execution in Hydra-core via Unsafe Logging Configuration
slug: 2026-10-hydra-logging-rce
description: Hydra-core versions prior to 1.3.6 and 1.4.0.dev9 are vulnerable to arbitrary code execution due to improper validation of logging configuration passed to dictConfig, allowing attackers to invoke arbitrary Python callables.
date: "2026-10-07T22:53:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:meta:hydra-core:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - hydra-core
  - python
vendors:
  - Meta
products:
  - hydra-core (< 1.3.6, >= 1.4.0.dev0, < 1.4.0.dev9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker who can control a Hydra logging configuration can use a custom class or factory to execute code with the application's privileges when Hydra configures logging.
    confidence_band: high
cves:
  - id: CVE-2026-106441
    cvss: 7.8
references:
  - https://github.com/advisories/GHSA-c3wx-c55w-pxjq
  - https://hydra.cc/docs/advanced/execution_whitelist/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade affected Hydra-core instances to version 1.3.6 or 1.4.0.dev9.
      owner: IT Operations
      due: 24h
      evidence: Source remediation section.
  mitigation_plan:
    - priority: immediate
      action: Restrict logging configuration input sources.
      owner: Application Security
      addresses: CVE-2026-106441
      evidence: Remediation note to not compose logging from untrusted sources.
---

Hydra-core, a configuration management framework, suffers from a critical vulnerability (CVE-2026-106441) where logging configurations are processed unsafely. The application passes user-controlled logging configuration directly to Python's `logging.config.dictConfig()` function. Because the logging configurator resolves and invokes importable classes and factories, an attacker capable of providing a configuration file or modifying application settings can force the application to instantiate arbitrary Python objects. 

This bypasses Hydra's existing `instantiate()` target policy because the logging configuration path does not utilize that mechanism. Successful exploitation results in arbitrary code execution running with the privileges of the host application process. Hydra 1.3.6 introduces a blacklist to mitigate this, while Hydra 1.4.0.dev9 implements a more robust execution whitelist approach, which is the recommended security boundary for production environments.

## Impact

Successful exploitation allows for remote code execution in any application utilizing an affected version of `hydra-core` that permits external or untrusted input to define its logging configuration. This could lead to full system compromise, data exfiltration, or lateral movement within the environment where the Hydra-based application is deployed.

## Recommendation

* Upgrade to Hydra 1.3.6 or later, or 1.4.0.dev9 or later for users on the 1.4 prerelease branch to address CVE-2026-106441.
* For Hydra 1.4 deployments, implement an execution whitelist via trusted Python code to strictly constrain callable selection.
* Audit application configuration files to ensure that logging settings are not derived from untrusted user input or external, unverified sources.
* Review the official Hydra execution whitelist documentation to ensure proper implementation of the new primary security boundary.
