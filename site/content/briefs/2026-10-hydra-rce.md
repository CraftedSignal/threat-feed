---
title: Arbitrary Code Execution in hydra-optuna-sweeper
slug: 2026-10-hydra-rce
description: The hydra-optuna-sweeper package allows arbitrary code execution by resolving and invoking untrusted callables provided through the custom_search_space configuration parameter.
date: "2026-10-07T22:53:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hydra:hydra-optuna-sweeper:*:*:*:*:*:*:*:*
tags:
  - arbitrary-code-execution
  - hydra
  - supply-chain
vendors:
  - Hydra
products:
  - hydra-optuna-sweeper (>= 1.2.0, < 1.3.0)
  - hydra-optuna-sweeper (>= 1.4.0.dev4, < 1.4.0.dev10)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The package used the hydra.utils.get_method API to resolve and invoke callables provided via configuration, which fails to enforce execution policies.
    confidence_band: high
cves:
  - id: CVE-2026-106440
    cvss: 7.8
references:
  - https://github.com/advisories/GHSA-5jjj-9xc3-rm56
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade hydra-optuna-sweeper to version 1.3.0 or 1.4.0.dev10 to mitigate CVE-2026-106440
      owner: IT Operations
      due: 48h
      evidence: Source provides fixed versions for CVE-2026-106440.
  mitigation_plan:
    - priority: immediate
      action: Restrict write access to configuration files and command-line overrides used by Hydra applications
      owner: Security Engineering
      addresses: CVE-2026-106440
      evidence: Workaround provided in the GHSA report.
---

The `hydra-optuna-sweeper` package contains a vulnerability (CVE-2026-106440) that permits arbitrary code execution. The vulnerability originates in the handling of the `hydra.sweeper.custom_search_space` configuration parameter. The component incorrectly used the low-level `hydra.utils.get_method()` API to resolve and execute callables specified in the configuration. Because `get_method()` is designed for trusted input, it lacks the safety checks, execution policies, and whitelists enforced by higher-level APIs like `instantiate()`. 

An attacker who can control an application's Optuna configuration or provide command-line overrides can specify a dotted path to any importable Python callable. The application then resolves and executes this code with the full privileges of the host process. This vulnerability affects stable versions from 1.2.0 up to 1.3.0, and development releases from 1.4.0.dev4 to 1.4.0.dev9. The issue was addressed by moving configuration-driven construction to the `instantiate()` helper, which respects security boundaries.

## Attack Chain

1. Attacker gains the ability to influence Hydra application configuration via file modification or command-line overrides.
2. Attacker crafts a malicious `hydra.sweeper.custom_search_space` parameter containing the path to a sensitive importable Python callable.
3. The Hydra application process loads the configuration during the Optuna sweep initialization.
4. The `hydra-optuna-sweeper` component receives the untrusted path from the configuration.
5. The component passes this path directly to `hydra.utils.get_method()`.
6. The `get_method()` API resolves the string path into a callable object in the application memory space.
7. The application invokes the resolved callable, resulting in arbitrary code execution within the context of the application.

## Impact

Successful exploitation results in arbitrary code execution with the privileges of the application process. This allows for full system compromise if the Hydra controller process runs with elevated permissions. The impact is significant for environments where Optuna sweep configurations are generated based on user-supplied parameters or pulled from external sources.

## Recommendation

* Upgrade `hydra-optuna-sweeper` to version 1.3.0 or later for stable releases, or 1.4.0.dev10 or later for development releases, to resolve CVE-2026-106440.
* Ensure that Optuna sweep configuration files and command-line arguments are treated as trusted inputs and are not modifiable by unauthorized users.
* Implement strict access controls on the application environment to prevent untrusted modules or packages from being placed on the Python import path.
