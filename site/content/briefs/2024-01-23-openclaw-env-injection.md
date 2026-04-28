---
title: OpenClaw Environment Variable Injection Vulnerability
slug: 2024-01-23-openclaw-env-injection
description: The openclaw package versions prior to 2026.4.10 are vulnerable to environment variable injection, where the exec environment policy missed interpreter startup variables allowing operator-supplied environment overrides to influence downstream execution or network behavior, addressed in versions 2026.4.10 and later.
date: "2026-04-17T21:54:20Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - npm
  - openclaw
  - environment-variable-injection
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://github.com/advisories/GHSA-vfp4-8x56-j7c5
rules:
  - title: Detect Process Execution with Suspicious Environment Variables
    description: Detects process execution with environment variables that may indicate an attempt to exploit the openclaw vulnerability
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Execution with HOSTALIASES Environment Variable
    description: Detects process execution with HOSTALIASES variable
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `openclaw` package, a tool used within the npm ecosystem, was found to have a vulnerability affecting versions prior to 2026.4.10. This vulnerability stems from an inadequate environment variable denylist in the exec environment policy. Specifically, the policy failed to block high-risk interpreter startup variables such as `VIMINIT`, `EXINIT`, `LUA_INIT`, and `HOSTALIASES`. This oversight allowed malicious actors to potentially inject arbitrary environment variables, thereby influencing the behavior of downstream execution or network operations. The vulnerability was reported by @feiyang666 of Tencent zhuque Lab. The fix was implemented in version 2026.4.10 and later, with version 2026.4.14 containing the fix as well. This vulnerability allows for potential code execution or network manipulation through environment variables.

## Attack Chain

1. An attacker gains control over an environment where the vulnerable `openclaw` package is utilized.
2. The attacker identifies that the `openclaw` version is prior to 2026.4.10.
3. The attacker injects a malicious environment variable, such as `VIMINIT`, `EXINIT`, `LUA_INIT`, or `HOSTALIASES`, into the system's environment.
4. The `openclaw` package executes a process that reads and utilizes environment variables without proper sanitization.
5. The injected environment variable overrides the intended behavior of the process. For example, `VIMINIT` can be used to execute arbitrary vim commands upon startup.
6. This execution leads to arbitrary code execution or modified network behavior, depending on the injected variable. For example, `HOSTALIASES` can redirect network requests to attacker-controlled servers.
7. The attacker achieves their objective, such as gaining unauthorized access, exfiltrating data, or causing denial of service.
8. The attacker leverages the compromised environment to propagate the attack further.

## Impact

The vulnerability allows for arbitrary code execution or network redirection by injecting malicious environment variables. Successful exploitation could lead to unauthorized access to sensitive data, system compromise, or denial-of-service conditions. The specific impact depends on the context in which `openclaw` is used and the permissions of the user running the affected process. The reported vulnerability has been fixed in `openclaw` version 2026.4.10 and later.

## Recommendation

*   Upgrade the `openclaw` package to version 2026.4.10 or later to remediate the vulnerability, as indicated in the advisory ([https://github.com/advisories/GHSA-vfp4-8x56-j7c5](https://github.com/advisories/GHSA-vfp4-8x56-j7c5)).
*   Monitor process execution for the presence of environment variables being passed to child processes, focusing on `VIMINIT`, `EXINIT`, `LUA_INIT`, and `HOSTALIASES`. Implement the Sigma rule below to detect suspicious process execution involving these variables.
*   Implement a system-wide policy to restrict the modification of environment variables by non-administrative users.
