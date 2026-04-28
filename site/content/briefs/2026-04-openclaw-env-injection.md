---
title: OpenClaw CLI Backend Environment Variable Injection (CVE-2026-4039)
slug: 2026-04-openclaw-env-injection
description: OpenClaw versions prior to 2026.3.24 are vulnerable to environment variable injection via a malicious workspace configuration, potentially allowing attackers to execute arbitrary code.
date: "2026-04-08T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-4039
  - environment variable injection
  - openclaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-4039
    cvss: 6.3
    epss: 0.00087
references:
  - https://github.com/advisories/GHSA-vfw7-6rhc-6xxg
rules:
  - title: Detect OpenClaw CLI Execution with Suspicious Environment Variables
    description: Detects OpenClaw CLI execution with command line arguments indicative of environment variable injection attempts, by looking for common injection strings.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw CLI Modification Attempts via Environment Variables
    description: Detects attempts to modify OpenClaw behavior using environment variables, a common injection technique.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw versions 2026.3.23-2 and earlier contain a vulnerability (CVE-2026-4039) that allows for environment variable injection when processing workspace configurations. An attacker can craft a malicious workspace configuration file that, when processed by the OpenClaw CLI backend, injects arbitrary environment variables. This can lead to the execution of arbitrary code with the privileges of the OpenClaw process. The vulnerability was reported by @YLChen-007 and a fix was implemented in commit `c2fb7f1948c3226732a630256b5179a60664ec24` and released in version 2026.3.24. This vulnerability poses a significant risk to systems using affected versions of OpenClaw as it can allow for full system compromise.

## Attack Chain

1.  Attacker crafts a malicious OpenClaw workspace configuration file containing environment variable injection payloads.
2.  The malicious workspace configuration is delivered to a system running a vulnerable version of OpenClaw (<=2026.3.23-2). This could be achieved through various means, such as tricking a user into importing the configuration or through exploiting a separate vulnerability to write the file to disk.
3.  The OpenClaw CLI is executed, and it loads the malicious workspace configuration file.
4.  The OpenClaw backend attempts to process the workspace configuration.
5.  Due to the vulnerability, the attacker-controlled environment variables are injected into the OpenClaw process's environment.
6.  The injected environment variables are leveraged to execute arbitrary commands. This could involve using the variables to modify the execution path of subsequent commands or to execute shell commands directly.
7.  The attacker gains arbitrary code execution on the system with the privileges of the OpenClaw process.
8.  The attacker can then perform further actions, such as escalating privileges, installing malware, or exfiltrating sensitive data.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on a system running a vulnerable version of OpenClaw. This could lead to complete system compromise, including data theft, malware installation, and denial of service. While the exact number of affected systems is unknown, any environment using OpenClaw versions prior to 2026.3.24 is potentially at risk. The severity is rated as high due to the potential for unauthenticated remote code execution.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.24 or later to remediate CVE-2026-4039.
*   Monitor process execution for suspicious activity originating from OpenClaw processes as a compensating control. Use process creation logs and the provided Sigma rules to detect potential exploitation attempts.
*   Implement strict input validation and sanitization for any workspace configurations loaded by OpenClaw, even after upgrading, to prevent similar vulnerabilities in the future.
