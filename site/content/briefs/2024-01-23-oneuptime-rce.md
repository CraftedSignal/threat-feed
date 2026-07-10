---
title: OneUptime Remote Command Execution via Playwright Script Abuse (CVE-2026-33396)
slug: 2024-01-23-oneuptime-rce
description: A low-privileged authenticated user can achieve remote command execution on the Probe container/host by abusing Synthetic Monitor Playwright script execution in OneUptime versions prior to 10.0.35.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oneuptime
  - rce
  - playwright
  - cve-2026-33396
  - sandbox-escape
  - execution
  - linux
vendors:
  - OneUptime
products:
  - OneUptime
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33396
rules:
  - title: Detect OneUptime Playwright RCE Attempt via Process Creation
    description: Detects suspicious process creation originating from the OneUptime Probe container potentially exploiting CVE-2026-33396.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect OneUptime Playwright RCE Attempt via Network Connection
    description: Detects suspicious network connections originating from the OneUptime Probe container, potentially indicating command execution after CVE-2026-33396 exploitation.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OneUptime, an open-source monitoring and observability platform, is vulnerable to remote command execution (RCE). This vulnerability, identified as CVE-2026-33396, affects versions prior to 10.0.35. A low-privileged, authenticated user with ProjectMember rights can exploit the Synthetic Monitor feature by injecting malicious Playwright scripts. The vulnerability resides within the VMRunner.runCodeInNodeVM function, where the code is executed with a live Playwright page object. The platform's sandbox, designed to prevent arbitrary code execution, relies on an incomplete denylist. The lack of proper filtering for properties like `_browserType` and methods like `launchServer` allows attackers to bypass the sandbox restrictions. This enables the attacker to traverse the object `page.context().browser()._browserType.launchServer(...)` and ultimately spawn arbitrary processes on the Probe container or host. This vulnerability poses a significant risk to organizations using OneUptime, potentially leading to complete system compromise.

## Attack Chain

1. A low-privileged user authenticates to the OneUptime platform as a ProjectMember.
2. The attacker accesses the Synthetic Monitor feature.
3. The attacker creates or modifies a synthetic monitor, injecting malicious JavaScript code within the Playwright script execution context.
4. The malicious script utilizes the `page.context().browser()` object to access the internal Playwright browser instance.
5. The script leverages the non-blocked `_browserType` property to gain access to browser management functionalities.
6. The script calls the `launchServer()` method via `page.context().browser()._browserType.launchServer(...)` to spawn a new process.
7. The attacker specifies an arbitrary command to be executed by the spawned process, bypassing the intended sandbox restrictions.
8. The arbitrary command executes on the Probe container/host, resulting in remote command execution.

## Impact

Successful exploitation of CVE-2026-33396 grants attackers the ability to execute arbitrary commands on the OneUptime Probe container or host. The observed damage includes unauthorized access to sensitive data, modification of system configurations, and potential lateral movement within the network. Given the nature of monitoring and observability platforms, this vulnerability could lead to a compromise of the entire monitored infrastructure. While the number of victims is unknown, all OneUptime instances running versions prior to 10.0.35 are susceptible.

## Recommendation

*   Upgrade OneUptime to version 10.0.35 or later to patch CVE-2026-33396.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts targeting CVE-2026-33396.
*   Review and harden the Synthetic Monitor input validation and sanitization processes within OneUptime.
*   Implement strict network segmentation to limit the potential impact of a compromised Probe container/host.
