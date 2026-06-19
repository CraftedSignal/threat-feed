---
title: Stack Buffer Overflow in Oj Ruby Gem (CVE-2026-54502)
slug: 2026-06-stack-buffer-overflow-oj-gem
description: The `Oj.dump` function in the `Oj` Ruby gem is vulnerable to a stack-based buffer overflow (CVE-2026-54502) due to improper validation of the `:indent` parameter, allowing an attacker to trigger a process crash or potentially remote code execution by providing an excessively large integer value, affecting all `Oj` gem versions prior to `3.17.2`.
date: "2026-06-19T19:47:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - overflow
  - ruby
  - gem
  - denial-of-service
  - remote-code-execution
  - application-vulnerability
products:
  - oj gem (< 3.17.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-3v45-f3vh-wg7m
rules:
  - title: Detect CVE-2026-54502 Exploitation Attempt - Large Oj.dump Indent
    description: Detects HTTP requests attempting to exploit CVE-2026-54502 by providing an excessively large integer value to an 'indent' parameter, targeting the vulnerable Oj.dump function in Ruby applications.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Ruby Process Spawning Suspicious Child Process (Windows)
    description: Detects ruby.exe processes spawning known command and scripting interpreters on Windows, which could indicate successful exploitation of a buffer overflow (e.g., CVE-2026-54502) leading to remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1059.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Ruby Process Spawning Suspicious Child Process (Linux)
    description: Detects ruby processes spawning known command and scripting interpreters on Linux, which could indicate successful exploitation of a buffer overflow (e.g., CVE-2026-54502) leading to remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

An attacker can exploit a critical stack-based buffer overflow vulnerability, identified as CVE-2026-54502, within the `Oj.dump` function of the `Oj` Ruby gem. This vulnerability affects all versions of the `Oj` gem prior to `3.17.2`. The flaw stems from insufficient input validation of the `:indent` parameter; when an application passes an extremely large integer value (such as `INT_MAX`, 2,147,483,647) to this parameter, the internal `fill_indent` function in `ext/oj/dump.h` calls `memset` without proper size checks. This leads to an attempt to write gigabytes of data into a small, stack-allocated buffer, corrupting the process's stack and resulting in an immediate denial of service through a crash. If exploited precisely, this could also enable remote code execution, posing a significant risk to the availability and integrity of Ruby applications using the vulnerable gem.

## Attack Chain

1.  **Initial Access**: An attacker identifies a Ruby application utilizing a vulnerable `Oj` gem version (prior to 3.17.2) and exposing a parameter or input field that directly or indirectly controls the `indent` argument for the `Oj.dump` function. This could be a web API endpoint, a file processing service, or another untrusted input vector.
2.  **Input Provision**: The attacker crafts a request (e.g., an HTTP GET/POST parameter, an API call payload, or a crafted data file) containing an excessively large integer value (such as `2,147,483,647` representing `INT_MAX`) for the `indent` parameter.
3.  **Application Processing**: The vulnerable Ruby application receives and processes this malicious input, passing the large integer value to the `Oj.dump` function's `indent` option without adequate validation.
4.  **Vulnerable Function Call**: Internally, `Oj.dump` invokes its C extension `fill_indent` function (located in `ext/oj/dump.h`), which receives the large `indent` value.
5.  **Buffer Overflow**: Within `fill_indent`, the `memset` function is called with the attacker-controlled large size, causing it to attempt to write gigabytes of data (`(size_t)opts->indent * depth`) into a much smaller, fixed-size stack-allocated `out` buffer (approximately 4KB).
6.  **Stack Corruption and Crash**: This massive write operation overflows the `out` buffer, severely corrupting the stack memory of the Ruby process.
7.  **Denial of Service**: The stack corruption immediately triggers an abnormal termination of the Ruby application process, leading to a denial of service for the affected service or application.
8.  **Potential Code Execution**: In specific, carefully crafted scenarios, this stack corruption could potentially be leveraged to overwrite critical program control flow data (e.g., return addresses), allowing the attacker to achieve arbitrary code execution within the context of the vulnerable Ruby process.

## Impact

Successful exploitation of CVE-2026-54502 primarily leads to a denial of service (DoS) for Ruby applications relying on the vulnerable `Oj` gem, causing immediate process crashes and service unavailability. Depending on the application's design, this can severely impact business operations and user access. In more sophisticated attack scenarios, the stack-based buffer overflow might be exploited to achieve arbitrary remote code execution (RCE). If RCE is successful, attackers could compromise the underlying server, execute commands with the privileges of the Ruby process, exfiltrate sensitive data, or establish further persistence within the environment, leading to significant data breaches, system compromise, and financial losses.

## Recommendation

*   Patch CVE-2026-54502 immediately by upgrading the `oj` gem to version 3.17.2 or later in all affected Ruby applications.
*   Deploy the webserver Sigma rule "Detect CVE-2026-54502 Exploitation Attempt - Large Oj.dump Indent" in this brief to your SIEM to identify attempts at exploiting this vulnerability.
*   Implement robust input validation for all user-supplied data, particularly for parameters that influence data formatting or transformation, to prevent excessively large integer values from reaching sensitive functions.
*   Deploy the process creation Sigma rules "Detect Ruby Process Spawning Suspicious Child Process (Windows)" and "Detect Ruby Process Spawning Suspicious Child Process (Linux)" to monitor for potential remote code execution payloads from Ruby processes.
