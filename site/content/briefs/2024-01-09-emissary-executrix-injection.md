---
title: Emissary Executrix OS Command Injection Vulnerability
slug: 2024-01-09-emissary-executrix-injection
description: A vulnerability in Emissary's Executrix class allows for arbitrary OS command execution by injecting shell metacharacters into the IN_FILE_ENDING or OUT_FILE_ENDING configuration values, leading to code execution within the JVM's security context.
date: "2024-01-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - emissary
  - command-injection
  - executrix
  - ghsa-3p24-9x7v-7789
vendors:
  - Emissary
products:
  - Emissary
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Persistence, Privilege Escalation, Defense Evasion, and Initial Access
references:
  - https://github.com/advisories/GHSA-3p24-9x7v-7789
rules:
  - title: Detect Emissary InfileEnding OutfileEnding Injection Attempt
    description: Detects attempts to exploit the Emissary Executrix vulnerability by identifying shell metacharacters in IN_FILE_ENDING or OUT_FILE_ENDING configuration parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Shell Command Execution via Executrix Injection
    description: Detects shell command execution that originates from a directory commonly used by Emissary, suggesting potential exploitation of the Executrix vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Emissary, a data processing framework, contains a critical OS command injection vulnerability in its `Executrix` class. This flaw arises from the unsafe construction of shell commands where user-controlled configuration values, specifically `IN_FILE_ENDING` and `OUT_FILE_ENDING`, are directly incorporated into a `/bin/sh -c` command string without proper sanitization or escaping. An attacker with the ability to modify place configurations can inject arbitrary shell commands by setting these configuration values to malicious sequences. The vulnerability, identified in Emissary versions up to 8.42.0-SNAPSHOT, requires no API or network access and is triggered when the affected place processes any payload. This framework-level defect poses a significant risk as it allows for unauthenticated remote code execution within the JVM's security context.

## Attack Chain

1.  The attacker gains access to modify the configuration of an Emissary "place", typically through compromised credentials or a separate vulnerability allowing configuration changes.
2.  The attacker sets the `IN_FILE_ENDING` or `OUT_FILE_ENDING` configuration value for a vulnerable place (e.g., `UnixCommandPlace`) to a malicious string containing shell metacharacters, such as backticks for command substitution.
3.  The Emissary server is restarted or reloads the modified configuration, applying the attacker-controlled `IN_FILE_ENDING` or `OUT_FILE_ENDING` value.
4.  A file is placed into the Emissary pickup directory, triggering the pipeline processing.
5.  The file is routed through the configured places, eventually reaching the place with the malicious `IN_FILE_ENDING` or `OUT_FILE_ENDING` value.
6.  The `Executrix.getCommand()` method constructs a shell command that includes the unsanitized `IN_FILE_ENDING` or `OUT_FILE_ENDING` value. The injected shell metacharacters are interpreted by the shell.
7.  The constructed command is executed via `/bin/sh -c`, resulting in the attacker-specified commands being executed on the system with the privileges of the Emissary process.
8.  The attacker achieves arbitrary code execution, potentially leading to data exfiltration, system compromise, or denial of service.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary OS commands on the Emissary server, leading to full system compromise. The vulnerability affects all Emissary deployments where place configurations can be modified. The impact includes potential data breaches, malware installation, and complete control over the affected server. Given the nature of Emissary as a data processing framework, successful exploitation could allow attackers to compromise sensitive data being processed.

## Recommendation

*   Apply input validation and sanitization to the `IN_FILE_ENDING` and `OUT_FILE_ENDING` configuration parameters to prevent shell injection.
*   Deploy the Sigma rule `Detect Emissary InfileEnding OutfileEnding Injection Attempt` to detect attempts to exploit this vulnerability by monitoring for shell metacharacters in configuration files.
*   Implement strict access controls to limit who can modify place configurations in Emissary, as this is the primary attack vector.
*   Enable DEBUG level logging in Emissary to expose the assembled shell command strings. This allows for forensic analysis and detection of injection attempts.
