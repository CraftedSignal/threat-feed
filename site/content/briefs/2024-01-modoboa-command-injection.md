---
title: Modoboa <= 2.7.0 OS Command Injection Vulnerability
slug: 2024-01-modoboa-command-injection
description: Modoboa versions 2.7.0 and earlier are vulnerable to OS command injection, allowing a Reseller or SuperAdmin to execute arbitrary OS commands on the server by injecting shell metacharacters into a domain name due to unsanitized input in the `exec_cmd()` function.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - modoboa
  - code-execution
vendors:
  - Modoboa
products:
  - Modoboa
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-wwv8-cqpr-vx3m
rules:
  - title: Modoboa Command Injection Attempt via Domain Name
    description: Detects attempts to exploit the Modoboa OS command injection vulnerability by monitoring process creation events for commands containing shell metacharacters within domain names.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Modoboa Suspicious File Creation in /tmp via Command Injection
    description: Detects suspicious file creation in the /tmp directory, a common target for command injection exploitation, specifically related to Modoboa.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Modoboa, a mail server management platform, is vulnerable to OS command injection in versions 2.7.0 and earlier. The vulnerability stems from the `exec_cmd()` function within `modoboa/lib/sysutils.py`, which executes subprocess calls with `shell=True` without properly sanitizing input. A Reseller or SuperAdmin account, possessing elevated privileges within Modoboa, can inject shell metacharacters into a domain name during domain creation. This injected code is then executed by the system, potentially granting the attacker root access to the underlying server. The vulnerability was confirmed on commit b521bcb4f. Successful exploitation allows for complete control over the mail server, leading to data breaches, service disruption, and further malicious activities.

## Attack Chain

1. An attacker obtains or compromises a Modoboa Reseller or SuperAdmin account.
2. The attacker logs into the Modoboa web interface.
3. The attacker navigates to the domain creation section.
4. The attacker crafts a malicious domain name containing shell metacharacters (e.g., `$(id>/tmp/proof).example.com`).
5. The attacker submits the domain creation request, triggering the `exec_cmd()` function.
6. The `exec_cmd()` function executes the `openssl` command with the malicious domain name embedded, leading to command injection.
7. The injected command executes on the server, allowing the attacker to perform arbitrary actions.
8. The attacker achieves arbitrary code execution as root on the Modoboa server.

## Impact

Successful exploitation of this vulnerability allows an attacker with Reseller-level access (or higher) to execute arbitrary OS commands on the mail server, typically running as root. This grants the attacker complete control over the system, enabling them to read sensitive data, modify configurations, install malware, and disrupt email services. Given that all identified vulnerable code paths are reachable through normal application workflows, the impact is significant, potentially affecting all Modoboa deployments running vulnerable versions.

## Recommendation

*   Upgrade Modoboa to a version greater than 2.7.0 to patch CVE-2026-27602.
*   Deploy the following Sigma rule to detect command injection attempts via domain name creation, monitoring process creation for the execution of commands with injected shell metacharacters in domain names.
*   Implement input validation and sanitization measures on domain name fields to prevent the injection of shell metacharacters.
