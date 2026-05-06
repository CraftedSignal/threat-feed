---
title: Sagredo qmail Remote Code Execution Vulnerability (CVE-2026-41113)
slug: 2026-04-qmail-rce
description: A remote code execution vulnerability exists in Sagredo qmail versions prior to 2026.04.07 due to the use of `popen` in the `notlshosts_auto` function within `qmail-remote.c`, potentially leading to OS command injection.
date: "2026-04-17T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - qmail
  - rce
  - command-injection
  - CVE-2026-41113
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-41113
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41113
  - https://blog.calif.io/p/we-asked-claude-to-audit-sagredos
  - https://github.com/califio/publications/tree/main/MADBugs/qmail
  - https://github.com/sagredo-dev/qmail/commit/749f607f6885e3d01b36f2647d7a1db88f1ef741
  - https://github.com/sagredo-dev/qmail/pull/42
  - https://github.com/sagredo-dev/qmail/releases/tag/v2026.04.07
rules:
  - title: Detect Suspicious Qmail Remote Execution via popen
    description: Detects potential remote code execution attempts in Qmail by monitoring for process execution originating from qmail-remote invoking shell commands through popen.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect Qmail Spawning Network Connections to Unusual Ports
    description: Detects qmail processes initiating network connections to ports outside the standard SMTP range, which could indicate command and control or data exfiltration after a successful RCE.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Sagredo qmail, a mail transfer agent (MTA), is vulnerable to a remote code execution (RCE) flaw, identified as CVE-2026-41113.  Specifically, versions prior to 2026.04.07 are affected. The vulnerability lies in the `notlshosts_auto` function within the `qmail-remote.c` file, where the `popen` function is used without proper sanitization, potentially allowing an attacker to inject and execute arbitrary OS commands. This vulnerability could be exploited by a remote attacker without requiring authentication, making it a critical security concern for organizations utilizing the affected qmail versions. Defenders should prioritize patching and consider implementing mitigations to prevent potential exploitation.

## Attack Chain

1.  An attacker sends an email to a target qmail server.
2.  The qmail server receives the email and processes the recipient address.
3.  During the delivery process, `qmail-remote.c` is invoked to handle remote delivery.
4.  The `notlshosts_auto` function is called within `qmail-remote.c` to determine if TLS should be used for the connection.
5.  The `notlshosts_auto` function executes the `popen` command with a crafted input string from the email, attempting to resolve hostnames.
6.  The attacker injects malicious commands into the hostname string, which are then executed by `popen` on the server.
7.  The attacker gains arbitrary code execution on the qmail server.
8.  The attacker can then pivot to other systems within the network or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-41113 allows a remote attacker to execute arbitrary code on the vulnerable qmail server. This could lead to complete system compromise, data breaches, or denial-of-service conditions. Organizations using vulnerable versions of qmail are at risk of losing control of their email infrastructure and potentially exposing sensitive information. While the number of actively exploited instances is currently unknown, the high CVSS score (8.1) underscores the severity and potential for widespread impact.

## Recommendation

*   Upgrade to Sagredo qmail version 2026.04.07 or later to patch CVE-2026-41113 (reference: <https://github.com/sagredo-dev/qmail/releases/tag/v2026.04.07>).
*   Implement network segmentation to limit the impact of a successful compromise on the qmail server.
*   Monitor qmail server logs for suspicious activity, such as unusual process execution or network connections (enable process_creation and network_connection logging).
*   Deploy the Sigma rule "Detect Suspicious Qmail Remote Execution via popen" to identify potential exploitation attempts.
