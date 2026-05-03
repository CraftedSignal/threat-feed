---
title: AV Stumpfl Pixera Two Media Server Code Injection Vulnerability
slug: 2026-05-pixera-code-injection
description: A remote code injection vulnerability exists in AV Stumpfl Pixera Two Media Server versions up to 25.2 R2 due to improper handling within the Websocket API, potentially allowing unauthenticated attackers to execute arbitrary code.
date: "2026-05-03T17:16:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - websocket
  - cve-2026-7703
vendors:
  - AV Stumpfl
products:
  - Pixera Two Media Server (<= 25.2 R2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-7703
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7703
  - https://vuldb.com/vuln/360872
rules:
  - title: Detect Suspicious Pixera Websocket Activity
    description: Detects potentially malicious websocket activity targeting Pixera servers, indicating possible code injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Pixera Two Media Server Process Creation with Unusual Arguments
    description: Detects unusual command-line arguments used when starting the Pixera Two Media Server process, which might indicate exploitation activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A code injection vulnerability, tracked as CVE-2026-7703, has been identified in AV Stumpfl Pixera Two Media Server impacting versions up to 25.2 R2. The vulnerability resides within an unspecified function of the Websocket API component. Successful exploitation allows a remote attacker to inject and execute arbitrary code on the affected system. Given that an exploit has been published, the risk of exploitation is elevated. Organizations using the Pixera Two Media Server should upgrade to version 25.2 R3 or later to mitigate the risk. This vulnerability poses a significant threat to media production environments relying on the affected software.

## Attack Chain

1.  The attacker identifies a vulnerable AV Stumpfl Pixera Two Media Server instance running a version prior to 25.2 R3.
2.  The attacker crafts a malicious payload designed to exploit the code injection vulnerability within the Websocket API.
3.  The attacker sends the malicious payload to the Pixera Two Media Server instance via a Websocket connection.
4.  The vulnerable function within the Websocket API fails to properly sanitize or validate the input.
5.  The malicious payload is processed, resulting in the injection of attacker-controlled code into the server's process.
6.  The injected code executes with the privileges of the Pixera Two Media Server process.
7.  The attacker gains arbitrary code execution on the server, potentially leading to complete system compromise.
8.  The attacker can then install malware, exfiltrate sensitive data, or disrupt media server operations.

## Impact

Successful exploitation of CVE-2026-7703 can result in arbitrary code execution on the AV Stumpfl Pixera Two Media Server. This could allow an attacker to gain complete control over the server, potentially disrupting media presentations, stealing sensitive data, or using the compromised server as a launchpad for further attacks within the network. The impact is significant due to the critical role media servers play in various entertainment and presentation environments.

## Recommendation

*   Upgrade AV Stumpfl Pixera Two Media Server to version 25.2 R3 or later to patch CVE-2026-7703 (reference: AV Stumpfl advisory).
*   Monitor network traffic for suspicious Websocket connections originating from or targeting AV Stumpfl Pixera Two Media Servers using the "Detect Suspicious Pixera Websocket Activity" Sigma rule.
*   Implement network segmentation to limit the blast radius of a potential compromise of the Pixera Two Media Server.
*   Review and harden the configuration of the Pixera Two Media Server to minimize the attack surface.
