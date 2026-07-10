---
title: OpenClaw Sandbox Browser CDP Relay Vulnerability Exposing DevTools Protocol
slug: 2024-01-openclaw-cdp-exposure
description: OpenClaw versions prior to 2026.4.10 are vulnerable to a configuration issue where the sandbox browser CDP relay could bind too broadly, exposing Chrome DevTools Protocol access outside the intended local/sandbox source range, potentially allowing unauthorized access to browser DevTools.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cdp
  - devtools
  - sandbox
  - exposure
  - openclaw
vendors:
  - openclaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
references:
  - https://github.com/advisories/GHSA-525j-hqq2-66r4
  - https://github.com/qclawer
rules:
  - title: Detect OpenClaw CDP Exposure via Network Connection
    description: Detects network connections to the default Chrome DevTools Protocol port range, which could indicate unauthorized access to a vulnerable OpenClaw instance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1040
    data_sources:
      - network_connection
      - windows|linux|macos
  - title: Detect OpenClaw Version via Process Creation
    description: Detects the execution of OpenClaw with a vulnerable version number based on command-line arguments.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows|linux|macos
rules_count: 2
---

The `openclaw` package, a sandbox browser CDP relay, contains a vulnerability in versions prior to 2026.4.10. This vulnerability allows the Chrome DevTools Protocol (CDP) to be exposed more broadly than intended, potentially allowing unauthorized access. Specifically, the CDP relay could bind to `0.0.0.0` by default, which exposes the DevTools protocol to all network interfaces instead of restricting it to the local machine or sandbox environment. An attacker could potentially exploit this exposure to interact with and control the browser instance remotely, leading to information disclosure or remote code execution within the sandbox environment. The vulnerability was reported by @zsxsoft, with sponsorship from @KeenSecurityLab and @qclawer, and a fix has been implemented in version 2026.4.10 to enforce CDP source-range restriction.

## Attack Chain

1. An attacker identifies a system running a vulnerable version of `openclaw` (prior to 2026.4.10).
2. The attacker scans the target system's network interfaces to identify the exposed Chrome DevTools Protocol (CDP) port, typically in the 9222+ range.
3. The attacker connects to the exposed CDP endpoint, bypassing intended access controls due to the broad binding.
4. The attacker uses the CDP to inspect the browser's state, including loaded pages, cookies, and other sensitive data.
5. The attacker leverages CDP commands to manipulate the browser, such as navigating to arbitrary URLs.
6. If the sandbox environment is misconfigured, the attacker may attempt to exploit vulnerabilities in the browser or its plugins via the CDP connection.
7. The attacker could potentially achieve remote code execution within the sandbox if suitable vulnerabilities are present.
8. The attacker uses the compromised sandbox environment to pivot to other internal systems, depending on the sandbox's network configuration.

## Impact

Successful exploitation of this vulnerability could allow an attacker to gain unauthorized access to the Chrome DevTools Protocol of a sandboxed browser. This could lead to the leakage of sensitive information displayed in the browser, manipulation of the browser's behavior, and potentially remote code execution within the sandbox environment. The extent of the impact depends on the sensitivity of the data handled by the browser and the configuration of the sandbox itself.

## Recommendation

*   Upgrade the `openclaw` package to version 2026.4.10 or later to remediate the vulnerability.
*   Deploy the Sigma rule "Detect OpenClaw CDP Exposure via Network Connection" to identify potentially vulnerable systems by monitoring for network connections to the CDP port range.
*   Review and harden sandbox configurations to minimize the impact of potential CDP exploits.
*   Monitor network traffic for unusual CDP traffic originating from or destined for systems running `openclaw`.
