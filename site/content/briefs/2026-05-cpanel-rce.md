---
title: WHM, cPanel, and WP Squared Vulnerability Allows Remote Code Execution
slug: 2026-05-cpanel-rce
description: A vulnerability exists in WHM, cPanel, and WP Squared, Linux-based web hosting control panels, which could allow for remote code execution by bypassing authentication and gaining administrative access.
date: "2026-05-04T16:20:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - cpanel
  - whm
  - wp squared
  - linux
vendors:
  - cPanel
products:
  - cPanel
  - WHM
  - WP Squared
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.cisecurity.org/advisory/a-vulnerability-in-whm-cpanel-and-wp-squared-could-allow-for-remote-code-execution_2026-042
rules:
  - title: Detect Suspicious PHP Upload via cPanel
    description: Detects the upload of suspicious PHP files to common cPanel directories, which may indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: Detect Cpanel Authentication Bypass Attempts
    description: Detects attempts to bypass cPanel authentication by looking for specific HTTP status codes following login attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability has been discovered in WHM, cPanel, and WP Squared, which are Linux-based web hosting control panels commonly used for server and website management. This vulnerability could allow unauthenticated remote attackers to bypass authentication mechanisms. By exploiting this flaw, attackers can gain unauthorized administrative access to the affected systems. This level of access could allow them to inject malicious code and achieve remote code execution. The impact of successful exploitation is significant, as it allows attackers to fully compromise the target system.

## Attack Chain

1.  Unauthenticated attacker sends a specially crafted request to a vulnerable cPanel, WHM, or WP Squared endpoint.
2.  The request exploits an authentication bypass vulnerability, allowing the attacker to proceed without valid credentials.
3.  The attacker gains unauthorized administrative access to the web hosting control panel.
4.  The attacker leverages the administrative access to upload a malicious PHP script to a writable directory on the server.
5.  The attacker crafts a request to execute the uploaded PHP script.
6.  The PHP script executes arbitrary commands on the underlying Linux operating system.
7.  The attacker establishes a reverse shell to maintain persistent access to the compromised system.
8.  The attacker performs further reconnaissance, lateral movement, or data exfiltration based on their objectives.

## Impact

Successful exploitation of this vulnerability grants attackers full control over the affected web hosting servers. This can lead to complete compromise of hosted websites, data theft, defacement, or the deployment of further malicious payloads. Given the wide use of cPanel, WHM, and WP Squared among web hosting providers, a large number of servers and websites are potentially at risk. The impact includes significant financial losses, reputational damage, and potential legal liabilities for both the hosting providers and their clients.

## Recommendation

*   Apply available patches or updates provided by cPanel to remediate the authentication bypass vulnerability.
*   Implement the Sigma rule `Detect Suspicious PHP Upload via cPanel` to identify potential malicious PHP script uploads.
*   Monitor web server logs for suspicious requests to cPanel endpoints, focusing on unusual parameters or authentication attempts, as covered by the Sigma rule `Detect Cpanel Authentication Bypass Attempts`.
*   Implement network segmentation to limit the impact of a compromised cPanel server on other internal systems.
