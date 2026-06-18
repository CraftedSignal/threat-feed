---
title: Crawl4AI Unauthenticated RCE via Chromium Launch-Argument Injection
slug: 2026-06-crawl4ai-unauth-rce
description: An attacker can achieve unauthenticated remote code execution (RCE) in Crawl4AI Docker deployments by injecting malicious Chromium launch arguments, such as `--utility-cmd-prefix` and `--no-zygote`, into the `browser_config.extra_args` field of the API request, allowing for arbitrary command execution as the container's runtime user.
date: "2026-06-18T17:40:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - RCE
  - web-vulnerability
  - Chromium
  - container
  - Docker
  - Linux
vendors:
  - Crawl4AI
products:
  - crawl4ai (<= 0.8.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-r253-r9jw-qg44
rules:
  - title: Detect Access to Vulnerable Crawl4AI API Endpoints
    description: Detects unauthenticated HTTP POST requests to known vulnerable Crawl4AI API endpoints that accept `browser_config.extra_args`.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Chromium Launched with Exploit Arguments in Crawl4AI Container
    description: Detects `chromium` or `chrome` processes launched with arguments indicative of RCE exploitation in Crawl4AI, specifically `--no-zygote` combined with child-process replacement flags.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Child Process Spawning from Chromium in Crawl4AI Container
    description: Detects `chromium` or `chrome` processes spawning unusual child processes commonly used for post-exploitation, indicating potential RCE within a Crawl4AI container.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
      - T1071.001
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A critical unauthenticated remote code execution (RCE) vulnerability exists in Crawl4AI, affecting versions up to 0.8.9, where the Docker API server improperly processes `browser_config.extra_args` from untrusted request bodies. This flaw allows an attacker to inject Chromium launch arguments, specifically those that can replace child-process launch commands like `--utility-cmd-prefix`, `--renderer-cmd-prefix`, `--gpu-launcher`, or `--browser-subprocess-path`, when combined with `--no-zygote`. By leveraging these arguments, Chromium is forced to fork and execute an attacker-controlled command as the container's runtime user, leading to full compromise. The vulnerability stems from an incomplete denylist approach in earlier versions, which failed to cover critical command execution switches. If exploited, an attacker gains complete control over the container, including access to sensitive application data, mounted secrets, environment variables, and tokens, enabling out-of-band data exfiltration.

## Attack Chain

1.  An attacker identifies an exposed and unauthenticated Crawl4AI Docker API endpoint.
2.  The attacker sends an unauthenticated HTTP POST request to a vulnerable API path, such as `/crawl`, `/crawl/stream`, or `/crawl/job`.
3.  The request body includes `browser_config.extra_args` containing specially crafted Chromium launch arguments.
4.  Malicious arguments typically include a child-process launch command (e.g., `--utility-cmd-prefix`) combined with `--no-zygote`.
5.  The Crawl4AI application passes these arguments to Chromium during its launch configuration.
6.  Chromium, influenced by the injected arguments, forks and executes an attacker-controlled command instead of its intended child process.
7.  The attacker's command executes as the container's runtime user, achieving remote code execution.
8.  Post-exploitation, the attacker can access sensitive data, exfiltrate information, or establish further persistence within the compromised container.

## Impact

Successful exploitation of this vulnerability leads to unauthenticated remote code execution (RCE) as the container's runtime user. This grants attackers full read/write access to all application data, mounted secrets, environment variables, and security tokens within the affected container. Attackers can exfiltrate sensitive data out-of-band, install additional malware, or pivot to other systems. Organizations using vulnerable Crawl4AI Docker deployments are at severe risk of data breaches, system compromise, and significant operational disruption.

## Recommendation

*   **Upgrade Crawl4AI to version 0.9.0 immediately** to address the fundamental trust boundary issue that allows injection of dangerous configuration.
*   **Enable authentication** by configuring `CRAWL4AI_API_TOKEN` and restrict API access to trusted networks and users.
*   **Run Crawl4AI containers with a restrictive seccomp profile** to limit the ability of processes within the container to execute helper binaries, mitigating the impact of potential RCE.
*   **Deploy the Sigma rules in this brief** to your SIEM for detection of exploitation attempts and post-exploitation activity.
*   **Ensure process creation logging is enabled for Linux containers** to allow detection of suspicious `chromium` child processes.
