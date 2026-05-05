---
title: OpenClaw Environment Variable Injection Vulnerability
slug: 2026-05-openclaw-env-injection
description: OpenClaw before version 2026.4.9 is vulnerable to environment variable injection, allowing attackers to use malicious workspace .env files to set runtime-control variables and compromise application behavior affecting update sources, gateway URLs, ClawHub resolution, and browser executable paths.
date: "2026-05-05T12:16:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - environment variable injection
  - application compromise
  - cve-2026-43531
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-43531
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43531
  - https://github.com/openclaw/openclaw/commit/dbfcef319618158fa40b31cdac386ea34c392c0c
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-7wv4-cc7p-jhxc
  - https://www.vulncheck.com/advisories/openclaw-environment-variable-injection-via-workspace-env-file
rules:
  - title: Detect Modification of .env Files in OpenClaw Workspace
    description: Detects the creation or modification of .env files within OpenClaw workspace directories, which could indicate an attempt to inject malicious environment variables.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect OpenClaw Launching Unexpected Browser Executable
    description: Detects OpenClaw launching a browser executable from an unusual location, indicating potential manipulation of the browser executable path via environment variables.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw before version 2026.4.9 is susceptible to an environment variable injection vulnerability. This flaw enables attackers to manipulate runtime-control variables by crafting malicious workspace .env files. Successful exploitation can lead to the redirection of update sources to attacker-controlled servers, modification of gateway URLs to intercept traffic, alteration of ClawHub resolution to point to malicious resources, and substitution of browser executable paths to execute arbitrary code. This vulnerability allows an attacker to potentially gain control of the application's behavior and compromise the underlying system.

## Attack Chain

1.  The attacker crafts a malicious `.env` file containing environment variable definitions designed to override default application settings.
2.  The attacker places the malicious `.env` file into a workspace directory accessible by the OpenClaw application.
3.  OpenClaw application parses the `.env` file during startup or when a workspace is loaded.
4.  The application reads the attacker-controlled environment variables, which are intended to modify update sources, gateway URLs, ClawHub resolution endpoints, and browser executable paths.
5.  The attacker redirects the update source to a malicious server hosting a compromised update package.
6.  The application downloads and installs the malicious update, leading to code execution.
7.  Alternatively, the attacker manipulates the browser executable path to execute arbitrary code using a different application.

## Impact

Successful exploitation of this vulnerability allows attackers to inject arbitrary environment variables, leading to code execution and potential system compromise. Attackers could redirect update sources, manipulate gateway URLs, or alter browser executable paths to execute malicious code. Given the potential for complete system compromise, this vulnerability poses a significant risk to organizations using affected versions of OpenClaw.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.9 or later to patch the environment variable injection vulnerability (CVE-2026-43531).
*   Implement strict file integrity monitoring on workspace directories to detect unauthorized modification of `.env` files using a file_event Sigma rule.
*   Monitor process execution for OpenClaw using unexpected browser executable paths by deploying the process_creation Sigma rule below.
