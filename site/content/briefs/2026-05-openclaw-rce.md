---
title: OpenClaw Arbitrary Code Execution via Malicious Plugin
slug: 2026-05-openclaw-rce
description: OpenClaw before version 2026.4.23 is vulnerable to arbitrary code execution (CVE-2026-45004) due to insecurely loading the setup-api.js file from the current working directory, allowing attackers to execute arbitrary JavaScript under the current user account.
date: "2026-05-11T18:18:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code execution
  - vulnerability
  - javascript
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-45004
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45004
  - https://github.com/openclaw/openclaw/commit/993781e6e6eaf50f033cfc3e3bf4f47059740707
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-r39h-4c2p-3jxp
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-code-execution-via-setup-api-js-in-current-working-directory
rules:
  - title: Detect Suspicious OpenClaw Plugin Execution
    description: Detects CVE-2026-45004 exploitation -- OpenClaw executing JavaScript files from user-writable directories, which may indicate a malicious plugin being loaded.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious OpenClaw Plugin Directory
    description: Detects the creation of 'setup-api.js' files in the OpenClaw plugin directory within user profile directories, potentially indicating a malicious plugin installation (CVE-2026-45004).
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

OpenClaw versions prior to 2026.4.23 are susceptible to an arbitrary code execution vulnerability (CVE-2026-45004) stemming from the bundled plugin setup resolver's behavior. Specifically, the resolver loads the `setup-api.js` file from the current working directory (`process.cwd()`) during the provider setup metadata resolution process. This design flaw allows a threat actor to craft a malicious `extensions/<plugin>/setup-api.js` file and place it within a repository. If a user is then convinced to execute OpenClaw commands from within that directory, the malicious JavaScript code will be executed under the privileges of the current user account. This poses a significant security risk as it can lead to complete system compromise.

## Attack Chain

1.  Attacker crafts a malicious `setup-api.js` file containing arbitrary JavaScript code intended for execution.
2.  The attacker places the malicious `setup-api.js` file in a directory structure mimicking the required plugin structure: `extensions/<plugin>/setup-api.js`.
3.  The attacker hosts the directory, or convinces the victim to download the malicious directory onto their local system.
4.  The attacker social engineers the victim into running OpenClaw commands from the directory containing the malicious plugin.
5.  OpenClaw, during plugin setup metadata resolution, loads the `setup-api.js` file from the current working directory (`process.cwd()`).
6.  The malicious JavaScript code within `setup-api.js` is executed under the current user account.
7.  The attacker gains arbitrary code execution on the victim's machine, potentially leading to data theft, system compromise, or further malicious activities.

## Impact

Successful exploitation of CVE-2026-45004 allows an attacker to execute arbitrary code on a victim's system with the privileges of the user running OpenClaw. This could lead to the installation of malware, exfiltration of sensitive data, or complete system compromise. Due to the nature of arbitrary code execution, the impact is significant and potentially devastating. The severity is compounded by the relative ease of exploitation, requiring only a user to execute a command from a directory controlled by the attacker.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.23 or later to patch CVE-2026-45004.
*   Deploy the Sigma rule "Detect Suspicious OpenClaw Plugin Execution" to detect potential attempts to exploit this vulnerability.
*   Educate users about the risks of running commands from untrusted directories to mitigate the social engineering aspect of this attack.
*   Monitor process creation events for OpenClaw executing JavaScript files from user-writable directories.
