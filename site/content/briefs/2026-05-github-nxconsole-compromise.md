---
title: GitHub Internal Repositories Compromised via Malicious Nx Console Extension
slug: 2026-05-github-nxconsole-compromise
description: GitHub internal repositories were compromised after an attacker injected malicious code into the Nx Console Visual Studio Code extension (v18.95.0), leading to the exfiltration of approximately 3,800 internal repositories.
date: "2026-05-29T16:30:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - github
  - nxconsole
  - repository-exfiltration
  - macos
vendors:
  - GitHub
products:
  - GitHub internal repositories
  - GitHub Enterprise Server
  - Nx Console Visual Studio Code extension
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://cyber.gc.ca/en/alerts-advisories/al26-013-security-incident-impacting-github-internal-repositories
  - https://github.blog/security/investigating-unauthorized-access-to-githubs-internal-repositories/
  - https://nx.dev/blog/nx-console-v18-95-0-postmortem
  - https://cyber.gc.ca/en/alerts-advisories/github-security-advisory-av26-512
rules:
  - title: Detect Suspicious cat.py Creation in Kitty Directory
    description: Detects the creation of a suspicious cat.py script in the Kitty configuration directory, associated with the compromised Nx Console extension.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - macos
  - title: Detect Nx Console Version 18.95.0 Installation
    description: Detects the installation or usage of the compromised Nx Console Visual Studio Code extension version 18.95.0 via process telemetry
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1195.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 18, 2026, GitHub detected unauthorized access to its internal systems originating from a compromised employee device. The initial intrusion vector was a supply chain attack involving a maliciously modified version of the Nx Console Visual Studio Code extension, specifically version 18.95.0. This malicious extension allowed the attacker to gain access to GitHub's internal network and exfiltrate approximately 3,800 internal GitHub repositories. These repositories contained proprietary source code and internal configuration data, representing a significant intellectual property and security risk. GitHub Enterprise Server customers are advised to rotate their GPG keys. No action is required for GitHub Enterprise Cloud clients. The malicious Nx Console extension also creates persistence via macOS launch agents and a `cat.py` script.

## Attack Chain

1.  The attacker injects malicious code into the Nx Console Visual Studio Code extension, version 18.95.0.
2.  A GitHub employee unknowingly installs the compromised Nx Console extension on their device.
3.  The malicious extension executes code on the employee's machine, granting the attacker initial access to the internal network.
4.  The attacker leverages the compromised device to access internal GitHub systems and resources.
5.  The attacker exfiltrates approximately 3,800 internal GitHub repositories containing source code and configuration data.
6.  On macOS systems, the malicious extension creates a `~/.local/share/kitty/cat.py` script and related persistence mechanisms using launch agents for recurring access.
7.  The attacker potentially uses exposed credentials on the developer's machine (AWS, GCP, Azure, GitHub, npm) to further their access and maintain persistence.
8.  The final objective of the attacker is to steal proprietary source code, internal configuration data, and potentially gain long-term access to GitHub's internal systems.

## Impact

The successful exfiltration of approximately 3,800 internal GitHub repositories poses a significant risk to GitHub's intellectual property and security. Exposed source code could be analyzed for vulnerabilities, leading to further attacks. Leaked configuration data could expose sensitive internal systems and credentials. Customers using GitHub Enterprise Server may need to rotate GPG keys to prevent unauthorized use of signed commits.

## Recommendation

*   Monitor CI/CD logs for unexpected repository access/cloning, unauthorized admin actions, authentication/access control changes, unauthorized pushes or orphan commits, and suspicious commits after May 18, 2026, especially from bot/service accounts, as mentioned in the advisory.
*   Remove Nx Console v18.95.0 from all environments and downgrade/upgrade to a known good version (18.94.0 or 18.96.0+), as indicated in the advisory.
*   Check macOS systems for `~/.local/share/kitty/cat.py` and related persistence (launch agents) if the malicious version of Nx Console was present, and remediate any findings.
*   Rotate all credentials (AWS, GCP, Azure, GitHub, npm) exposed on developer machines between May 11–20, 2026, if the malicious version of Nx Console was present.
*   Disable IDE extension auto-updates in high-security environments and enforce an approved allowlist of developer tools to strengthen controls.
