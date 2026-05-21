---
title: GitHub Internal Repositories Breached via Malicious VS Code Extension
slug: 2026-05-github-repo-breach
description: A GitHub employee's device was compromised via a malicious VS Code extension, leading to the theft of approximately 3,800 internal repositories by threat actor TeamPCP (UNC6780), who then offered the data for sale.
date: "2026-05-21T13:38:27Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - github
  - credential-theft
  - vscode
vendors:
  - GitHub
  - Microsoft
products:
  - Visual Studio Code
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1608
    technique_name: Stage Capabilities
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Remote File Copy
references:
  - https://www.sophos.com/en-us/blog/github-internal-repositories-breached
rules:
  - title: Detect VS Code Spawning Git
    description: Detects Visual Studio Code spawning git.exe or git commands, which could indicate malicious extension activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Archive Download Followed By Interpreter Execution
    description: 'Detects a suspicious sequence of events: an archive file download (e.g., .zip, .tar.gz) followed by an interpreter (e.g., python.exe, node.exe, powershell.exe) executing a file from within that archive, which could indicate malicious activity.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 19-20, 2026, GitHub confirmed a security incident where a threat actor known as TeamPCP (also tracked as UNC6780) compromised an employee's development device using a malicious Visual Studio Code extension. This allowed the attacker to clone roughly 3,800 of GitHub’s internal repositories, including proprietary source code, deployment scripts, and internal configuration material. The attacker subsequently listed the stolen data for sale on a criminal forum, reportedly for upwards of $50,000 USD. GitHub believes that customer repositories, enterprise accounts, and user data were not affected, limiting the compromise to their internal corporate estate. GitHub has rotated credentials and isolated affected endpoints.

## Attack Chain

1.  **Initial Access:** TeamPCP delivered a malicious Visual Studio Code extension to a GitHub employee's development device.
2.  **Credential Harvesting:** The malicious extension harvested developer secrets and access tokens from the IDE's local environment.
3.  **Repository Theft:** Using the stolen credentials, the attacker cloned approximately 3,800 GitHub-internal private repositories.
4.  **Data Exfiltration:** The cloned repositories, containing proprietary source code, deployment scripts, and internal configuration material, were exfiltrated from the compromised device.
5.  **Monetization:** TeamPCP listed the stolen data for sale on a cybercrime forum.
6.  **Public Taunting:** The actor used a purportedly associated X/Twitter account (xploitrsturtle2) to publicly taunt GitHub.
7.  **Detection and Response:** GitHub detected the breach on May 19th, began incident response, and rotated critical secrets.
8.  **Mitigation:** The malicious extension version was removed, and infected endpoints were isolated.

## Impact

The breach resulted in the theft of approximately 3,800 of GitHub's internal private repositories, including proprietary source code, deployment scripts, and internal configuration material. The stolen data was then offered for sale on a criminal forum, potentially enabling further malicious activities by other threat actors who purchase the data. Although customer data was reportedly unaffected, the incident impacts GitHub's intellectual property and internal security posture.

## Recommendation

*   Audit installed VS Code extensions across developer endpoints, flagging new, rare, or suspicious publishers as noted in the overview.
*   Hunt for IDE-driven anomalies, such as VS Code child processes spawning Git outside working hours; deploy the "Detect VS Code Spawning Git" Sigma rule.
*   Enforce short-lived tokens, scoped access, and SSO for source control to mitigate future credential theft, rotating any long-lived developer access tokens as described in the overview.
*   Review audit logs for mass-clone behavior or unusual repository read patterns, as described in the overview.
