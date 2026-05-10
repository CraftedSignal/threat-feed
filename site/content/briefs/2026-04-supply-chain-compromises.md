---
title: Supply Chain Compromises via Npm, PyPI Packages and Teams Phishing Campaigns
slug: 2026-04-supply-chain-compromises
description: The April 2026 Red Canary Intelligence Insights highlights the axios npm compromise, TeamPCP's LiteLLM compromise via PyPI, and a surge in Microsoft Teams phishing, leading to RAT deployment, credential harvesting, ransomware deployment, or data theft.
date: "2026-04-25T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - phishing
  - rat
  - npm
  - pypi
  - email-bombing
vendors:
  - Microsoft
  - ConnectWise
products:
  - axios
  - LiteLLM
  - Microsoft Teams
  - Microsoft Quick Assist
  - ScreenConnect
affected_os:
  - macos
  - windows
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://redcanary.com/blog/threat-intelligence/intelligence-insights-april-2026/
rules:
  - title: Detect Suspicious Postinstall Script Execution
    description: Detects suspicious execution of postinstall scripts, often used by malicious packages to install malware.
    platform: sigma
    severity: high
    tactics:
      - installation
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Tar Archive Extraction
    description: Detects suspicious extraction of archives using the 'tar' command, which can be indicative of malicious activity following Teams phishing.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Microsoft Quick Assist Execution by Non-Admin Users
    description: Detects execution of Microsoft Quick Assist by non-administrator users, which can be indicative of a user being tricked into granting remote access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Red Canary's April 2026 Intelligence Insights report details several prominent threats observed in March 2026. The most significant was the axios npm compromise, where attackers gained control of a lead maintainer's account on March 30, 2026, and published two malicious versions of the axios package. This was achieved by bypassing the project's GitHub Actions CI/CD pipeline after compromising the maintainer’s npm account and changing its associated email. These poisoned releases injected a hidden dependency, plain-crypto-js@4.2.1, which acted as a cross-platform RAT dropper targeting macOS, Windows, and Linux systems.  Additionally, the report highlights the activities of the threat group TeamPCP, which compromised LiteLLM via PyPI, and a surge in Microsoft Teams phishing campaigns paired with email bombing. These campaigns leverage social engineering to trick users into installing RMM tools.

## Attack Chain

1.  **Initial Compromise:** Attackers compromise a lead maintainer's npm account and change the associated email.
2.  **Pipeline Bypass:** The attacker bypasses the project's GitHub Actions CI/CD pipeline using the compromised account.
3.  **Malicious Package Publication:** The attacker manually publishes two malicious versions of the axios package via the npm CLI.
4.  **Dependency Injection:** The poisoned releases inject a hidden dependency called plain-crypto-js@4.2.1.
5.  **RAT Dropper Execution:** The injected dependency executes a postinstall script, functioning as a cross-platform RAT dropper.
6.  **Payload Installation:** The RAT dropper installs a remote access trojan (RAT) on macOS, Windows, and Linux systems.
7.  **Email Bombing and Teams Phishing:**  Victims are flooded with spam emails, followed by contact from an adversary posing as IT support via Microsoft Teams.
8.  **RMM Installation:** The adversary guides the user into running an RMM tool like Microsoft Quick Assist, leading to potential ransomware deployment or data theft.

## Impact

The axios npm compromise resulted in the potential installation of RAT payloads on macOS, Windows, and Linux systems.  TeamPCP's compromise of LiteLLM via PyPI highlights the risk of supply chain attacks leading to credential harvesting and coinmining. The increase in Microsoft Teams phishing paired with email bombing can lead to the installation of RMM tools, potentially resulting in ransomware deployment or data theft.  Successful attacks may result in significant financial losses, data breaches, and reputational damage.

## Recommendation

*   Enable two-factor authentication (2FA) for all accounts with publishing rights to the npm package repository to mitigate impacts from npm compromises as described in the overview.
*   Deploy the Sigma rule "Detect Suspicious Tar Archive Extraction" to identify potential malicious file extraction activities associated with the Microsoft Teams phishing campaigns.
*   Evaluate and baseline legitimate RMM applications running in your environment, particularly Microsoft Quick Assist, as mentioned in the attack chain, to provide critical context for identifying abused tools.
*   Implement a policy that all calls with IT be conducted over the approved video conferencing application, ensuring users know how to verify the caller's identity, as mentioned in the analysis of Teams phishing campaigns.
