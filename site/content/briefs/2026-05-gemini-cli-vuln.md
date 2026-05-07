---
title: Gemini CLI Vulnerability Leads to Potential Supply Chain Attack
slug: 2026-05-gemini-cli-vuln
description: A critical vulnerability in Google's Gemini CLI, an open-source AI agent, could have enabled attackers to inject malicious prompts into GitHub issues, leading to code execution and a supply chain compromise.
date: "2026-05-07T10:39:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - prompt-injection
  - code-execution
vendors:
  - Google
products:
  - Gemini CLI
  - gemini-cli's repository
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0009
    tactic_name: Supply Chain Compromise
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.securityweek.com/gemini-cli-vulnerability-could-have-led-to-code-execution-supply-chain-attack/
rules:
  - title: Detect Suspicious Gemini CLI Command Execution
    description: Detects suspicious command execution by Gemini CLI, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Gemini CLI Configuration File Access
    description: Detects access to Gemini CLI configuration files, potentially indicating unauthorized access in headless mode.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability was discovered in Gemini CLI, an open-source AI agent that provides terminal access to Google's Gemini AI assistant. The vulnerability stemmed from the `-yolo` mode, which bypassed tool allowlists, allowing arbitrary command execution. An attacker could inject malicious prompts into a public GitHub issue within a Google repository. This could then be exploited to take over the AI agent designed to triage the issue. This could potentially lead to the extraction of internal secrets, full repository write access, and a complete supply chain compromise. At least eight Google repositories were found to have the same vulnerable workflow template deployed. The vulnerability was addressed on April 24, 2026, with the release of Gemini CLI version 0.39.1, which implements tool allowlisting in `-yolo` mode, and an update to the `run-gemini-cli` GitHub Action.

## Attack Chain

1.  Attacker creates a public issue on a Google-owned GitHub repository.
2.  The attacker embeds malicious prompts within the text of the GitHub issue.
3.  The AI agent (Gemini CLI) automatically triages the issue in `-yolo` mode.
4.  Due to the bypassed allowlists, the injected malicious prompts are executed by the agent.
5.  The agent extracts internal secrets from the build environment based on attacker instructions.
6.  The agent sends the extracted secrets to an attacker-controlled server.
7.  Using the stolen credentials, the attacker obtains a token with full write access to the repository.
8.  The attacker pushes arbitrary code to the main branch of the `gemini-cli` repository, impacting all downstream users.

## Impact

This vulnerability could have enabled a full supply chain compromise, potentially affecting all users of Gemini CLI and other repositories with the same vulnerable workflow templates. An attacker could inject malicious code into the `gemini-cli` repository, leading to widespread distribution of compromised software. The number of affected users and systems is unknown, but the potential impact is significant given the broad use of open-source tools and the high CVSS score.

## Recommendation

*   Upgrade to Gemini CLI version 0.39.1 or later to ensure proper tool allowlisting is enforced, as detailed in the overview.
*   Review GitHub Action workflows for use of the `run-gemini-cli` action and ensure it is updated to the latest version, mitigating the vulnerability described in the overview.
*   Monitor GitHub issue creation events for suspicious patterns indicative of prompt injection, helping to identify potential exploit attempts as outlined in the attack chain.
*   Deploy the Sigma rule `Detect Suspicious Gemini CLI Command Execution` to detect command execution patterns associated with potential exploitation attempts.
*   Deploy the Sigma rule `Detect Gemini CLI Configuration File Access` to monitor for unauthorized access to configuration files in headless mode, as mentioned in the overview.
