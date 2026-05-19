---
title: Shai-Hulud Campaign Returns Targeting npm Maintainer Accounts
slug: 2026-05-shai-hulud-returns
description: The Shai-Hulud campaign is back and targets maintainer accounts to publish malicious code directly into the software supply chain via npm, recently hitting the Ant Design (AntV) ecosystem and potentially exposing downstream developers to credential theft and remote code execution.
date: "2026-05-19T17:17:55Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Shai-Hulud
tags:
  - supply-chain
  - npm
  - credential-theft
  - remote-code-execution
vendors:
  - Sonatype
products:
  - npm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://www.sonatype.com/blog/shai-hulud-is-back-maintainers-the-target
  - https://www.sonatype.com/blog/the-second-coming-of-shai-hulud-attackers-innovating-on-npm
rules:
  - title: Detect Suspicious Outbound Connection from NPM
    description: Detects suspicious outbound network connections initiated by npm processes, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

The Shai-Hulud campaign has resurfaced, focusing on compromising npm maintainer accounts to inject malicious code directly into the software supply chain. This avoids the need to exploit traditional vulnerabilities. The latest wave of attacks, observed in May 2026, targeted the Ant Design (AntV) ecosystem. Successful compromises of maintainer accounts allowed attackers to publish malicious versions of trusted packages. This resulted in downstream developers unknowingly incorporating backdoored code into their projects, potentially leading to credential theft and remote code execution within their environments. The re-emergence of Shai-Hulud highlights the ongoing risk of supply chain attacks and the importance of securing developer accounts.

## Attack Chain

1.  Attacker identifies a target npm package within the Ant Design (AntV) ecosystem.
2.  Attacker gains unauthorized access to the npm account of the package maintainer, likely through credential theft or account compromise.
3.  Attacker injects malicious code into the package's source code, potentially targeting credential theft and remote code execution.
4.  Attacker publishes a new, compromised version of the npm package to the npm registry.
5.  Downstream developers unknowingly update their projects to use the compromised package version.
6.  The malicious code executes within the developers' environments, potentially stealing credentials or establishing a reverse shell for remote access.

## Impact

This campaign has the potential to compromise numerous downstream developers who rely on the affected Ant Design (AntV) npm packages. Successful exploitation could lead to widespread credential theft, allowing attackers to pivot to other systems and resources. Remote code execution could grant attackers persistent access to developer environments, enabling further malicious activities, including supply chain attacks on other projects.

## Recommendation

*   Monitor npm package updates for unexpected changes in dependencies or file hashes that could indicate a compromised package (review file_event logs for npm package directories).
*   Implement multi-factor authentication (MFA) for all npm accounts to prevent account compromise.
*   Deploy the Sigma rule to detect suspicious network connections originating from npm-related processes.
