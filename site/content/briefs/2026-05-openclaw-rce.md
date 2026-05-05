---
title: OpenClaw Arbitrary Code Execution via Malicious Plugin
slug: 2026-05-openclaw-rce
description: OpenClaw is vulnerable to arbitrary code execution due to insecure plugin loading from the current working directory, allowing attackers to execute malicious JavaScript code when a user runs OpenClaw commands from a compromised directory.
date: "2026-05-05T18:43:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - supply-chain
  - javascript
vendors:
  - npm
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-r39h-4c2p-3jxp
rules:
  - title: Detect OpenClaw Execution from Suspicious Directory
    description: Detects OpenClaw execution from a world-writable directory, which is often a sign of potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious setup-api.js Execution by OpenClaw
    description: Detects the execution of setup-api.js from extensions directory which could indicate a malicious plugin execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.4.23 are susceptible to arbitrary code execution. The vulnerability arises from the bundled plugin setup resolver's fallback mechanism, which could inadvertently resolve provider setup metadata from `process.cwd()`. This means that if a user executes an OpenClaw command within an attacker-controlled repository containing a malicious `extensions/<plugin>/setup-api.js` file, OpenClaw could load and execute this JavaScript. This occurs during the normal process of provider/model status resolution. Defenders should be aware that exploitation requires user interaction, specifically running OpenClaw from a directory containing the malicious setup file.

## Attack Chain

1.  Attacker creates a malicious repository containing a specially crafted `extensions/<plugin>/setup-api.js` file designed for arbitrary code execution.
2.  The attacker distributes the malicious repository, potentially through social engineering or compromised software packages.
3.  A user clones or otherwise obtains the malicious repository onto their system.
4.  The user navigates to the malicious repository in their terminal or command prompt.
5.  The user executes an OpenClaw command, such as inspecting provider/model status (e.g., `openclaw provider status`).
6.  OpenClaw's plugin setup resolver incorrectly prioritizes `process.cwd()` when searching for `setup-api.js`.
7.  The malicious `setup-api.js` file is loaded and executed within the OpenClaw process.
8.  The attacker achieves arbitrary code execution under the user's account, potentially leading to data theft, system compromise, or further lateral movement.

## Impact

Successful exploitation allows an attacker to execute arbitrary JavaScript code within the OpenClaw process, running under the privileges of the user executing the command.  This could lead to the compromise of sensitive data, installation of malware, or further exploitation of the user's system. While the vulnerability requires user interaction, it poses a significant risk to developers and users who interact with untrusted OpenClaw repositories.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.23 or later to remediate the vulnerability as described in the advisory (https://github.com/advisories/GHSA-r39h-4c2p-3jxp).
*   Implement process monitoring to detect unusual JavaScript execution originating from the OpenClaw process to detect potential exploitation attempts using the detection rules provided below.
*   Educate users about the risks of running OpenClaw commands from untrusted directories, especially those containing `extensions/<plugin>/setup-api.js`.
