---
title: Electerm Command Injection Vulnerability via runLinux Function
slug: 2024-01-electerm-command-injection
description: A command injection vulnerability exists in electerm's install.js due to insufficient validation in the runLinux() function, allowing attackers to execute arbitrary commands by manipulating remote release metadata.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - electerm
  - npm
products:
  - electerm
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-8x35-hph8-37hq
  - https://github.com/electerm/electerm/commit/59708b38c8a52f5db59d7d4eff98e31d573128ee
rules:
  - title: Electerm NPM install Command Injection
    description: Detects command injection attempts during npm install of electerm package by monitoring process execution with suspicious command line arguments.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Child Processes of NPM
    description: Detects suspicious child processes spawned by npm, indicating potential command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical command injection vulnerability has been identified in Electerm, specifically affecting users who install the application via `npm install -g electerm` on Linux systems. The vulnerability resides within the `runLinux()` function in `github.com/elcterm/electerm/npm/install.js`. This function lacks proper validation when appending remote version strings into an `exec("rm -rf ...")` command. An attacker capable of controlling the remote release metadata (e.g., version string, release name) served by Electerm's update server could exploit this flaw to execute arbitrary system commands. This could lead to tampering with local files and a complete compromise of development or runtime assets. This vulnerability affects Electerm versions prior to 3.3.8.

## Attack Chain

1.  Attacker gains control over the Electerm update server or performs a man-in-the-middle attack.
2.  The attacker crafts malicious release metadata, including a crafted version string containing command injection payloads.
3.  A user on a Linux system executes `npm install -g electerm` to install or update Electerm.
4.  The `install.js` script fetches the malicious release metadata from the compromised update server.
5.  The `runLinux()` function appends the attacker-controlled version string directly into an `exec("rm -rf ...")` command.
6.  The `exec()` function executes the command, resulting in arbitrary command execution with the privileges of the user running `npm install`.
7.  The attacker can then tamper with local files, install backdoors, or escalate privileges.
8.  The attacker achieves complete system compromise, potentially exfiltrating sensitive data or using the compromised system as a pivot point.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary system commands on the victim's machine. This can lead to complete system compromise, including unauthorized access to sensitive data, installation of malware, and further propagation of the attack within the network. Given the nature of `npm install`, developers are primarily at risk. The impact could be significant for development environments.

## Recommendation

*   Apply the following rule to detect command injection attempts within npm installations referencing the electerm package: `Electerm NPM install Command Injection`.
*   Monitor network traffic for connections to unexpected or suspicious update servers that could be serving malicious Electerm release metadata using network connection logs.
*   While the vulnerability is patched in later versions, ensure users are aware of the risks associated with running older versions of Electerm (`< 3.3.8`).
