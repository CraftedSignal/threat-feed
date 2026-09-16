---
title: PhantomRaven Information Stealer
slug: 2026-09-phantomraven-stealer
description: A bug bounty hunter is leveraging LLM-generated JavaScript information stealers distributed via malicious npm packages to identify vulnerabilities for bounty submissions.
date: "2026-09-16T07:01:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - infostealer
  - supply-chain
  - npm
  - malware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: The threat actor attributed the compromise to a dependency-confusion attack that used malicious npm packages to deploy PhantomRaven.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: The actor also creates variants in Python for the PyPI repository.
    confidence_band: high
iocs:
  - type: domain
    value: npm.jpartifacts.com
  - type: domain
    value: packages.storeartifact.com
  - type: domain
    value: registry.storageartifact.com
  - type: domain
    value: packages.storageartifact.com
  - type: ip
    value: 54.173.15.59
  - type: hash_sha256
    value: c31831d47fcbf52ff1f4e61838611916a4276d005a564e69946d5dac04235eed
  - type: hash_sha256
    value: 95a7dcc6de46826b22c43bee7fc550f3b5e2e6cbc5f33b0c241faf523641cf63
  - type: hash_sha256
    value: db3fe46df0a65fe9f8c99d2e11126a032a72e9814e354ce017448ce088a01e02
ioc_counts:
  domain: 4
  hash_sha256: 3
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block listed C2 domains and IP addresses
      owner: SOC
      due: 24h
      evidence: Source provides explicit list of C2 infrastructure.
  mitigation_plan:
    - priority: immediate
      action: Review and audit npm/PyPI dependencies for project build environments
      owner: IT Operations
      addresses: Supply Chain Compromise
      evidence: Source identifies dependency-confusion as primary vector.
---

CrowdStrike Counter Adversary Operations identified a financially motivated threat actor who utilizes LLM-generated JavaScript (JS) code to create the PhantomRaven information stealer. Active since November 2022, the actor operates as a bug bounty hunter, using the malware to identify security weaknesses in target environments for submission to bug bounty programs rather than selling logs on illicit marketplaces. 

The actor distributes the malware via dependency-confusion attacks on the npm registry, hosting malicious packages such as 'transform-jsbi-to-bigint' and 'sort-imports-es6-autofix'. Analysis of the code reveals characteristics highly indicative of LLM generation, including verbose comments, placeholder code, and specific token-analysis patterns. The actor frequently contacts organizations to disclose vulnerabilities, using the claim of a successful compromise as leverage for bounty payouts.

## Attack Chain

1. The attacker publishes typosquatted or malicious packages (e.g., 'transform-jsbi-to-bigint') to the public npm registry.
2. A developer or automated build system installs the malicious dependency into their development or production environment.
3. The package's 'preinstall' script executes automatically upon installation via the npm package manager.
4. The script executes a secondary payload that initiates a connection to attacker-controlled infrastructure, such as 'npm.jpartifacts.com'.
5. PhantomRaven collects system information and potentially sensitive environment data from the infected host.
6. The data is exfiltrated to the C2 infrastructure to facilitate the actor's vulnerability discovery process.
7. The attacker contacts the victim, claiming to have achieved RCE or unauthorized access to justify a bug bounty submission.

## Impact

The use of PhantomRaven allows the threat actor to gain unauthorized access to target environments. While the primary goal observed is vulnerability discovery for bug bounty payouts, the capability of the information stealer poses a significant risk to the confidentiality and integrity of victim networks, potentially exposing environment variables, configuration files, and proprietary source code.

## Recommendation

* Block the C2 domains 'npm.jpartifacts.com', 'packages.storeartifact.com', 'registry.storageartifact.com', and 'packages.storageartifact.com' at the DNS resolver and proxy levels.
* Implement package vetting processes to detect and prevent the installation of typosquatted or untrusted npm/PyPI dependencies.
* Use software composition analysis (SCA) tools to audit project dependencies for suspicious 'preinstall' scripts and unexpected network requests during build-time.
* Monitor internal network egress for unusual HTTP/HTTPS connections originating from build servers or developer workstations to the identified C2 infrastructure.
