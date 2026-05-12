---
title: Mini Shai-Hulud Campaign Compromises npm Packages
slug: 2026-05-mini-shai-hulud-npm
description: The Mini Shai-Hulud supply chain campaign, attributed to TeamPCP, has compromised several npm packages, including those within the @tanstack, @uipath, and @mistralai namespaces, leading to credential theft and potential further compromise.
date: "2026-05-12T07:01:02Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - npm
  - malware
vendors:
  - TanStack
  - UiPath
  - Mistral AI
products:
  - '@tanstack/react-router'
  - '@uipath/apollo-core'
  - '@mistralai/mistralai'
affected_os:
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1608
    technique_name: Stage Capabilities
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1572
    technique_name: Protocol Application Layer Protocol
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
references:
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
iocs:
  - type: domain
    value: git-tanstack.com
  - type: domain
    value: seed1.getsession.org
  - type: domain
    value: seed2.getsession.org
  - type: domain
    value: seed3.getsession.org
  - type: domain
    value: filev2.getsession.org
  - type: hash_sha256
    value: ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
  - type: hash_sha256
    value: 2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
  - type: hash_sha256
    value: 2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df
ioc_counts:
  domain: 5
  hash_sha256: 3
rules:
  - title: Detect Malicious setup.mjs Execution
    description: Detects execution of the malicious setup.mjs script used in the UiPath package compromise.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1608.001
    data_sources:
      - process_creation
      - linux
  - title: Detect router_init.js File Creation
    description: Detects the creation of the router_init.js file with a specific size associated with the TanStack compromise.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1608.001
    data_sources:
      - file_event
      - linux
  - title: Detect gh-token-monitor Persistence
    description: Detects installation of the gh-token-monitor LaunchAgent or systemd service.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
rules_count: 3
---

On May 11, 2026, TeamPCP launched a coordinated supply chain attack against the npm ecosystem, compromising packages across multiple namespaces simultaneously. Impacted packages include those in the @tanstack, @uipath, and @mistralai namespaces. The TanStack compromise exploited a chain of three vulnerabilities in GitHub Actions, allowing the attacker to poison the cache and extract OIDC tokens. The published packages contain two infection vectors: an optionalDependencies entry and an embedded ~2.3MB obfuscated file named router_init.js. The UiPath packages use a preinstall script (node setup.mjs) to download the Bun runtime and execute the payload. This campaign uses similar methods to previous TeamPCP operations.

## Attack Chain

1. Attacker creates a fork of a legitimate repository (e.g., TanStack/router) and renames it (e.g., zblgg/configuration).
2. Attacker opens a pull request to the original repository, triggering a `pull_request_target` workflow.
3. The workflow checks out and executes the attacker's fork code.
4. The attacker's code poisons the GitHub Actions cache with a malicious pnpm store.
5. Legitimate maintainer pull requests are merged, restoring the poisoned cache.
6. Attacker-controlled binaries extract OIDC tokens from the GitHub Actions runner's process memory (`/proc/<pid>/mem`).
7. The attacker uses stolen tokens to publish malicious package versions to npm.
8. The published packages execute a credential stealer and self-propagating worm that exfiltrates data via git-tanstack[.]com, Session messenger network, and GitHub API dead drops.

## Impact

The compromised npm packages can lead to the theft of sensitive credentials, including CI/CD tokens (GitHub Actions OIDC, GitLab, CircleCI), cloud credentials (AWS IMDSv2, GCP, Azure), Kubernetes service accounts, HashiCorp Vault tokens, and package registry tokens. The self-propagating worm functionality allows the attacker to further compromise other npm packages the victim has write access to. On developer machines, the malware installs a persistent gh-token-monitor daemon that polls GitHub and can wipe the home directory if a token is revoked.

## Recommendation

*   Search lockfiles and CI logs for affected package versions, specifically looking for `router_init.js` or `setup.mjs` at package roots (see affected packages list in this brief).
*   Search for the `gh-token-monitor` daemon on developer machines and remove it before revoking GitHub tokens to avoid the wiper (see Attack Chain and Overview).
*   Block the C2 domain `git-tanstack.com` and `*.getsession.org` at the DNS/proxy level (see IOCs).
