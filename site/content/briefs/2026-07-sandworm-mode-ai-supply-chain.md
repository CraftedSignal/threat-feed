---
title: 'Denying the Worm: Detecting SANDWORM_MODE and AI Toolchain Supply Chain Attacks'
slug: 2026-07-sandworm-mode-ai-supply-chain
description: The SANDWORM_MODE campaign is a multi-stage npm supply chain worm that targets AI-augmented development workflows by exploiting runtime behaviors of AI coding assistants and CI/CD pipelines, leading to credential theft, supply chain poisoning, and persistence through obfuscated loaders, credential harvesting, and malicious Git hooks.
date: "2026-07-21T17:23:33Z"
lastmod: "2026-07-26T08:11:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain-attack
  - npm
  - git
  - ai-toolchain
  - development-workflow
  - code-injection
  - credential-theft
  - persistence
  - evasion
vendors:
  - GitHub
  - GitLab
  - Atlassian
  - OpenAI
  - Anthropic
  - Google
  - Cloudflare
  - npm
  - PyPI
  - Microsoft
  - Cursor
  - Bitbucket
  - Windsurf
  - Socket.dev
  - CrowdStrike
  - npm Inc.
  - Python Software Foundation
  - Cursor.sh
  - Cursor AI
  - Claude AI
  - npmjs
  - Claude
  - Python Package Index
  - OpenJS Foundation
  - Software Freedom Conservancy
  - Copilot
  - Claude Code
  - Git
  - Node.js Foundation
products:
  - npm
  - PyPI
  - GitHub Actions
  - GitLab CI
  - Bitbucket Pipelines
  - GitHub Copilot
  - Cursor
  - Claude Code
  - GitHub
  - OpenAI
  - Anthropic
  - Google APIs
  - Cloudflare Workers
  - Git
  - Cloudflare Worker
  - Windsurf
  - GitHub Secrets
  - OpenAI API
  - Anthropic API
  - Google API
  - OpenAI APIs
  - Anthropic APIs
  - Node.js
  - GitHub REST/GraphQL API
  - Copilot
  - npm packages
  - PyPI packages
  - .npmrc
  - GitHub REST API
  - GitHub GraphQL API
  - Google AI APIs
  - npm registry
  - PyPI registry
  - GitHub API
  - npm package registry
  - GitLab
  - Bitbucket
  - Node.js runtime
  - git hooks
  - OpenAI LLM provider services
  - Anthropic LLM provider services
  - Google LLM provider services
  - PyPI package registry
  - Cursor (AI assistant)
  - Claude Code (AI assistant)
  - Windsurf (AI assistant)
  - OpenAI services
  - Anthropic services
  - Google LLM APIs
  - GitHub (Secrets, REST/GraphQL API)
  - Google
  - .npmrc tokens
  - .git-templates/hooks
  - Anthropic Claude Code
  - git config
affected_os:
  - Linux
  - macOS
  - Windows
  - Node.js runtime
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The initial payload employs multi-layer encoding via Base64 decode, zlib inflate, XOR decryption, and indirect eval() or Module._compile() calls, which are triggered on package import.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The initial payload employs multi-layer encoding via Base64 decode, zlib inflate, XOR decryption, and indirect eval() or Module._compile() calls, which are triggered on package import... After the gate clears, AES-256-GCM decryption unpacks the full payload into /dev/shm, executes it via require(), then immediately unlinks the file.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event-Triggered Execution
    evidence: The worm establishes persistence by writing malicious pre-commit and pre-push hooks to ~/.git-templates/hooks/, then sets git config --global init.templateDir to point at this directory.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The initial payload employs multi-layer encoding via Base64 decode, zlib inflate, XOR decryption, and indirect eval() or Module._compile() calls, which are triggered on package import. This technique bypasses many static analysis tools, which rely on scanning package contents at the time of publishing.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: AES-256-GCM decryption unpacks the full payload into /dev/shm, executes it via require(), then immediately unlinks the file.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: 'Upon activation, the loader performs the following steps: Fingerprinting the runtime environment to determine if execution is on a developer workstation or CI runner.'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Extraction of .npmrc tokens, environment variables matching distinct patterns (KEY, SECRET, TOKEN, or PASSWORD), and cryptocurrency wallet keys.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Extraction of .npmrc tokens, environment variables matching distinct patterns (KEY, SECRET, TOKEN, or PASSWORD), and cryptocurrency wallet keys.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Extraction of .npmrc tokens, environment variables matching distinct patterns (KEY, SECRET, TOKEN, or PASSWORD), and cryptocurrency wallet keys.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Harvested cryptocurrency keys are immediately sent in an HTTP POST request to an attacker-controlled Cloudflare Worker endpoint.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Harvested cryptocurrency keys are immediately sent in an HTTP POST request to an attacker-controlled Cloudflare Worker endpoint.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Through GitHub API tokens, it enumerates accessible repositories, injects a carrier dependency, commits or opens a pull request, and injects a pull_request_target workflow that executes in the context of the base repository, bypassing fork-based isolation.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: When API-based methods are unavailable, an SSH fallback authenticates via ssh -T git@github.com, clones target repositories directly, injects the dependency, and pushes.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/
iocs:
  - type: domain
    value: github.com
  - type: other
    value: ~/.git-templates/hooks/
  - type: other
    value: git config --global init.templateDir
  - type: file-path
    value: ~/.git-templates/hooks/
  - type: other
    value: /dev/shm
  - type: other
    value: .npmrc tokens
  - type: other
    value: GitHub API tokens
  - type: other
    value: cryptocurrency wallet keys
  - type: file-path
    value: /dev/shm
  - type: domain
    value: git@github.com
  - type: file
    value: .npmrc
  - type: path
    value: ~/.git-templates/hooks/
  - type: operating_system_function
    value: /dev/shm
  - type: npm package
    value: 19 malicious packages
  - type: domain
    value: cloudflare.com
  - type: file_path
    value: /.git-templates/hooks/
  - type: campaign_name
    value: SANDWORM_MODE
  - type: file_path
    value: /dev/shm
  - type: file_path
    value: ~/.git-templates/hooks/
  - type: campaign-name
    value: SANDWORM_MODE
  - type: filename
    value: /dev/shm
  - type: filepath
    value: ~/.git-templates/hooks/
  - type: path
    value: /dev/shm
  - type: filename
    value: .npmrc
  - type: keyword
    value: SANDWORM_MODE
  - type: file
    value: .npmrc tokens
  - type: file
    value: ~/.git-templates/hooks/
  - type: variable
    value: KEY
  - type: variable
    value: SECRET
  - type: variable
    value: TOKEN
  - type: variable
    value: PASSWORD
  - type: cryptocurrency_wallet
    value: cryptocurrency wallet keys
  - type: string
    value: SANDWORM_MODE
  - type: string
    value: .npmrc tokens
  - type: string
    value: environment variables matching distinct patterns (KEY, SECRET, TOKEN, or PASSWORD)
  - type: string
    value: cryptocurrency wallet keys
  - type: other
    value: environment variables matching patterns (KEY, SECRET, TOKEN, PASSWORD)
  - type: other
    value: Stage 0 loader shim
  - type: other
    value: carrier dependency
  - type: other
    value: attacker-controlled Cloudflare Worker endpoint
  - type: other
    value: 19 malicious npm packages
  - type: other
    value: SANDWORM_MODE
  - type: filepath
    value: /dev/shm
ioc_counts:
  campaign-name: 1
  campaign_name: 1
  cryptocurrency_wallet: 1
  domain: 3
  file: 3
  file-path: 2
  file_path: 3
  filename: 2
  filepath: 2
  keyword: 1
  npm package: 1
  operating_system_function: 1
  other: 12
  path: 2
  string: 4
  variable: 4
rules:
  - title: Detect Git Global Template Directory Modification for Persistence
    description: Detects SANDWORM_MODE setting git config --global init.templateDir to an arbitrary path to establish persistence by ensuring future git operations inherit malicious hooks.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1546
      - T1546.007
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Git Hook Creation in Global Template Directory
    description: Detects SANDWORM_MODE creating or modifying executable files in the global git templates hooks directory, indicating an attempt to establish persistence via event-triggered execution.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1546
      - T1546.007
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious npm Publish Activity from Non-CI Environments
    description: Detects SANDWORM_MODE performing npm publish commands from contexts outside of typical CI/CD pipelines, indicating a potential compromise of developer workstations or supply chain attack.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1620
    data_sources:
      - process_creation
      - linux
rules_count: 3
updates:
  - at: "2026-07-25T09:11:24Z"
    level: L1
    summary: new IOCs
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/
  - at: "2026-07-25T11:21:32Z"
    level: L1
    summary: new vendor
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/
  - at: "2026-07-25T16:19:48Z"
    level: L1
    summary: new product
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/
  - at: "2026-07-26T01:29:39Z"
    level: L1
    summary: new IOCs
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/
  - at: "2026-07-26T08:11:56Z"
    level: L1
    summary: new IOCs
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/
---

CrowdStrike has identified a sophisticated multi-stage npm supply chain worm, internally tracked as SANDWORM_MODE, which has affected 19 malicious packages distributed across two unique publisher aliases. This campaign, active since at least February 2026, represents a new class of attacks targeting AI-augmented development workflows. Unlike typical supply chain attacks that focus on build outputs or static backdoors, SANDWORM_MODE is designed to exploit the runtime behaviors of AI coding assistants, CI automation, and large language model (LLM) toolchains. Its primary evasion technique involves multi-layer obfuscation and delayed payload unpacking, bypassing static analysis. The worm conducts reconnaissance to steal sensitive credentials, including npm tokens, environment variables (KEY, SECRET, TOKEN, PASSWORD), and cryptocurrency wallet keys, exfiltrating them to attacker-controlled Cloudflare Workers. It achieves persistence and propagates by injecting malicious code into new npm packages, modifying GitHub repositories via API or SSH, and establishing malicious Git hooks in developer environments, posing a significant threat to software development integrity.

## Attack Chain

1. The initial payload is delivered via a malicious npm package and employs multi-layer obfuscation (Base64, zlib, XOR) and indirect JavaScript execution methods like `eval()` or `Module._compile()` to unpack the payload at runtime, evading static analysis.
2. Upon activation, the loader fingerprints the runtime environment to determine if it's a developer workstation or a CI runner; CI environments trigger the next stage immediately, bypassing a time-delay gate.
3. The worm performs initial reconnaissance, extracting sensitive credentials such as `.npmrc` tokens, environment variables matching patterns like KEY, SECRET, TOKEN, or PASSWORD, and cryptocurrency wallet keys.
4. Harvested cryptocurrency keys are immediately exfiltrated via an HTTP POST request to an attacker-controlled Cloudflare Worker endpoint.
5. A time-delay gate (48-96 hours) is initiated for developer workstations before the main payload decrypts; in CI environments, decryption occurs instantly.
6. The full Stage 2 payload is decrypted using AES-256-GCM, unpacked into `/dev/shm`, executed via `require()`, and then immediately unlinked to remove on-disk forensic artifacts.
7. The worm propagates by injecting the Stage 0 loader into new npm packages published under compromised accounts, by using stolen GitHub API tokens to inject carrier dependencies and `pull_request_target` workflows, or via SSH to clone and push code changes.
8. Persistence is established on developer systems by writing malicious `pre-commit` and `pre-push` hooks to `~/.git-templates/hooks/` and configuring `git config --global init.templateDir` to point to this directory, ensuring new repositories inherit the hooks.

## Impact

The SANDWORM_MODE campaign critically compromises AI-augmented software development lifecycles by infecting widely used package registries and source control platforms. Successful attacks lead to the theft of sensitive credentials such as npm tokens, GitHub API keys, and cryptocurrency wallets, which can be used for further supply chain attacks or financial gain. Organizations face significant risks including the distribution of poisoned software dependencies to downstream consumers, unauthorized code modifications in source repositories, and persistent compromise of developer workstations and CI/CD pipelines. The stealthy nature of the attack, particularly its evasion of static analysis and ephemeral execution, makes detection challenging and increases the potential for widespread and long-lasting damage across the software supply chain.

## Recommendation

* Deploy the provided Sigma rules to your SIEM and tune for your environment to detect suspicious `git` and `npm` activities.
* Monitor `process_creation` logs for suspicious modifications to `git config --global init.templateDir` as described in `Detect Git Global Template Directory Modification for Persistence`.
* Enable `file_event` logging for creation/modification events in `~/.git-templates/hooks/` directories to activate the `Detect Suspicious Git Hook Creation` rule.
* Monitor `process_creation` logs for `npm publish` commands originating from unexpected users or processes, as targeted by `Detect Suspicious npm Publish Activity`.
* Implement strong credential management and regularly rotate API tokens and `.npmrc` credentials, especially in CI/CD environments.
* Utilize security scanning tools capable of dynamic analysis and runtime monitoring to detect highly obfuscated and time-delayed payloads that evade static analysis.
