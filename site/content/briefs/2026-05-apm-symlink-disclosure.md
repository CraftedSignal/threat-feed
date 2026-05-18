---
title: APM CLI Symlink Vulnerability Leads to File Content Disclosure (CVE-2026-45539)
slug: 2026-05-apm-symlink-disclosure
description: A vulnerability in the `apm-cli` tool allows a malicious APM package to include symlinks that, when installed, can lead to file-content disclosure, by dereferencing symlinks under `.apm/prompts/` and `.apm/agents/` during `apm install`, and copying host-local file contents into the project tree.
date: "2026-05-18T13:27:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - symlink
  - file-disclosure
  - apm-cli
  - dependency-confusion
vendors:
  - pip
products:
  - apm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-45539
    cvss: 7.4
    epss: 0.00076
references:
  - https://github.com/advisories/GHSA-q5pp-gvjg-h7v4
rules:
  - title: Detect APM CLI Installation with Suspicious Symlink Targets
    description: Detects CVE-2026-45539 exploitation — Flags APM CLI installations where the command line contains paths suggestive of symlink exploitation, especially those targeting sensitive files.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect APM CLI Writing Files Containing Credential-Looking Content
    description: Detects writing files containing credential-looking content in known apm deploy paths
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in the `apm-cli` tool (versions 0.5.4 through 0.12.4) where symbolic links within APM packages are mishandled during the installation process. Specifically, when an APM package containing symlinks under the `.apm/prompts/` or `.apm/agents/` directories is installed, the `apm install` command dereferences these symlinks. This leads to the contents of the linked files being copied into the project's deployment directories. This vulnerability, identified as CVE-2026-45539, allows a malicious APM package author to potentially disclose sensitive file contents from the system running the `apm install` command if the user running the command has read access to them. The issue stems from the `PromptIntegrator` and `AgentIntegrator` classes, which lack proper symlink handling.

## Attack Chain

1.  Attacker creates a malicious APM package.
2.  The package includes a symbolic link within the `.apm/agents/` or `.apm/prompts/` directory. The symlink points to a sensitive file on the victim's system (e.g., `/etc/shadow` or `/proc/self/environ`).
3.  The attacker publishes this malicious package to a repository or otherwise distributes it to victims.
4.  Victim adds the malicious package as a dependency in their `apm.yml` file.
5.  Victim runs the `apm install` command.
6.  The `apm install` command clones the package and, due to vulnerable code in `PromptIntegrator` or `AgentIntegrator`, dereferences the symbolic link.
7.  The content of the file pointed to by the symlink is copied into the victim project's deployment directories (e.g., `.github/`, `.claude/`).
8.  The attacker gains access to the disclosed file content, potentially leading to credential theft or other unauthorized access.

## Impact

Successful exploitation of this vulnerability (CVE-2026-45539) leads to arbitrary file content disclosure. An attacker can craft a malicious APM package to read and exfiltrate the content of any file readable by the user running the `apm install` command. The observed result is that the files in the deploy directories will contain the content of the linked file. This could include sensitive information like environment variables, configuration files, or even credentials. This allows the attacker to perform lateral movement or privilege escalation within the victim's environment.

## Recommendation

*   Apply the recommended fix provided in the advisory by routing affected finders through the existing safe helper (`BaseIntegrator.find_files_by_glob()`) to mitigate CVE-2026-45539.
*   Deploy the Sigma rule "Detect APM CLI Installation with Suspicious Symlink Targets" to identify attempts to exploit this vulnerability via `process_creation` logs.
*   Implement the optional defense-in-depth measures suggested in the advisory, such as raising an exception on `source.is_symlink()` within `copy_prompt`, `copy_agent`, `_write_codex_agent`, and `_write_windsurf_agent_skill` functions.
*   Treat any symlink under a dependency's `.apm/` tree as a security finding during scanning.
