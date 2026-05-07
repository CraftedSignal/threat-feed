---
title: Microsoft APM CLI Path Traversal Vulnerability
slug: 2024-01-apm-cli-path-traversal
description: Microsoft APM CLI version 0.8.11 and earlier are vulnerable to path traversal, allowing a malicious plugin to copy arbitrary readable host files during installation by manipulating paths in the plugin.json file.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - supply-chain
  - apm-cli
vendors:
  - Microsoft
products:
  - apm-cli
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://github.com/advisories/GHSA-xhrw-5qxx-jpwr
rules:
  - title: APM CLI Plugin Install Path Traversal - Absolute Path
    description: Detects CVE-2026-44641 exploitation — detects APM CLI plugin installations attempting to use absolute paths in plugin.json, indicative of path traversal attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: APM CLI Plugin Install Path Traversal - Relative Path
    description: Detects CVE-2026-44641 exploitation — detects APM CLI plugin installations attempting to use relative paths with traversal sequences (../) in plugin.json, indicative of path traversal attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft APM CLI is vulnerable to a path traversal vulnerability in versions 0.8.11 and earlier. This vulnerability arises during the installation of marketplace plugins, where the CLI normalizes plugins by copying components referenced in the `plugin.json` file. The `agents`, `skills`, `commands`, and `hooks` fields in `plugin.json` are attacker-controlled. However, the implementation fails to validate that these paths remain within the plugin directory. Consequently, a malicious plugin can exploit this by using absolute paths or `../` traversal paths to copy arbitrary, readable host files or directories from the installer's machine during the `apm install` process. This allows attackers to stage local files into repository-controlled paths, potentially leading to the exposure of sensitive information.

## Attack Chain

1.  Attacker crafts a malicious APM plugin with a `plugin.json` file.
2.  The `plugin.json` file contains crafted paths within the `commands` field pointing to sensitive host files using absolute paths or relative path traversal (e.g., `commands: "D:\\absolute\\path\\to\\victim\\secret.md"` or `commands: "../../../secret.md"`).
3.  A user executes the `apm install` command, referencing the malicious plugin either locally or remotely.
4.  The `normalize_plugin_directory` function in `src/apm_cli/commands/install.py` processes the plugin.
5.  The `_resolve_sources()` function in `src/apm_cli/deps/plugin_parser.py` resolves the component paths specified in `plugin.json` without proper validation.
6.  The APM CLI copies the files pointed to by the malicious paths into the `.apm/` directory.
7.  If the copied files are recognized as prompt files (e.g., end with `.prompt.md`), they are integrated into the `.github/prompts/` directory of the project via `prompt_integrator.py`.
8.  The attacker gains access to sensitive information from the copied files, which may then be committed and synced.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files from the victim's machine during the installation of a malicious APM plugin. This can lead to the disclosure of sensitive information, such as local notes, markdown files, source code, or configuration files. The copied files can be automatically written into `.github/prompts/`, increasing the likelihood that sensitive or attacker-selected content is committed, synced, or consumed by other tooling. The issue breaks the expected trust boundary that a dependency install should copy only content belonging to the dependency itself.

## Recommendation

*   Deploy the "APM CLI Plugin Install Path Traversal - Absolute Path" Sigma rule to detect attempts to use absolute paths in `plugin.json` configurations, which can be indicative of malicious plugin activity.
*   Deploy the "APM CLI Plugin Install Path Traversal - Relative Path" Sigma rule to detect attempts to use relative paths with traversal sequences in `plugin.json` configurations.
*   Upgrade to a patched version of `apm-cli` that includes the recommended fix of resolving manifest-controlled component paths against `plugin_path.resolve()`, rejecting absolute or relative paths that escape the plugin root.
*   Implement file integrity monitoring on the `.apm/` directory to detect unauthorized file modifications or additions, using file_event logging.
