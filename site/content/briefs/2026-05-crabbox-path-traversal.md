---
title: Crabbox Path Traversal Vulnerability (CVE-2026-45224)
slug: 2026-05-crabbox-path-traversal
description: Crabbox versions before 0.9.0 contain a path traversal vulnerability (CVE-2026-45224) in the Islo provider's workspace path resolution, allowing attackers to cause arbitrary file deletion and overwrite by crafting malicious .crabbox.yaml files with traversal sequences when sync.delete is enabled.
date: "2026-05-11T19:17:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-deletion
  - file-overwrite
  - CVE-2026-45224
products:
  - Crabbox < 0.9.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-45224
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45224
rules:
  - title: Detect Crabbox Path Traversal Attempt via Malicious YAML
    description: Detects CVE-2026-45224 exploitation — Detects suspicious .crabbox.yaml or crabbox.yaml files containing path traversal sequences (../) indicating a potential path traversal attempt
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious rm -rf or mkdir -p with Path Traversal
    description: Detects suspicious rm -rf or mkdir -p commands with path traversal sequences, potentially related to CVE-2026-45224 exploitation
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Crabbox, a software tool with unspecified functionality, is vulnerable to a path traversal flaw affecting versions prior to 0.9.0. The vulnerability lies within the Islo provider's workspace path resolution logic. By supplying specially crafted `.crabbox.yaml` or `crabbox.yaml` files containing directory traversal sequences (e.g., `../`), attackers can manipulate the application to resolve paths outside the intended `/workspace` directory. When the `sync.delete` option is enabled, this vulnerability allows for arbitrary file deletion and overwrite because the application uses `rm -rf` and `mkdir -p` on the attacker-controlled, resolved path without proper input sanitization. This can lead to significant data loss or system compromise.

## Attack Chain

1.  Attacker crafts a malicious `.crabbox.yaml` or `crabbox.yaml` file.
2.  The malicious YAML file contains path traversal sequences (e.g., `../`) within the workspace path definition.
3.  The attacker places the crafted YAML file in a location accessible to the Crabbox application.
4.  The Crabbox application processes the YAML file using the Islo provider.
5.  The Islo provider's workspace path resolution logic resolves the attacker-supplied path, failing to properly sanitize directory traversal sequences.
6.  If `sync.delete` is enabled, the application executes `rm -rf` on the resolved (malicious) path, leading to arbitrary file deletion.
7.  Subsequently, the application executes `mkdir -p` on the resolved path, potentially overwriting existing files and directories.
8.  The attacker achieves arbitrary file deletion and overwrite, potentially leading to data loss or system compromise.

## Impact

Successful exploitation of CVE-2026-45224 allows attackers to delete or overwrite arbitrary files and directories on the system where Crabbox is running. The severity of the impact depends on the privileges of the Crabbox process and the location of the files that are targeted. A successful attack could lead to data loss, denial of service, or in some circumstances, even remote code execution if critical system files are overwritten.

## Recommendation

*   Upgrade Crabbox to version 0.9.0 or later to patch CVE-2026-45224.
*   As a workaround, disable the `sync.delete` option in Crabbox configurations to mitigate the file deletion aspect of the vulnerability.
*   Implement the Sigma rule "Detect Crabbox Path Traversal Attempt via Malicious YAML" to detect suspicious `.crabbox.yaml` files containing path traversal sequences.
*   Monitor file system events for `rm -rf` and `mkdir -p` commands executed by the Crabbox process, especially when the target paths contain directory traversal sequences, using the Sigma rule "Detect Suspicious rm -rf or mkdir -p with Path Traversal".
