---
title: OpenClaw Arbitrary Directory Deletion Vulnerability
slug: 2026-04-openclaw-directory-deletion
description: OpenClaw before 2026.4.2 is vulnerable to arbitrary directory deletion in mirror mode, enabling attackers to delete remote directories by manipulating remoteWorkspaceDir and remoteAgentWorkspaceDir configuration values.
date: "2026-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-41383
  - directory-traversal
  - file-deletion
  - openclaw
vendors:
  - openclaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-41383
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41383
  - https://github.com/openclaw/openclaw/commit/b21c9840c2e38f4bb338d031511b479d5f07ca25
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-m34q-h93w-vg5x
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-remote-directory-deletion-via-mis-scoped-mirror-mode-paths
rules:
  - title: Detect Modification of OpenClaw Configuration Files
    description: Detects attempts to modify OpenClaw configuration files, which could indicate exploitation of CVE-2026-41383.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect OpenClaw Process Accessing Suspicious Remote Paths
    description: Detects OpenClaw processes attempting to access remote file paths that may indicate an attempt to exploit CVE-2026-41383 through directory deletion.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw before version 2026.4.2 is susceptible to an arbitrary directory deletion vulnerability (CVE-2026-41383) when operating in mirror mode. An attacker with control over the OpenShell configuration paths, specifically `remoteWorkspaceDir` and `remoteAgentWorkspaceDir`, can trigger the deletion of unintended remote directory contents. This is achieved by manipulating these configuration values to point to sensitive directories. The subsequent mirror sync operation replaces the deleted contents with data from the attacker's workspace, leading to data loss and potential system compromise. This vulnerability allows an attacker to potentially wipe out important data on the remote end.

## Attack Chain

1.  The attacker gains access to the OpenClaw configuration.
2.  The attacker modifies the `remoteWorkspaceDir` and/or `remoteAgentWorkspaceDir` configuration values to point to a target directory they wish to delete.
3.  The attacker initiates a mirror sync operation.
4.  OpenClaw, using the attacker-controlled path, connects to the remote system.
5.  OpenClaw deletes the contents of the directory specified by the modified `remoteWorkspaceDir` or `remoteAgentWorkspaceDir`.
6.  OpenClaw uploads the contents of the attacker's local workspace to the now-empty remote directory, effectively replacing the original data.
7.  The targeted remote directory now contains the attacker's data instead of the original contents.
8.  The attacker achieves arbitrary directory deletion and data replacement, potentially causing significant disruption and data loss.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary deletion of files and directories on the remote system where OpenClaw is used in mirror mode. The impact includes potential data loss, service disruption, and the replacement of legitimate data with attacker-controlled content. Given the CVSS v3.1 score of 8.1, this vulnerability is considered high severity due to the potential for significant data integrity and availability impact.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.2 or later to remediate CVE-2026-41383.
*   Monitor OpenClaw configuration files for unauthorized modifications to `remoteWorkspaceDir` and `remoteAgentWorkspaceDir` using a file integrity monitoring system.
*   Implement strict access controls to OpenClaw configuration files to prevent unauthorized modification of these settings.
*   Deploy the Sigma rule to detect suspicious process execution related to modification of openclaw configuration files.
