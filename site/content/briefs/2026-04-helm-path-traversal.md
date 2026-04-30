---
title: Helm Plugin Path Traversal Vulnerability
slug: 2026-04-helm-path-traversal
description: A path traversal vulnerability in Helm versions 4.0.0 to 4.1.3 allows a malicious plugin to write files to arbitrary locations on the filesystem, leading to potential system compromise.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - helm
  - path-traversal
  - vulnerability
  - plugin
  - kubernetes
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Impair System
cves:
  - id: CVE-2026-35204
    epss: 0.00013
references:
  - https://github.com/advisories/GHSA-vmx8-mqv2-9gmg
rules:
  - title: Helm Plugin Install with Path Traversal
    description: Detects Helm plugin installations where the plugin.yaml contains path traversal sequences in the version field.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
  - title: Suspicious Helm Plugin Update with Path Traversal
    description: Detects Helm plugin updates where the plugin.yaml contains path traversal sequences in the version field.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Helm, a package manager for Kubernetes charts, is vulnerable to a path traversal issue. Specifically, Helm versions 4.0.0 through 4.1.3 are affected. A maliciously crafted Helm plugin, when installed or updated, can exploit this vulnerability (CVE-2026-35204) to write the plugin's contents to arbitrary locations on the user's filesystem. This can lead to overwriting critical system files or user data, potentially compromising the system's integrity. Helm v4.1.4 resolves this vulnerability by rejecting plugins with non-SemVer versions containing path traversal patterns. Defenders should ensure Helm installations are updated to the patched version or implement workarounds to validate plugin metadata.

## Attack Chain

1. An attacker crafts a malicious Helm plugin. This plugin contains a `plugin.yaml` file with a `version` field that includes POSIX dot-dot path separators (e.g., `/../`).
2. The attacker distributes the malicious plugin to potential victims, possibly through public repositories or direct spear phishing.
3. A victim attempts to install or update the Helm plugin using the `helm plugin install` or `helm plugin update` command.
4. Helm parses the `plugin.yaml` file and extracts the `version` field, which contains the path traversal characters.
5. Due to the vulnerability, Helm incorrectly resolves the file path, allowing the plugin's contents to be written outside the intended plugin directory.
6. The malicious plugin overwrites arbitrary files on the user's system based on the path specified in the `version` field.
7. Depending on the files overwritten, the attacker can achieve various malicious objectives, such as gaining persistence, escalating privileges, or executing arbitrary code.
8. The attacker achieves persistence by overwriting system startup scripts or configuration files, allowing the malicious code to run automatically on system reboot.

## Impact

Successful exploitation of this vulnerability allows attackers to overwrite arbitrary files on the victim's system. This can lead to various detrimental outcomes, including data loss, system instability, privilege escalation, and ultimately, complete system compromise. While the specific number of victims is unknown, any user running a vulnerable version of Helm (4.0.0 - 4.1.3) is at risk. The potential impact includes compromising Kubernetes deployments and sensitive data stored on affected systems.

## Recommendation

*   Upgrade Helm to version 4.1.4 or later to remediate CVE-2026-35204, as this version includes a patch that prevents path traversal during plugin installation.
*   Implement a validation step before installing or updating Helm plugins, checking the `plugin.yaml` file for a `version:` field containing POSIX dot-dot path separators. This mitigates the risk described in the workaround section of the advisory.
*   Deploy the Sigma rule "Helm Plugin Install with Path Traversal" to detect attempts to install plugins with malicious `version` fields, using file_event logs.
