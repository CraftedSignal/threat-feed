---
title: Splunk Path Traversal Vulnerability Allows Arbitrary File Writes (CVE-2026-20297)
slug: 2026-07-splunk-path-traversal
description: A path traversal vulnerability (CVE-2026-20297) in Splunk Enterprise and Splunk Cloud Platform allows an authenticated user with `edit_local_apps` and `install_apps` capabilities to write files outside the intended application directory during app installation, specifically into the `$SPLUNK_HOME/etc/` directory and its subdirectories, leading to configuration manipulation, persistence, or privilege escalation.
date: "2026-07-15T18:20:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - splunk
  - rce
  - persistence
  - privilege-escalation
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Cloud Platform
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: a user who holds a role that contains the `edit_local_apps` and `install_apps` capabilities could cause a legitimate app installation to write files outside the intended app directory, into `$SPLUNK_HOME/etc/` and its subdirectories.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: a user who holds a role that contains the `edit_local_apps` and `install_apps` capabilities could cause a legitimate app installation to write files outside the intended app directory, into `$SPLUNK_HOME/etc/` and its subdirectories.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: a user who holds a role that contains the `edit_local_apps` and `install_apps` capabilities could cause a legitimate app installation to write files outside the intended app directory, into `$SPLUNK_HOME/etc/` and its subdirectories.
    confidence_band: med
cves:
  - id: CVE-2026-20297
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20297
---

A path traversal vulnerability (CVE-2026-20297) affects Splunk Enterprise versions below 10.4.1, 10.2.5, 10.0.8, 9.4.13, and 9.3.14, and Splunk Cloud Platform versions below 10.5.2605.0, 10.4.2604.6, 10.2.2510.18, and 10.1.2507.24. This critical vulnerability allows an authenticated attacker, possessing roles with `edit_local_apps` and `install_apps` capabilities, to exploit a flaw in the app installation workflow. By crafting a malicious Splunk app, the attacker can leverage path traversal sequences to write files outside the designated application directory. Specifically, files can be written into the `$SPLUNK_HOME/etc/` directory and its subdirectories, which typically store sensitive Splunk configuration and system files. This enables the attacker to manipulate Splunk's core configuration, potentially leading to persistent access, privilege escalation within the Splunk environment, or even remote code execution depending on the affected configuration files and their impact on Splunk's operational mechanisms. This vulnerability poses a significant risk to the integrity and security of Splunk deployments, allowing attackers to subvert expected system behavior from within.

## Attack Chain

1. **Initial Access (Assumed)**: An attacker gains access to a legitimate Splunk user account that has been granted the `edit_local_apps` and `install_apps` capabilities.
2. **Malicious App Creation**: The attacker crafts a Splunk app package, typically a `.spl` file, incorporating files with path traversal sequences (e.g., `../`, `..\`) in their filenames or internal paths. These sequences are designed to redirect file writes outside the app's intended installation directory.
3. **App Installation Initiation**: The authenticated attacker uploads and initiates the installation of the specially crafted Splunk app through the Splunk Web UI or via the Splunk REST API.
4. **Path Traversal Exploitation**: During the app installation process, the vulnerable Splunk component fails to properly sanitize the file paths within the app package, allowing the path traversal sequences to resolve to locations outside the standard app directory structure.
5. **Arbitrary File Write**: Splunk writes the malicious files to arbitrary locations, specifically targeting critical configuration directories such as `$SPLUNK_HOME/etc/` and its subdirectories.
6. **Configuration Modification**: The attacker successfully overwrites or injects malicious configuration into sensitive Splunk files (e.g., `server.conf`, `web.conf`, `inputs.conf`, `authorize.conf`).
7. **Persistence / Privilege Escalation**: The modified configurations are then loaded by Splunk, granting the attacker persistent access, elevated privileges within the Splunk environment, or triggering malicious command execution based on the altered settings.

## Impact

A successful exploitation of CVE-2026-20297 allows an authenticated attacker to inject arbitrary files into critical Splunk configuration directories such as `$SPLUNK_HOME/etc/`. This can lead to various severe consequences, including the modification of core Splunk settings, enabling persistence mechanisms by altering startup scripts or scheduled tasks, and privilege escalation within the Splunk environment. For instance, modifying authentication configurations or command execution settings could grant the attacker broader control over the Splunk instance or underlying host. In scenarios where the attacker can introduce and execute malicious scripts or binaries via compromised configuration, remote code execution becomes a tangible threat, impacting data integrity, confidentiality, and the overall availability of Splunk services. While no specific victim count is provided in the advisory, organizations using affected Splunk Enterprise or Cloud Platform versions are at risk if their environments allow users with the necessary `edit_local_apps` and `install_apps` capabilities.

## Recommendation

* Patch CVE-2026-20297 by upgrading Splunk Enterprise to versions 10.4.1, 10.2.5, 10.0.8, 9.4.13, 9.3.14, or higher, and Splunk Cloud Platform to versions 10.5.2605.0, 10.4.2604.6, 10.2.2510.18, 10.1.2507.24, or higher, immediately.
* Review and restrict Splunk user roles, ensuring that only trusted administrators have the `edit_local_apps` and `install_apps` capabilities.
* Implement file integrity monitoring on critical Splunk directories, particularly `$SPLUNK_HOME/etc/` and its subdirectories, to detect unauthorized or suspicious file modifications.
