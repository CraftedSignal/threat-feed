---
title: Zarf Path Traversal Vulnerability via Malicious Package Metadata.Name
slug: 2026-04-15-zarf-path-traversal
description: Zarf is vulnerable to path traversal due to insufficient sanitization of the Metadata.Name field in package manifests when using the `zarf package inspect sbom` or `zarf package inspect documentation` commands, potentially leading to arbitrary file write.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - zarf
  - path-traversal
  - arbitrary-file-write
  - package-inspection
  - linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-pj97-4p9w-gx3q
rules:
  - title: Detect Zarf Package Inspection with Path Traversal
    description: Detects zarf package inspect commands with Metadata.Name containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Zarf Arbitrary File Write
    description: Detects file writes by zarf to sensitive directories, indicating potential exploitation.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Zarf Usage
    description: Detects execution of the zarf binary, which may indicate legitimate usage or the start of malicious activity.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Zarf, a tool for air-gapped deployments, is susceptible to a path traversal vulnerability (CVE-2026-40090) affecting versions prior to v0.74.2. The vulnerability stems from inadequate sanitization of the `Metadata.Name` field within Zarf package manifests. When a user employs the `zarf package inspect sbom` or `zarf package inspect documentation` commands on an untrusted package, the tool constructs output file paths by concatenating a user-controlled output directory with the package's `Metadata.Name` field. A malicious actor can craft a Zarf package with a manipulated `Metadata.Name` containing path traversal sequences (e.g., `../../`), enabling arbitrary file write capabilities within the permissions of the user running the `inspect` command. This vulnerability allows attackers to write to locations they control, potentially leading to privilege escalation or system compromise.

## Attack Chain

1.  Attacker crafts a malicious Zarf package.
2.  The attacker modifies the `zarf.yaml` manifest within the package to include a `Metadata.Name` field containing path traversal sequences (e.g., `../../../../tmp/evil`).
3.  The attacker repacks the Zarf package, recalculating checksums if necessary.
4.  The attacker distributes the malicious Zarf package.
5.  A victim user downloads the malicious Zarf package.
6.  The victim executes `zarf package inspect sbom --output-dir /tmp <malicious-package.tar.zst>` or `zarf package inspect documentation --output-dir /tmp <malicious-package.tar.zst>`.
7.  Zarf extracts the `Metadata.Name` from the `zarf.yaml` file.
8.  Zarf constructs an output path by joining the user-specified output directory (/tmp) with the malicious `Metadata.Name` (`../../../../tmp/evil`), resulting in `/tmp/../../../../tmp/evil`. The tool attempts to write the SBOM or documentation data to this path, resulting in writing the file to `/tmp/evil`. This allows attackers to write files such as SSH authorized keys, cron jobs, or shell profiles.

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files to the file system, limited by the permissions of the user running the `zarf package inspect` command. This can lead to several critical consequences: privilege escalation by writing to authorized_keys files, arbitrary code execution by writing cron jobs, or persistent compromise by writing to shell profiles. This vulnerability affects users running the `zarf package inspect sbom` or `zarf package inspect documentation` command on untrusted packages. The affected packages are go/github.com/zarf-dev/zarf versions >= 0.23.0 and < 0.74.2.

## Recommendation

*   Upgrade Zarf to version v0.74.2 or later to patch CVE-2026-40090.
*   Avoid inspecting unsigned Zarf packages as a workaround until the upgrade is complete, as mentioned in the advisory.
*   Deploy the Sigma rule "Detect Zarf Package Inspection with Path Traversal" to identify attempts to exploit this vulnerability via command-line arguments.
*   Monitor file creation events in sensitive directories (e.g., `/home/$USER/.ssh`, `/etc/cron.d`) for files created by the zarf binary using the "Detect Zarf Arbitrary File Write" Sigma rule.
