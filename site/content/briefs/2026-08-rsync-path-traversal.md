---
title: Path Traversal Vulnerability in rsync make_path() Function
slug: 2026-08-rsync-path-traversal
description: A path traversal vulnerability in rsync versions prior to 3.5.0 allows a malicious sender to perform arbitrary file writes outside the intended destination directory via crafted relative paths.
date: "2026-08-13T15:37:59Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - rsync
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A path traversal vulnerability exists in rsync versions prior to 3.5.0, specifically within the make_path() function during operations using the --relative mode.
    confidence_band: high
cves:
  - id: CVE-2026-53785
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53785
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade rsync to version 3.5.0 or later
      owner: IT Operations
      addresses: CVE-2026-53785
      evidence: NVD vulnerability disclosure
---

A path traversal vulnerability exists in rsync versions prior to 3.5.0, specifically impacting the make_path() function during operations utilizing the --relative mode. The vulnerability arises because the software fails to properly validate that file paths created during a synchronization task remain within the intended destination directory tree. By crafting malicious relative paths containing symlink components, a remote sender can trick the receiver's rsync process into following symlinks that point outside the restricted boundary. This flaw enables an attacker to write files to arbitrary locations on the receiving system's filesystem. This vulnerability represents a significant security risk for automated backup systems or file synchronization services that accept incoming rsync connections from untrusted or compromised sources.

## Impact

Successful exploitation allows a malicious actor to perform unauthorized arbitrary file writes on the receiving host. This can lead to system-wide compromise if an attacker overwrites critical system configuration files, injects malicious binaries into search paths, or alters sensitive data, impacting the integrity and availability of the affected system.

## Recommendation

- Upgrade rsync to version 3.5.0 or later on all systems to remediate the vulnerability associated with CVE-2026-53785.
- Audit existing rsync configuration files to restrict the use of --relative mode where not strictly required for business operations.
- Implement filesystem-level permissions that enforce the principle of least privilege for the user account executing the rsync process, preventing it from writing to sensitive system directories.
