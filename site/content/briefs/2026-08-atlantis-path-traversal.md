---
title: Path Traversal in Atlantis Workspace Configuration
slug: 2026-08-atlantis-path-traversal
description: Atlantis versions 0.19.8 through 0.44.9 are vulnerable to path traversal (CVE-2026-64679) allowing unauthorized directory creation or deletion outside the intended workspace root.
date: "2026-08-22T01:17:31Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Atlantis
products:
  - Atlantis (0.19.8 to 0.44.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A user who can cause Atlantis to process a crafted workspace value, for example through repository-level atlantis.yaml configuration accepted by the server or an authenticated /api/plan request, may cause filesystem operations to occur outside the intended workspace boundary.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1006
    technique_name: File System Logical Access
    evidence: A crafted workspace value containing path traversal segments could cause Atlantis to resolve workspace paths outside the intended per-pull workspace directory.
    confidence_band: high
cves:
  - id: CVE-2026-64679
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-26w5-6g95-gj28
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64679
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Atlantis to 0.45.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-64679 remediation
  mitigation_plan:
    - priority: immediate
      action: Enforce least privilege on Atlantis process user
      owner: IT Operations
      addresses: CVE-2026-64679
      evidence: Source documentation of out-of-bounds filesystem operations
---

Atlantis versions 0.19.8 through 0.44.9 contain a path traversal vulnerability in its workspace handling mechanism. The application fails to properly sanitize the `workspace` value provided in repository-level `atlantis.yaml` configuration files or through authenticated API requests. By injecting path traversal sequences (e.g., `../../`), an attacker can cause the Atlantis process to resolve workspace paths outside of the designated `~/.atlantis/repos/` directory.

When Atlantis performs workspace setup, it executes filesystem operations such as `os.RemoveAll` and `os.MkdirAll` on the resolved path before delegating to Terraform. Because these operations are executed with the permissions of the Atlantis process user, an authenticated user or an attacker capable of submitting a PR with a malicious `atlantis.yaml` can trigger unintended directory creation, deletion, or modification on the host system or within mounted container volumes. The issue is addressed in Atlantis version 0.45.0.

## Impact

Successful exploitation allows unauthorized manipulation of the filesystem within the context of the Atlantis process. This can lead to the deletion of critical local data, unauthorized creation of directories, or the reuse of arbitrary paths during Terraform execution. While containerization may mitigate host-wide impacts, persistent volumes and internal Atlantis data paths remain exposed. This vulnerability poses significant integrity and denial-of-service risks to organizations relying on Atlantis for Infrastructure as Code automation.

## Recommendation

- Upgrade Atlantis to version 0.45.0 or later immediately to resolve CVE-2026-64679.
- Audit repository-level `atlantis.yaml` files for any suspicious `workspace` parameter values containing directory traversal sequences.
- Restrict the permissions of the user account running the Atlantis service to the minimum required for its operation, ensuring it cannot modify sensitive system directories.
- Implement monitoring for unexpected directory deletion or creation events occurring within the application's working directories.
