---
title: Improper Link Resolution Vulnerability in Serena
slug: 2026-10-serena-path-traversal
description: Serena versions prior to 2.0.0 contain a path traversal vulnerability in Project.is_path_in_project() that allows attackers to access sensitive files outside the project root via malicious symlinks.
date: "2026-10-13T14:39:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:serena:serena:*:*:*:*:*:*:*:*
vendors:
  - Serena
products:
  - Serena (< 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The Project.is_path_in_project() function performs lexical normalization without resolving symbolic links, allowing an attacker to commit malicious symlinks within a repository to read or overwrite sensitive files.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The vulnerability allows attackers to overwrite files such as SSH keys or cloud credentials.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The vulnerability allows attackers to access files outside the project root.
    confidence_band: high
cves:
  - id: CVE-2026-109965
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109965
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Serena to 2.0.0 or later
      owner: IT Operations
      due: 48h
      evidence: Serena before 2.0.0 contains an improper link resolution vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade Serena to version 2.0.0
      owner: IT Operations
      addresses: CVE-2026-109965
      evidence: Serena before 2.0.0 contains an improper link resolution vulnerability
---

Serena versions before 2.0.0 are affected by an improper link resolution vulnerability identified as CVE-2026-109965. The vulnerability resides in the Project.is_path_in_project() function, which performs lexical path normalization without resolving symbolic links. An attacker can exploit this by committing malicious symlinks within a repository. When the Serena software processes these files using tools such as read_file or create_text_file, the lack of symlink resolution bypasses the intended project root boundary. This allows an unauthorized actor to perform arbitrary file reads or overwrites on sensitive system files, including SSH keys, cloud provider credentials, or configuration files, depending on the service account's permissions. This vulnerability represents a significant risk for environments where Serena processes untrusted or third-party repositories.

## Impact

Successful exploitation allows attackers to gain unauthorized access to sensitive files on the underlying host. Depending on the environment, this could lead to full credential theft, persistence through the overwriting of authorized_keys files, or remote code execution by modifying sensitive configuration files. This vulnerability affects all environments deploying Serena versions prior to 2.0.0.

## Recommendation

- Upgrade the Serena installation to version 2.0.0 or later immediately to address the underlying symlink resolution failure.
- Implement strict file system auditing on servers hosting Serena to detect unexpected file read or write activity originating from the application process.
- Review repository content for suspicious symbolic link creation if the environment has processed untrusted or external codebases.
