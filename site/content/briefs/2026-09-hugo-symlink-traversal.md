---
title: 'CVE-2026-100690: Symlink Traversal Vulnerability in Hugo Node.js Integration'
slug: 2026-09-hugo-symlink-traversal
description: Hugo versions 0.161.0 through 0.165.0 contain a directory traversal vulnerability where the Node.js sandbox fails to resolve symbolic links correctly, allowing unauthorized disclosure of sensitive files during the build process.
date: "2026-09-26T15:12:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hugo:hugo:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - static-site-generator
vendors:
  - Hugo
products:
  - Hugo (0.161.0-0.165.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: An attacker who can contribute content to a Hugo project (for example via a pull request) can commit a symlink.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Hugo versions from v0.161.0 through v0.165.0 run Node.js tools (css.PostCSS, css.TailwindCSS, js.Babel).
    confidence_band: high
cves:
  - id: CVE-2026-100690
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100690
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Hugo build environment to version v0.166.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Fixed in v0.166.0, which scans allowed paths and fails the build when a symbolic link resolves outside them.
  mitigation_plan:
    - priority: immediate
      action: Implement build-time scanners to detect and block symbolic links referencing system directories in project repositories.
      owner: Security Operations
      addresses: CVE-2026-100690
      evidence: projects that do not invoke Node.js tools are unaffected
---

Hugo versions 0.161.0 through v0.165.0 are affected by a directory traversal vulnerability that stems from improper validation of symbolic links within the integrated Node.js sandbox. Hugo utilizes the Node.js permission model to restrict file system access for integrated tools such as PostCSS, TailwindCSS, and Babel. However, because the permission model validates lexical paths rather than resolved paths, Hugo fails to detect when symbolic links point outside of the project directory or configured mounts. An attacker with the ability to influence project content, such as through a malicious pull request or compromised source repository, can commit a symbolic link that resolves to a sensitive system file (e.g., /etc/passwd). When the project is built, the integrated Node.js tools follow this symlink, potentially disclosing the content of the target file in the resulting site output. This vulnerability is fixed in version v0.166.0, which enforces strict resolution of all paths to ensure they remain within allowed boundaries.

## Impact

Successful exploitation allows for the disclosure of arbitrary files readable by the user account running the Hugo build process. This is particularly critical in CI/CD environments where build processes may have broader read permissions or access to sensitive build-time secrets and environment files. The number of impacted projects depends on the use of Node.js-based Hugo features (PostCSS, TailwindCSS, Babel) and the presence of external contributor access.

## Recommendation

Prioritize the upgrade of all Hugo instances to version v0.166.0 or later to address the symlink resolution logic. For organizations using Hugo in automated pipelines, implement strict file system auditing to detect non-project-relative symbolic links in source repositories prior to the build phase.
