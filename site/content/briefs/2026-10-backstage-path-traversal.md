---
title: Improper Repository Path Validation in Backstage Scaffolder Backend Module
slug: 2026-10-backstage-path-traversal
description: An authenticated user can exploit improper path validation in the Backstage plugin-scaffolder-backend-module-confluence-to-markdown (CVE-2026-106560) to write files outside the designated task workspace.
date: "2026-10-07T22:54:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:backstage:plugin-scaffolder-backend-module-confluence-to-markdown:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - path-traversal
  - backend-security
vendors:
  - Backstage
products:
  - plugin-scaffolder-backend-module-confluence-to-markdown (< 0.3.25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user who can execute an affected template and control its repository file location may cause generated content to be written outside the task workspace.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An authenticated user... may cause generated content to be written outside the task workspace, within locations writable by the Backstage backend process.
    confidence_band: med
cves:
  - id: CVE-2026-106560
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-2cmg-v53w-8xfp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106560
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @backstage/plugin-scaffolder-backend-module-confluence-to-markdown to 0.3.25
      owner: IT Operations
      due: 24h
      evidence: Patched in @backstage/plugin-scaffolder-backend-module-confluence-to-markdown version 0.3.25
  mitigation_plan:
    - priority: immediate
      action: Restrict template execution to trusted users or disable the affected action
      owner: Security Engineering
      addresses: CVE-2026-106560
      evidence: Remove or disable the affected action until the patched package is deployed.
---

Backstage, an open platform for building developer portals, contains a path traversal vulnerability in the Scaffolder backend module `@backstage/plugin-scaffolder-backend-module-confluence-to-markdown`. The vulnerability, tracked as CVE-2026-106560, stems from improper validation of repository file location inputs provided by users. An authenticated attacker who can execute affected templates and control repository path parameters can escape the restricted task workspace. By manipulating these paths, the attacker can force the Backstage backend process to write files into any directory on the server that the backend process has permissions to access. This can lead to arbitrary file creation or overwriting of configuration files, potentially facilitating further system compromise or persistent unauthorized access. The issue was addressed in version 0.3.25 of the affected module.

## Impact

Successful exploitation allows authenticated users to bypass directory restrictions within the Scaffolder environment. This vulnerability impacts organizations hosting Backstage instances that utilize the affected Confluence-to-Markdown Scaffolder action. An attacker could overwrite critical application files or drop web shells if the backend process runs with elevated privileges, leading to full application compromise or unauthorized data modification.

## Recommendation

- Upgrade the `@backstage/plugin-scaffolder-backend-module-confluence-to-markdown` package to version 0.3.25 or later.
- Implement access control restrictions to limit which users can execute templates that utilize the Confluence-to-Markdown action until the update is deployed.
- Audit logs for the Backstage backend process to identify suspicious template execution attempts involving unusual file paths (e.g., paths containing '..').
