---
title: Path Traversal Vulnerability in Backstage Bitbucket Scaffolder Modules
slug: 2026-10-backstage-path-traversal
description: Authenticated users can exploit improper filesystem validation in Backstage Bitbucket scaffolder plugins to achieve unauthorized file access, modification, or deletion outside the intended working directory via CVE-2026-106486.
date: "2026-10-07T22:54:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - backstage
  - vulnerability
  - cve-2026-106486
vendors:
  - Backstage
products:
  - plugin-scaffolder-backend-module-bitbucket-cloud (< 0.3.10)
  - plugin-scaffolder-backend-module-bitbucket-server (< 0.2.25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user who can execute an eligible template and influence an allowed Bitbucket repository could affect filesystem paths outside the expected working area.
    confidence_band: high
cves:
  - id: CVE-2026-106486
    cvss: 8.5
references:
  - https://github.com/advisories/GHSA-g8rx-f7m5-7794
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-106486
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevOps
  immediate_actions:
    - action: Upgrade affected Backstage modules to patched versions
      owner: IT Operations
      due: 48h
      evidence: Patches provided in GHSA-g8rx-f7m5-7794
  mitigation_plan:
    - priority: immediate
      action: Restrict template execution to trusted users and sanitize repository parameters
      owner: DevOps
      addresses: CVE-2026-106486
      evidence: Workaround documented in GHSA-g8rx-f7m5-7794
---

The Backstage Scaffolder backend modules for Bitbucket Cloud and Bitbucket Server contain an improper filesystem validation vulnerability, tracked as CVE-2026-106486. This flaw exists within the scaffolder actions responsible for interacting with Bitbucket repositories. An authenticated user who has the privileges to execute templates and the ability to influence the targeted Bitbucket repository parameter can supply malicious input to traverse the filesystem on the backend host. By manipulating these inputs, an attacker may escape the expected working directory, potentially reading sensitive configuration files, modifying application code, or deleting arbitrary files. This vulnerability poses a significant risk to backend integrity and confidentiality, particularly in environments where untrusted users have template creation or execution access.

## Impact

Successful exploitation allows an authenticated attacker to perform unauthorized file operations on the host running the Backstage backend. This can result in the compromise of backend confidentiality (sensitive file exfiltration), integrity (malicious code injection), or availability (system file deletion). The scope of impact is limited by the permissions of the process running the Backstage backend service.

## Recommendation

- Upgrade `@backstage/plugin-scaffolder-backend-module-bitbucket-cloud` to version 0.3.10 or later.
- Upgrade `@backstage/plugin-scaffolder-backend-module-bitbucket-server` to version 0.2.25 or later.
- Apply administrative restrictions on Scaffolder template execution, limiting them to trusted users only.
- Audit existing Scaffolder templates to identify and restrict actions that accept user-controlled target repository inputs until patching is complete.
