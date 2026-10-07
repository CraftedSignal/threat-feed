---
title: Remote Code Execution in Backstage TechDocs via Malicious MkDocs Configuration
slug: 2026-10-backstage-techdocs-rce
description: An improper input validation vulnerability (CVE-2026-106509) in Backstage plugin-techdocs-node allows authenticated users to achieve arbitrary code execution via crafted mkdocs.yml files.
date: "2026-10-07T16:58:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:backstage:backstage:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - supply-chain
vendors:
  - Backstage
products:
  - plugin-techdocs-node (< 1.15.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A user with write access to a registered repository can include configuration values in mkdocs.yml that cause arbitrary code execution
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: a user with write access to a registered repository can include configuration values in mkdocs.yml that cause arbitrary code execution during the documentation build process.
    confidence_band: high
cves:
  - id: CVE-2026-106509
    cvss: 7.7
references:
  - https://github.com/advisories/GHSA-8w7q-29mw-gf5c
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @backstage/plugin-techdocs-node to 1.15.4 or later.
      owner: IT Operations
      due: 24h
      evidence: Patched in @backstage/plugin-techdocs-node version 1.15.4
  mitigation_plan:
    - priority: immediate
      action: Set techdocs.generator.runIn to 'docker' and restrict repository write access.
      owner: Security Engineering
      addresses: CVE-2026-106509
      evidence: Workarounds suggested in official GHSA advisory
---

Backstage, an open platform for building developer portals, is vulnerable to a remote code execution (RCE) flaw in the `@backstage/plugin-techdocs-node` package. Tracked as CVE-2026-106509, the issue stems from improper validation of configuration values within the `mkdocs.yml` file used by the TechDocs plugin. 

When TechDocs is configured to perform documentation builds locally or within a container environment, an attacker with repository write access can inject malicious configuration directives. These directives are processed during the documentation build stage, leading to the execution of arbitrary commands on the build infrastructure. This vulnerability poses a high risk to organizations that permit documentation builds from untrusted or compromised repository contributors. The vulnerability was remediated in `@backstage/plugin-techdocs-node` version 1.15.4.

## Attack Chain

1. Attacker gains write access to a repository registered in the Backstage catalog.
2. Attacker modifies the `mkdocs.yml` file within the repository to include malicious configuration parameters.
3. The TechDocs plugin triggers a build process for the documentation, either locally or within a container runner.
4. The build process, facilitated by `plugin-techdocs-node`, parses the manipulated `mkdocs.yml` file.
5. The plugin fails to properly sanitize or validate the user-controlled configuration values.
6. The underlying build engine executes the injected commands as part of the MkDocs build process.
7. Attacker achieves remote code execution within the build environment (e.g., the Backstage host or the container instance).

## Impact

Successful exploitation allows an attacker to execute arbitrary code on the infrastructure hosting the TechDocs build service. This can lead to credential theft, lateral movement within the build environment, or exposure of sensitive data processed by the documentation pipeline. Organizations using TechDocs in 'local' build mode are at the highest risk, though containerized deployments may also be compromised depending on the container runtime's isolation capabilities.

## Recommendation

Prioritize the upgrade of `@backstage/plugin-techdocs-node` to version 1.15.4 or later across all Backstage instances to address CVE-2026-106509. As a compensatory control for environments where immediate patching is not possible, modify the `techdocs.generator.runIn` configuration to use 'docker' instead of 'local' to enforce container-level isolation. Furthermore, strictly enforce repository write permissions to ensure only trusted users can modify documentation configurations and trigger builds.
