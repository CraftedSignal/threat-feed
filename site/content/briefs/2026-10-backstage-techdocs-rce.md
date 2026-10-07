---
title: Remote Code Execution in Backstage TechDocs Plugin
slug: 2026-10-backstage-techdocs-rce
description: Authenticated users can execute arbitrary commands on Backstage TechDocs build hosts by injecting malicious values into the markdown_extensions configuration of mkdocs.yml files.
date: "2026-10-07T22:54:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:backstage:techdocs_plugin:*:*:*:*:*:node:*:*
tags:
  - rce
  - vulnerability
  - supply-chain
vendors:
  - Backstage
products:
  - '@backstage/plugin-techdocs-node (< 1.15.4)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated user who can register catalog entities can provide a crafted mkdocs.yml causing arbitrary OS command execution on the TechDocs build host.
    confidence_band: high
cves:
  - id: CVE-2026-106510
    cvss: 7.7
references:
  - https://github.com/advisories/GHSA-4488-j8vj-vqqv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106510
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @backstage/plugin-techdocs-node to 1.15.4
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates version 1.15.4 or later
  mitigation_plan:
    - priority: immediate
      action: 'Switch to techdocs.builder: external'
      owner: IT Operations
      addresses: CVE-2026-106510
      evidence: Source documentation for mitigation
---

Backstage, a common developer portal framework, contains a critical vulnerability (CVE-2026-106510) in the `@backstage/plugin-techdocs-node` package. The flaw stems from insufficient validation of `markdown_extensions` defined within `mkdocs.yml` configuration files. When an authenticated user with permissions to register catalog entities submits a crafted `mkdocs.yml` file, the TechDocs build process fails to sanitize input, leading to command injection on the underlying host. This vulnerability allows attackers to gain code execution context on the build server. Organizations utilizing the standard TechDocs builder are at highest risk, as it shares the application environment with the build process. Defending against this requires upgrading the plugin or implementing isolation strategies to limit the impact of untrusted builds.

## Attack Chain

1. The attacker gains authenticated access to the Backstage instance.
2. The attacker identifies an entity or creates a new one with TechDocs annotations enabled.
3. The attacker crafts a malicious `mkdocs.yml` file containing a payload within the `markdown_extensions` configuration field.
4. The attacker registers or updates the catalog entity in Backstage with the malicious configuration.
5. Backstage triggers the TechDocs build process for the updated entity.
6. The `plugin-techdocs-node` package processes the configuration, resulting in arbitrary OS command execution during the build phase.
7. The command runs with the privileges of the Backstage application/build service, potentially allowing for further internal network traversal or data exfiltration.

## Impact

Successful exploitation allows for full command execution on the build host. This can lead to the compromise of environment variables, source code access, and lateral movement within the infrastructure supporting the developer portal. If left unpatched, any authenticated user with catalog registration rights can gain this foothold.

## Recommendation

Prioritized actions for security teams:
- Patch `@backstage/plugin-techdocs-node` to version 1.15.4 or later immediately.
- Audit existing catalog entities for suspicious or non-standard `markdown_extensions` values defined in `mkdocs.yml` files.
- Implement the `techdocs.builder: external` configuration to isolate TechDocs build processes within containers, mitigating the risk of direct host compromise.
- Review and restrict permissions for catalog entity registration to trusted users only to minimize the pool of potential attackers.
