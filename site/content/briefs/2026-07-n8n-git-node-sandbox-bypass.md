---
title: n8n Git Node Operations Bypass Sandbox Path Restriction
slug: 2026-07-n8n-git-node-sandbox-bypass
description: An authenticated n8n user can exploit a path restriction bypass vulnerability within the Git node's fetch, pull, or push-tags operations to access arbitrary local Git repositories and their contents, potentially leading to sensitive data exposure.
date: "2026-07-22T22:10:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - sandbox-bypass
  - n8n
  - data-exfiltration
  - workflow-automation
vendors:
  - n8n GmbH
products:
  - 'n8n (Vulnerable versions: < 1.123.67)'
  - 'n8n (Vulnerable versions: >= 2.0.0-rc.0, < 2.31.5)'
  - 'n8n (Vulnerable versions: >= 2.32.0, < 2.32.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated n8n users with workflow create/execute rights could use the Git node's fetch, pull, or push-tags operations to bypass the repository-path containment checks
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: bypass the repository-path containment checks
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: pull an arbitrary local git repository into the workspace and subsequently read its files and history
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gf29-4f56-r2jf
---

A high-severity vulnerability has been identified in the n8n workflow automation platform that allows authenticated users to bypass intended sandbox path restrictions. This vulnerability affects n8n versions prior to 1.123.67, versions from 2.0.0-rc.0 to below 2.31.5, and version 2.32.0. The flaw resides within the Git node's `fetch`, `pull`, and `push-tags` operations, which can be manipulated by an attacker to point an allowlisted remote configuration value at a local path outside the designated sandbox. This allows the attacker to pull arbitrary local Git repositories into the n8n workspace, subsequently exposing their files and history. This issue is critical for organizations using n8n, as it could lead to unauthorized access and exfiltration of sensitive source code or other local system data from the host running the n8n instance.

## Attack Chain

1. An attacker gains authenticated access to an n8n instance with workflow creation and execution rights.
2. The attacker crafts a new n8n workflow or modifies an existing one.
3. Within the workflow, the attacker adds or configures a Git node to perform `fetch`, `pull`, or `push-tags` operations.
4. The attacker manipulates the Git node's configuration by setting an allowlisted remote configuration value to a local file path that lies outside n8n's intended sandbox.
5. The attacker executes the maliciously configured n8n workflow.
6. During execution, the Git node, using the manipulated remote configuration, bypasses the internal repository-path containment checks.
7. The n8n instance pulls an arbitrary local Git repository from the host system into its workspace, effectively making its contents accessible within the n8n environment.
8. The attacker can then access and read the files and historical data contained within the exposed local Git repository, leading to data collection.

## Impact

The successful exploitation of this vulnerability by an authenticated n8n user can lead to the unauthorized disclosure of sensitive information. Attackers can access and read the contents, including source code and historical data, of any local Git repository present on the n8n host system that they manage to pull into the workspace. This could expose intellectual property, credentials, internal system configurations, and other proprietary data. While no specific victim count or sectors are mentioned, any organization using affected versions of n8n is at risk of significant data exfiltration if the n8n host contains valuable Git repositories.

## Recommendation

* Upgrade n8n instances to versions 1.123.67, 2.31.5, 2.32.1, or later immediately as outlined in the `Patches` section of the advisory.
* Restrict n8n instance access to fully trusted users only to mitigate risks while awaiting upgrades, as specified in the `Workarounds` section.
* Disable the Git node by adding `n8n-nodes-base.git` to the `NODES_EXCLUDE` environment variable if immediate upgrade is not possible, as detailed in the `Workarounds` section.
