---
title: n8n Arbitrary File Read via Git Node (CVE-2026-44790)
slug: 2026-05-n8n-file-read
description: An authenticated user with workflow creation or modification permissions can inject CLI flags into the Git node's Push operation, leading to arbitrary file read on the n8n server; patched in versions 1.123.43, 2.20.7, and 2.22.1, and tracked as CVE-2026-44790.
date: "2026-05-14T16:23:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - arbitrary file read
  - n8n
  - git node
  - CVE-2026-44790
vendors:
  - n8n GmbH
products:
  - n8n (< 1.123.43)
  - n8n (>= 2.21.0, < 2.22.1)
  - n8n (>= 2.0.0-rc.0, < 2.20.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-57g9-58c2-xjg3
rules:
  - title: Detect n8n Git Node CLI Injection (CVE-2026-44790)
    description: Detects CVE-2026-44790 exploitation — CLI injection attempts in n8n Git node operations by monitoring process execution with suspicious Git commands.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect n8n Git Node File Read via Command Injection (CVE-2026-44790)
    description: Detects CVE-2026-44790 exploitation — Monitors process executions with git commands containing arguments for reading arbitrary files, potentially indicating command injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-44790, exists within the n8n workflow automation platform. The vulnerability resides in the Git node's Push operation, where an authenticated user with permissions to create or modify workflows can inject arbitrary CLI flags. This injection allows the attacker to read arbitrary files from the n8n server's file system. Successful exploitation can lead to complete compromise of the n8n instance, including access to sensitive data stored on the server, such as credentials, API keys, and internal configuration files. Patches have been released in n8n versions 1.123.43, 2.20.7, and 2.22.1 to address this vulnerability.

## Attack Chain

1. An attacker gains authenticated access to an n8n instance.
2. The attacker obtains permissions to create or modify workflows within n8n.
3. The attacker creates or modifies a workflow to include the Git node.
4. Within the Git node's configuration, specifically the Push operation, the attacker injects malicious CLI flags. These flags are crafted to read arbitrary files from the server's file system (e.g., using `git --help`).
5. The workflow is executed, and the Git node attempts to perform the Push operation with the injected flags.
6. Due to the flag injection, the Git command executes with the attacker-supplied arguments.
7. The attacker retrieves the contents of the targeted file, which may contain sensitive information.
8. The attacker leverages the stolen information to further compromise the n8n instance or connected systems.

## Impact

Successful exploitation of CVE-2026-44790 allows an attacker to read arbitrary files from the n8n server. This can expose sensitive information such as API keys, credentials, configuration files, and other internal data. A successful attack could lead to full compromise of the n8n instance and potentially impact connected systems and data. The severity of the impact is critical due to the potential for complete system takeover and sensitive data exposure.

## Recommendation

*   Upgrade n8n to version 1.123.43, 2.20.7, 2.22.1, or later to patch CVE-2026-44790 as mentioned in the advisory.
*   Limit workflow creation and editing permissions to only fully trusted users as a short-term workaround.
*   Deploy the Sigma rule `Detect n8n Git Node CLI Injection` to identify potential exploitation attempts by monitoring process execution with suspicious Git commands.
*   Monitor n8n application logs for Git node operations involving unusual command-line arguments, focusing on commands that attempt to read files outside the intended Git repository.
