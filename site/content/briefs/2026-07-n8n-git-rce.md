---
title: Race Condition in n8n Git Clone Node Leads to Remote Code Execution
slug: 2026-07-n8n-git-rce
description: A Time-of-Check to Time-of-Use (TOCTOU) race condition exists in the Git node's clone operation in n8n versions prior to 1.123.64, 2.29.8, and 2.30.1. This vulnerability allows authenticated users to bypass path restrictions by swapping a validated directory for a symlink, enabling them to plant a crafted repository in the community node directory. Upon the next restart, n8n loads this as a custom node, leading to arbitrary JavaScript execution on the server, affecting both self-hosted and cloud instances.
date: "2026-07-22T17:56:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - race-condition
  - rce
  - n8n
  - application-security
  - cloud-security
vendors:
  - n8n GmbH
products:
  - n8n < 1.123.64
  - n8n < 2.29.8
  - n8n < 2.30.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allows authenticated users
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: swapping a directory for a symlink after the path is validated but before the clone runs. This lets an attacker plant a crafted repository in the community node directory, which n8n loads as a custom node on the next restart
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: executing arbitrary JavaScript on the server
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-725q-c4vp-q4cg
---

This threat brief details a critical Time-of-Check to Time-of-Use (TOCTOU) race condition affecting n8n, an open-source workflow automation platform, in versions prior to 1.123.64, 2.29.8, and 2.30.1. The vulnerability exists within the Git node's clone operation, which is designed to integrate external code repositories. An authenticated attacker can exploit this race condition by carefully timing a swap between a legitimate directory and a malicious symbolic link (symlink) immediately after n8n performs a path validation check but before the Git clone process completes. This allows the attacker to redirect the cloned repository into n8n's community node directory, effectively planting a crafted, malicious custom node. Upon the next restart of the n8n instance, this malicious custom node is automatically loaded, leading to the execution of arbitrary JavaScript code on the underlying server. This severe vulnerability impacts both self-hosted and cloud deployments of n8n, granting attackers remote code execution capabilities and persistent access to the platform.

## Attack Chain

1. An authenticated attacker identifies a vulnerable n8n instance and initiates a Git clone operation via its Git node functionality.
2. The attacker specifies a target directory for the cloned repository within the n8n environment.
3. The n8n application performs an initial path validation check on the specified directory to ensure it is a legitimate and permissible location.
4. Immediately after n8n's path validation and before the actual Git clone operation fully completes, the attacker exploits a TOCTOU race condition by replacing the originally validated directory with a symbolic link (symlink). This symlink is crafted to point to a sensitive location, such as n8n's community node directory (e.g., `~/.n8n/custom/`).
5. The Git clone operation proceeds, unaware of the symlink swap, and writes the attacker's specially crafted malicious repository into the community node directory via the symlink. This repository is designed to function as a custom n8n node containing arbitrary JavaScript code.
6. Upon the next restart of the n8n instance (either scheduled or triggered by the attacker), the application automatically discovers and loads the newly planted custom node from the community node directory.
7. The malicious JavaScript code embedded within the custom node is executed on the n8n server with the privileges of the n8n process, resulting in remote code execution (RCE).
8. The attacker achieves persistent control over the n8n instance, enabling further compromise of the system, data exfiltration, or lateral movement within the compromised environment.

## Impact

Successful exploitation of this race condition leads to remote code execution (RCE) on the n8n server, allowing an authenticated attacker to execute arbitrary JavaScript code. This can result in complete compromise of the n8n instance, enabling unauthorized access to sensitive data, disruption of critical workflows, or lateral movement within the network. Both self-hosted and cloud environments running vulnerable n8n versions are at risk, making the scope of potential victims broad across various sectors. The attacker gains persistent access as the malicious custom node is loaded automatically upon service restart, posing a significant security threat.

## Recommendation

Update n8n to a patched version (1.123.64, 2.29.8, or 2.30.1 or newer) immediately to address the vulnerability. Enable detailed logging for file system changes, particularly within directories associated with n8n custom nodes (e.g., `~/.n8n/custom/`) to detect unexpected file or symlink creation. Monitor n8n process execution for any anomalous child processes or network connections that deviate from established baselines, indicating potential arbitrary code execution.
