---
title: Authenticated Code Execution Vulnerability in n8n Git Node
slug: 2026-07-n8n-authenticated-code-execution
description: An authenticated n8n user with workflow creation and execution rights can achieve arbitrary code execution on the n8n host by staging a crafted local Git repository within the Git node, causing Git to run malicious hooks as the n8n process user.
date: "2026-07-22T22:10:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-execution
  - vulnerability
  - n8n
  - authenticated-rce
vendors:
  - n8n GmbH
products:
  - n8n (< 1.123.67)
  - n8n (>= 2.32.0, < 2.32.1)
  - n8n (>= 2.0.0-rc.0, < 2.31.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: an attacker could cause `git` to run hooks, executing arbitrary commands as the n8n process user.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rcv6-pvrj-4xcg
---

A high-severity authenticated code execution vulnerability has been discovered in the n8n automation platform's Git node. Authenticated n8n users with permissions to create and execute workflows can exploit this flaw to execute arbitrary commands on the underlying n8n host. The vulnerability, present in versions prior to 1.123.67, 2.31.5, and 2.32.1, leverages the default security settings of the Git node. By crafting a malicious local Git repository, an attacker can trick Git into running arbitrary hooks, thereby achieving code execution as the n8n process user. This impacts both self-hosted and cloud instances where authenticated users have workflow creation and execution capabilities, posing a significant risk of system compromise and data breach.

## Attack Chain

1. An authenticated attacker gains access to an n8n instance with permissions to create and execute workflows.
2. The attacker creates a new workflow and integrates the Git node into it.
3. The attacker stages a specially crafted local Git repository. This repository contains malicious Git hooks (e.g., `pre-receive`, `post-update`, `post-checkout`) designed to execute arbitrary commands.
4. The attacker configures the Git node in the workflow to interact with this crafted local repository.
5. When the workflow containing the malicious Git node is executed, Git, under its default security settings, processes the crafted repository.
6. Git triggers the malicious hooks embedded in the repository.
7. The commands within the Git hooks are executed with the privileges of the n8n process user on the underlying host system.
8. The attacker achieves arbitrary code execution, potentially leading to full system compromise or data exfiltration.

## Impact

Successful exploitation of this vulnerability grants an authenticated attacker arbitrary code execution capabilities on the n8n host system. This means an attacker can run any command as the user account under which the n8n process operates. This could lead to full compromise of the n8n server, including access to sensitive data, configuration files, credentials, and potentially lateral movement to other systems within the environment. Both self-hosted n8n instances and cloud deployments are at risk if authenticated users can create and execute workflows using the Git node. The direct consequence is a severe breach of confidentiality, integrity, and availability of the n8n platform and potentially connected systems.

## Recommendation

* Upgrade n8n instances immediately to patched versions 1.123.67, 2.31.5, 2.32.1, or later as specified in the source.
* If immediate upgrade is not possible, restrict n8n instance access to fully trusted users only to mitigate the risk of authenticated attackers.
* Disable the Git node by adding `n8n-nodes-base.git` to the `NODES_EXCLUDE` environment variable if the Git node functionality is not essential for operations.
* Restrict network egress from the n8n instance to limit the impact of potential arbitrary code execution.
