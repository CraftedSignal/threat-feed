---
title: N8n Git Node Race Condition Allows Authenticated RCE (CVE-2026-65598)
slug: 2026-07-n8n-git-node-rce
description: A Time-of-Check to Time-of-Use (TOCTOU) race condition in n8n's Git node allows an authenticated user to achieve remote code execution (RCE) by swapping a directory with a symlink after path validation but before cloning, leading to the loading of a crafted malicious custom node upon server restart.
date: "2026-07-22T18:04:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - race-condition
  - rce
  - n8n
  - cloud
  - web-application
vendors:
  - n8n GmbH
products:
  - n8n (npm/n8n) < 1.123.64
  - n8n (npm/n8n) >= 2.30.0, < 2.30.1
  - n8n (npm/n8n) >= 2.0.0-rc.0, < 2.29.8
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: since nodes execute JavaScript, this yields arbitrary code execution on the server.
    confidence_band: high
cves:
  - id: CVE-2026-65598
references:
  - https://github.com/advisories/GHSA-g3r5-9h93-4j2c
---

A high-severity Time-of-Check to Time-of-Use (TOCTOU) race condition, identified as CVE-2026-65598, has been discovered in the Git node functionality of n8n, an open-source workflow automation platform. This vulnerability allows authenticated users to bypass path restrictions during a `git clone` operation. By exploiting the brief window between a directory path's validation and the actual clone execution, an attacker can replace the intended target directory with a symbolic link pointing to the community node directory. This enables the attacker to plant a crafted, malicious repository directly into n8n's custom node directory. Upon the subsequent restart of the n8n server, this malicious repository is loaded as a custom node, granting the attacker arbitrary JavaScript code execution on the underlying server. Both self-hosted and cloud instances of n8n are affected if authenticated users can create and run workflows using the Git node.

## Attack Chain

1. An authenticated user gains initial access to the n8n instance and creates a workflow containing a Git node.
2. The attacker configures the Git node to clone a controlled repository, triggering the application's internal path validation logic for the target directory.
3. During the time-of-check (path validation) and time-of-use (actual `git clone` execution) window, the attacker races to replace the validated target directory with a symbolic link.
4. The symbolic link is crafted to point to the n8n `community node directory`, a location where custom nodes are loaded.
5. The `git clone` operation then proceeds, writing the contents of the attacker-controlled malicious repository into the `community node directory` via the symlink.
6. Upon the next restart of the n8n server process, the newly planted malicious repository is loaded and registered as a custom node.
7. Since n8n executes JavaScript code within custom nodes, the attacker achieves arbitrary code execution on the server.
8. The final objective is likely full compromise of the n8n server, potentially leading to data exfiltration, further lateral movement, or service disruption.

## Impact

Successful exploitation of CVE-2026-65598 results in arbitrary code execution (RCE) on the n8n server. This allows an authenticated attacker to take full control of the underlying host system, impacting both self-hosted and cloud instances of n8n. The attacker can execute any command with the privileges of the n8n service, potentially leading to sensitive data exposure, unauthorized modification of workflows or data, or using the compromised server as a pivot point for further attacks within the organization's network. The extent of damage is critical, as it undermines the integrity and confidentiality of the n8n platform and any integrated systems.

## Recommendation

* Upgrade n8n instances immediately to a patched version once available to remediate CVE-2026-65598.
* If immediate upgrade is not possible, restrict n8n instance access to fully trusted users only to mitigate risks related to authenticated exploitation.
* As a temporary measure, disable the Git node functionality by adding `n8n-nodes-base.git` to the `NODES_EXCLUDE` environment variable within your n8n environment.
* Restrict network egress from the n8n instance to prevent connections to arbitrary or attacker-controlled git repositories, reducing the attack surface.
