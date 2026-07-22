---
title: n8n Edit Image Node Format Injection Allows Arbitrary File Write
slug: 2026-07-n8n-arbitrary-file-write
description: An authenticated user can exploit a format injection vulnerability in the n8n Edit Image node to write arbitrary files outside the node's working directory within the n8n instance, potentially leading to remote code execution or other significant impact.
date: "2026-07-22T22:15:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-write
  - vulnerability
  - rce
  - n8n
vendors:
  - n8n GmbH
products:
  - n8n (npm/n8n < 1.123.67)
  - n8n (npm/n8n >= 2.32.0, < 2.32.1)
  - n8n (npm/n8n >= 2.0.0-rc.0, < 2.31.5)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: An authenticated user able to run workflows could use this to write arbitrary files in the n8n instance, potentially leading to remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated user able to run workflows could use this to write arbitrary files in the n8n instance, potentially leading to remote code execution.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-xmc9-4f2h-jf9c
---

A high-severity format injection vulnerability, identified as GHSA-xmc9-4f2h-jf9c, exists in the n8n automation platform's Edit Image node, affecting versions prior to 1.123.67, 2.32.0 up to 2.32.1, and 2.0.0-rc.0 up to 2.31.5. This vulnerability allows an authenticated user, with the ability to create or execute workflows, to achieve arbitrary file write on the n8n instance. The flaw stems from the Edit Image node passing user-controlled output format parameters directly to the underlying image processing library without proper validation, enabling directory traversal and placement of malicious files in sensitive locations. Successful exploitation can lead to system compromise, including remote code execution or persistence within the n8n environment. Defenders should prioritize patching to the remediated versions immediately.

## Attack Chain

1. An authenticated attacker, with privileges to create or modify n8n workflows, logs into the vulnerable n8n instance.
2. The attacker creates a new workflow or modifies an existing one to incorporate the "Edit Image" node.
3. Within the "Edit Image" node's configuration, the attacker crafts a malicious value for the "Format" parameter, embedding directory traversal sequences (e.g., `../../`) and a controlled file name (e.g., `../../path/to/webshell.php`).
4. When the workflow is executed, the n8n application passes the unvalidated, maliciously crafted format string directly to the underlying image processing library.
5. The image processing library, acting on the attacker-supplied path, writes the image output data to an arbitrary location on the server's filesystem, escaping the intended working directory.
6. The attacker leverages this arbitrary file write to place a malicious file, such as a web shell, a modified application configuration file, or a backdoor script, into a sensitive directory accessible by the n8n application or web server.
7. By subsequently interacting with the written malicious file (e.g., sending an HTTP request to a web shell) or by triggering n8n to load the modified configuration, the attacker achieves remote code execution.
8. This exploitation grants the attacker persistent access or full control over the compromised n8n instance and potentially the underlying server.

## Impact

The successful exploitation of this vulnerability by an authenticated user leads to arbitrary file write capabilities on the n8n instance. This means an attacker can place any file type, including web shells, modified configuration files, or other malicious executables, into sensitive directories on the server. The direct consequence is potential remote code execution, allowing the attacker to fully compromise the n8n application system and gain control over the underlying server. While no specific victim counts are provided, all n8n instances running vulnerable versions are at risk from any authenticated user, regardless of their intended privilege level.

## Recommendation

* Upgrade n8n instances immediately to patched versions 1.123.67, 2.31.5, or 2.32.1 or later to remediate the vulnerability.
* If immediate upgrade is not feasible, restrict n8n instance access to fully trusted users only as a temporary measure.
* As a short-term mitigation, disable the Edit Image node by adding `n8n-nodes-base.editImage` to the `NODES_EXCLUDE` environment variable.
