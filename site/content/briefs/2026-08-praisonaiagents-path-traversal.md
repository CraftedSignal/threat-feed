---
title: Arbitrary File Write Vulnerability in PraisonAI Agents
slug: 2026-08-praisonaiagents-path-traversal
description: The FileMemory component in praisonaiagents versions 1.6.52 and earlier fails to sanitize user-supplied identifiers, enabling path traversal attacks that result in arbitrary JSON file creation or overwriting.
date: "2026-08-25T16:02:43Z"
lastmod: "2026-08-25T16:03:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - python
  - ssrf
  - praisonaiagents
  - cloud-security
vendors:
  - PraisonAI
products:
  - praisonaiagents
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows for arbitrary file write which can be leveraged to write system-level scripts or configuration files.
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The validator's dependency on initial resolution allows for the injection of malicious URLs that pivot into the internal network.
    confidence_band: med
cves:
  - id: CVE-2026-55527
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-gxmw-5f7x-6g22
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55527
  - https://github.com/advisories/GHSA-vg6p-v9vm-6fgj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55524
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade praisonaiagents to 1.6.58
      owner: IT Operations
      due: 24h
      evidence: Source advisory states patch availability
  mitigation_plan:
    - priority: immediate
      action: Restrict process filesystem permissions to non-critical directories
      owner: IT Operations
      addresses: CVE-2026-55527
      evidence: Standard hardening for file write vulnerabilities
updates:
  - at: "2026-08-25T16:03:03Z"
    level: L2
    summary: added coverage for praisonaiagents
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-vg6p-v9vm-6fgj
---

PraisonAI Agents (up to version 1.6.52) contains a critical path traversal vulnerability within the `FileMemory` component, located in `praisonaiagents/memory/file_memory.py`. The `__init__` method accepts a `user_id` parameter that is directly joined to a base directory without validation or normalization. An attacker able to influence this parameter - through direct API calls, agent configurations, or submitted job manifests - can inject path traversal sequences such as `../`. This allows the application to write files to arbitrary locations on the host filesystem that the process has permissions to access. The vulnerability persists in the `main` branch and is distinct from previously reported issues, posing a significant risk for file manipulation, system configuration corruption, or denial-of-service attacks.

## Attack Chain

1. Attacker crafts a malicious input containing a traversal payload (e.g., `user_id: "../../etc/cron.d/malicious"`) within an agent job submission.
2. The `agents_generator.py` service parses the user-submitted `agent_yaml` and extracts the memory configuration.
3. The `Agent` constructor is invoked, passing the attacker-controlled `user_id` to the `FileMemory` class.
4. The `FileMemory.__init__` method concatenates the malicious `user_id` with the `base_path` using Python's `pathlib` join operator.
5. The application calls `mkdir` on the constructed path, creating the directory structure on the filesystem if it does not exist.
6. The `FileMemory` instance performs file operations (e.g., `add_short_term`), resulting in the creation of JSON files (e.g., `short_term.json`) at the attacker-specified target location.
7. Successful execution results in unauthorized file writes, potentially allowing an attacker to overwrite sensitive system configurations or package files.

## Impact

Successful exploitation allows attackers to perform arbitrary file writes on the host system running the PraisonAI service. Impacts include Denial of Service by disk filling, overwriting critical application configuration files to alter runtime behavior, or attempting to leverage the file write to achieve persistence or code execution by overwriting startup scripts, cron tasks, or system files if the service process runs with sufficient privileges. This is particularly critical in multi-tenant environments where one user could overwrite the memory data or configurations belonging to another user.

## Recommendation

- Upgrade `praisonaiagents` to version 1.6.58 or later to incorporate necessary sanitization patches.
- Implement strict input validation on `user_id` parameters in any application code interacting with `FileMemory` to ensure they only contain alphanumeric characters, underscores, and hyphens.
- Apply the principle of least privilege to the service account executing PraisonAI agents to minimize the impact of arbitrary file writes on system-level directories.
- If immediate patching is not possible, implement a proxy or validation layer to scan `agent_yaml` inputs for directory traversal patterns before processing.
