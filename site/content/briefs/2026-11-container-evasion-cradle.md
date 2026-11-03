---
brief_id: brief-2026-11-03-container-evasion-cradle
event_id: brief-2026-11-03-container-evasion-cradle
revision: 1
activity_at: "2026-11-03T21:45:55Z"
title: Container Defense Evasion via Rapid File Lifecycle
slug: 2026-11-container-evasion-cradle
description: Attackers are observed using a rapid sequence of ingress tool transfer, execution, and deletion within container environments to minimize on-disk artifacts and evade forensic review.
date: "2026-11-03T21:45:55Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - container-security
  - defense-evasion
  - ingress-tool-transfer
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    subtechnique_id: T1070.004
    subtechnique_name: File Deletion
    evidence: This detection flags a rapid sequence inside a container where a file is written to a common transient or user-writable location, executed, then deleted shortly after.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: Attackers often use a shell to pull a payload with common transfer utilities into /tmp or shared memory.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Attackers often use a shell to pull a payload with common transfer utilities into /tmp or shared memory.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/defense_evasion_file_creation_execution_deletion_cradle.toml
  - https://flare.io/learn/resources/blog/teampcp-cloud-native-ransomware
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify rapid lifecycle file events in sensitive container directories
      technique_id: T1070.004
      data_needed:
        - Container file system audit logs
        - Container process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This detection flags a rapid sequence inside a container where a file is written to a common transient or user-writable location, executed, then deleted shortly after.
  mitigation_plan:
    - priority: medium
      action: Enforce read-only root filesystems and restricted shell access in production container images.
      owner: DevOps
      addresses: Defense Evasion (T1070)
      evidence: Harden by enforcing least privilege and runtime controls such as read-only root filesystems, no shell or download tools in production images.
---

This threat involves a container-based defense evasion technique where an attacker downloads a payload into a transient directory (e.g., /tmp, /dev/shm) using standard utilities like curl or wget. The file is immediately executed and then deleted, a pattern designed to bypass security monitoring and frustrate forensic analysis. This activity is often indicative of post-exploitation phases such as credential theft or lateral movement.

## Attack Chain
1. Access is gained to a containerized environment.
2. A shell is opened or an existing process is hijacked.
3. The attacker initiates a download of a malicious payload using utilities such as curl, wget, or rsync.
4. The payload is written to a user-writable path such as /tmp, /dev/shm, or /proc/*/fd/.
5. The downloaded file is executed within the container.
6. The file is deleted shortly after execution to remove the indicator of compromise.

## Recommendation
- Deploy detection rules that correlate file creation, process execution, and file deletion events within containers.
- Implement and enforce read-only root filesystems for production containers to prevent the creation of unauthorized binaries in temporary directories.
- Monitor container egress traffic to identify and block connections to unauthorized download hosts or C2 infrastructure.
- Use runtime security tooling to identify and isolate containers exhibiting rapid file lifecycle patterns in sensitive paths.
- Revoke and rotate any secrets, service account tokens, or API keys associated with a container identified in a suspicious file lifecycle event.
