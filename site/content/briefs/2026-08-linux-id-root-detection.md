---
title: Detection of Root-Level Execution of the 'id' Command on Linux
slug: 2026-08-linux-id-root-detection
description: This brief addresses the detection of the 'id' command executed by the root user on Linux systems, a behavior frequently utilized by attackers for situational awareness during post-exploitation and privilege escalation verification.
date: "2026-08-07T15:16:32Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - linux
  - post-exploitation
  - discovery
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: Attackers commonly run id during post-exploitation to confirm they have achieved root-level privileges after a privilege escalation attempt.
    confidence_band: high
rules:
  - title: Detect Linux Root Execution of id
    description: Detects the execution of the id command by the root user, which may indicate an attacker confirming successful privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon for Linux process creation logging
      owner: IT Operations
      due: 7d
      evidence: Required for visibility into command execution.
  hunt_leads:
    - lead: Search for non-standard parent processes spawning id as root
      technique_id: T1033
      data_needed:
        - ParentProcessName
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Unexpected parent processes may indicate manual attacker interaction.
---

The 'id' command is a standard Linux utility used to display user and group information. While its usage is benign in many administrative contexts, it is commonly leveraged by threat actors during post-exploitation to confirm that a privilege escalation attempt has successfully granted them root-level access. Detecting this command when executed under the 'root' context provides security teams with visibility into potential malicious discovery activities. This activity is significant as it indicates an attacker is actively profiling their environment or confirming superuser status, which often precedes further malicious actions such as exfiltration, system destruction, or the establishment of persistent unauthorized access. Defenders should tune detections to account for legitimate administrative tasks or automated maintenance scripts that may perform this check.

## Impact

Successful exploitation where an attacker confirms root privileges typically indicates an advanced stage of a breach. If left unmonitored, compromised systems with root-level access permit attackers to move laterally across the network, modify critical system configuration files, install persistent backdoors, or exfiltrate sensitive data. 

## Recommendation

* Deploy the Sigma rule below to monitor for 'id' execution by the root user.
* Ingest Sysmon for Linux Event ID 1 (process creation) logs into your SIEM, ensuring process names and command lines are captured.
* Establish a baseline of known-good administrative users and automated service accounts that legitimately invoke 'id' as root to tune out false positives.
* Integrate process lineage data (parent-child process relationships) to differentiate between legitimate service management and anomalous execution triggered by shells or unauthorized binaries.
