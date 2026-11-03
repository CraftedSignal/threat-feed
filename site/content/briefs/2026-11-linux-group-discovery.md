---
brief_id: brief-2026-11-03-linux-group-discovery
event_id: brief-2026-11-03-linux-group-discovery
revision: 1
activity_at: "2026-11-03T08:44:20Z"
title: Linux Local Group Enumeration via Standard Utilities
slug: 2026-11-linux-group-discovery
description: This detection-focused brief covers the monitoring of common Linux utilities used for local group and privilege enumeration.
date: "2026-11-03T08:44:20Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - discovery
  - linux
  - reconnaissance
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    subtechnique_id: T1069.001
    subtechnique_name: Local Groups
    evidence: Adversaries may read files such as /etc/group and /etc/gshadow, or use tools like getent and groups to identify group memberships and privilege assignments on a compromised system.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_local_groups.yml
rules:
  - title: Local Groups Discovery Attempt - Linux
    description: Detects attempts to enumerate local groups and group membership via common Linux utilities and sensitive file access.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify accounts executing group enumeration commands across multiple hosts
      technique_id: T1069.001
      data_needed:
        - Process creation logs with user context
      priority: low
      confidence: medium
      disposition: convert_to_detection
      evidence: Adversaries may read files such as /etc/group and /etc/gshadow, or use tools like getent and groups to identify group memberships.
---

Adversaries often perform local group enumeration to identify target accounts for privilege escalation or lateral movement. Threat actors use common Linux system utilities, such as 'getent', 'groups', and various file readers, to query '/etc/group' or '/etc/gshadow' files to gain visibility into system account permissions and administrative group membership.

## Impact

The impact of group enumeration is primarily reconnaissance. Successful discovery allows an attacker to identify high-privilege users or security groups, facilitating subsequent phases of an attack such as credential harvesting or privilege escalation.

## Recommendation

Deploy the provided Sigma detection rule to monitor process executions involving sensitive group files or enumeration tools. Because these utilities are heavily used for legitimate system administration, focus analysis on deviations from established administrative baselines or account behavior.
