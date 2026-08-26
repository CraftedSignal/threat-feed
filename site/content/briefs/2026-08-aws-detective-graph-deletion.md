---
title: Defense Evasion via Deletion of Amazon Detective Behavior Graphs
slug: 2026-08-aws-detective-graph-deletion
description: Attackers with high-level IAM permissions may delete Amazon Detective behavior graphs to impair forensic investigations by destroying historical relationship mapping and telemetry analysis data.
date: "2026-08-26T13:55:50Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - defense-evasion
  - forensic-obstruction
vendors:
  - Amazon
products:
  - Amazon Detective
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An attacker with sufficient IAM permissions may delete the Detective graph to impair forensic investigation of a compromise.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/detective/latest/APIReference/API_DeleteGraph.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_detective_graph_deleted.toml
rules:
  - title: Detect AWS Detective Graph Deletion
    description: Detects the successful execution of the DeleteGraph API call in Amazon Detective, which may indicate an attempt to impair forensic investigation capabilities.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule for AWS Detective graph deletion.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific KQL detection logic for DeleteGraph.
  mitigation_plan:
    - priority: medium_term
      action: Implement SCPs to restrict detective:DeleteGraph permissions.
      owner: IT Operations
      addresses: T1562.001
      evidence: Source investigation guide explicitly recommends SCP restrictions.
---

The deletion of an Amazon Detective behavior graph via the DeleteGraph API is a defense evasion technique that targets an organization's forensic capabilities. Amazon Detective consumes logs from AWS CloudTrail, VPC Flow Logs, and Amazon GuardDuty to provide automated security insights and visual relationship mapping. Because the deletion of a behavior graph is an irreversible operation, it effectively destroys the historical analytical context required for post-compromise investigation.

This activity is significant for defenders because it is rarely performed as a routine maintenance task. When observed in production environments without accompanying change management records, the deletion of a Detective graph likely indicates an attempt by an adversary to obstruct security teams, hide their movements, or disrupt the incident response timeline. Security teams must monitor for this API call and correlate it with other environmental changes, such as the disabling of GuardDuty or the modification of logging configurations.

## Attack Chain

1. Attacker gains initial access to an AWS environment through compromised credentials or exploitation of a misconfigured resource.
2. Attacker performs discovery to identify enabled security services and monitoring capabilities, including Amazon Detective.
3. Attacker evaluates existing IAM permissions to determine if they possess the authorization to modify or delete security infrastructure.
4. Attacker executes the `DeleteGraph` API call, resulting in the permanent destruction of the behavior graph and historical data.
5. Attacker proceeds with further malicious objectives, such as data exfiltration or persistent resource deployment, now unhindered by Detective's behavior monitoring.
6. Attacker clears or attempts to minimize trace artifacts while the environment's forensic investigation capabilities are degraded.

## Impact

Successful deletion of an Amazon Detective behavior graph results in the permanent loss of historical security analytics and the inability to use graph theory-based investigation tools for existing incidents. This creates significant blind spots for incident responders who rely on Detective to trace resource interactions and identify the scope of an adversary's activity. The impact is primarily a severe reduction in forensic capability, which complicates incident scoping and increases the time required for threat hunting and remediation.

## Recommendation

Prioritize the following actions to detect and mitigate the unauthorized deletion of security services:
- Implement a detection alert for the `DeleteGraph` action in AWS CloudTrail using the provided Sigma rule.
- Apply Service Control Policies (SCPs) that restrict the `detective:DeleteGraph` permission to a limited set of break-glass or senior administrator identities.
- Audit IAM permissions across all accounts to identify identities with excessive access to security service management APIs.
- Review change management logs when this alert triggers to differentiate between authorized environment decommissioning and malicious activity.
