---
brief_id: brief-2026-11-20-azure-snapshot-abuse
event_id: brief-2026-11-20-azure-snapshot-abuse
revision: 1
activity_at: "2026-11-20T13:59:45Z"
title: 'Azure: Unauthorized Compute Snapshot Creation (T1578.001)'
slug: 2026-11-azure-snapshot-abuse
description: Adversaries can abuse the creation of Azure managed-disk snapshots to stage sensitive data for exfiltration by sharing or copying the snapshot to an attacker-controlled scope, bypassing direct interaction with the source VM.
date: "2026-11-20T13:59:45Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection logic requires environment-specific baseline tuning.
tags:
  - cloud
  - azure
  - defense-evasion
  - data-exfiltration
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    subtechnique_id: T1578.001
    subtechnique_name: Create Snapshot
    evidence: Adversaries create snapshots of disks to stage data for exfiltration, copying or sharing the snapshot to an attacker-controlled scope without reading the source VM directly.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1578.001/T1578.001.md
  - https://www.cyngular.com/blog/beyond-the-backup-the-hidden-dangers-of-azure-snapshot-exfiltration
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/defense_evasion_azure_compute_snapshot_created_by_unusual_identity.toml
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Cloud Security
  hunt_leads:
    - lead: Search Azure Activity Logs for "Microsoft.Compute/snapshots/write" operations, filtering for unusual Source ASNs or principals that do not match expected backup/administrative activity.
      technique_id: T1578.001
      data_needed:
        - Azure Activity Logs (event.action, user.name, source.as.organization.name)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries create snapshots of disks to stage data for exfiltration... excluding known cloud-provider egress networks.
  mitigation_plan:
    - priority: short_term
      action: Baseline and exclude known backup/disaster-recovery service accounts from alert monitoring.
      owner: Cloud Security
      addresses: Azure Compute Snapshots
      evidence: Backup, disaster-recovery, and image-bake automation create snapshots routinely; baseline known automation identities and add exceptions.
---

## Overview

Adversaries create snapshots of Azure managed disks as a defense evasion technique to stage data for exfiltration. By creating a snapshot, the attacker can move, share, or export the disk data to an attacker-controlled subscription without triggering alerts associated with direct VM access or data-in-use monitoring. Monitoring for "Microsoft.Compute/snapshots/write" operations, particularly those originating from unexpected Autonomous System Numbers (ASN), can help identify potential unauthorized staging activity.

## Impact

Unauthorized creation of disk snapshots facilitates data theft and exfiltration by allowing attackers to access point-in-time copies of virtual machine storage. This technique enables attackers to move data to their own infrastructure for offline analysis or data extraction.

## Recommendation

- Inventory all principals authorized to create snapshots within your Azure environment.
- Implement monitoring for the "Microsoft.Compute/snapshots/write" activity in Azure Activity Logs.
- Alert on snapshot creation activities originating from IP addresses or ASNs that are not part of your organization's known network range or typical cloud egress providers.
- Monitor for follow-on actions such as SAS export ("Microsoft.Compute/snapshots/beginGetAccess/action"), CopySnapshot, or unexpected share operations in the same time window as snapshot creation.
- Tighten least-privilege access to the "Microsoft.Compute/snapshots/*" resource provider and revoke SAS access if unauthorized snapshots are identified.
