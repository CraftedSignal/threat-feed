---
brief_id: brief-2026-11-03-esxi-account-persistence
event_id: brief-2026-11-03-esxi-account-persistence
revision: 1
activity_at: "2026-11-03T15:31:26Z"
title: 'VMware ESXi: Unauthorized local account creation detection'
slug: 2026-11-esxi-account-persistence
description: This brief details the detection of local account creation on VMware ESXi hosts, a technique frequently used by threat actors to establish persistence on hypervisors.
date: "2026-11-03T15:31:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Content matches source investigation guides and detection logic.
tags:
  - persistence
  - ransomware
  - vmware
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.001
    subtechnique_name: Local Account
    evidence: The rule detects creation of a local ESXi account, a separate login that remains after the session that created it, as a first step toward persistent login.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/vsphere/persistence_esxi_account_created.toml
  - https://lolesxi-project.github.io/LOLESXi/#
  - https://blogs.vmware.com/security/2022/10/esxi-targeting-ransomware-tactics-and-techniques-part-2.html
  - https://detect.fyi/vmware-esxi-logging-detection-opportunities-4fb56411ec21
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify and validate all local account creation events on ESXi hosts
      technique_id: T1136.001
      data_needed:
        - VMware ESXi hostd.log
        - VMware ESXi shell.log
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The source documentation notes that hostd logs account creation and shell logs record esxcli system account add.
  mitigation_plan:
    - priority: medium
      action: Remove unauthorized accounts via esxcli system account remove --id <name>
      owner: IT Operations
      addresses: T1136.001
      evidence: Source investigation guide provides removal command for unauthorized accounts.
---

Local account creation on VMware ESXi hosts serves as a persistence mechanism that survives session termination. Unauthorized accounts, often created via the Host Client or `esxcli` system commands, are a known precursor to hypervisor-level control, particularly in ransomware campaigns. Organizations should audit account creation events against expected administrative activity.

## Impact
Unauthorized local accounts provide persistent access to the ESXi hypervisor, enabling potential lateral movement, data exfiltration, or deployment of ransomware by threat actors who have gained initial management access.

## Recommendation
- Deploy log collection for VMware ESXi using the Elastic vSphere integration to ensure visibility into `hostd` and shell execution logs.
- Establish a baseline of authorized administrative accounts for all ESXi hosts.
- Monitor for the creation of local accounts (`esxcli system account add`) or logs indicating an account was created on a host.
- Investigate any account creation not tied to documented onboarding or break-glass procedures by identifying the user who performed the action and checking for subsequent assignment of administrative roles.
