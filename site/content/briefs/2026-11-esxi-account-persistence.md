---
brief_id: brief-2026-11-03-esxi-account-persistence
event_id: brief-2026-11-03-esxi-account-persistence
revision: 3
activity_at: "2026-11-06T15:07:50Z"
revision_history:
  - revision: 2
    at: "2026-11-05T08:54:12Z"
    checksum: sha256:616506924292566e50fd801ddcb5ed3c178187409daa599ce7a2de5af3c87aa1
    summary: added coverage for ESXi
    changed_fields:
      - action_plan
      - iocs
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - tags
      - threat_actor
      - ttps
      - updates
    source_urls:
      - https://www.ransomware.live/group/lockbit5
  - revision: 3
    at: "2026-11-06T15:07:50Z"
    checksum: sha256:17a1b63a626666e7293fc29cb2ba28a0e9876f14f1eed255920fdc79e8dca917
    summary: exploited:true
    changed_fields:
      - claim_state
      - exploitation_evidence
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://securelist.com/virtualization-security-esxi-and-proxmox-ransomware-cases/121819/
title: 'VMware ESXi: Unauthorized local account creation detection'
slug: 2026-11-esxi-account-persistence
description: This brief details the detection of local account creation on VMware ESXi hosts, a technique frequently used by threat actors to establish persistence on hypervisors.
date: "2026-11-03T15:31:26Z"
lastmod: "2026-11-06T15:07:08Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
actors:
  - LockBit
  - BITWISE SPIDER
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://securelist.com/virtualization-security-esxi-and-proxmox-ransomware-cases/121819/
  observed_at: "2026-11-06T10:00:12Z"
  confidence: high
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
  - extortion
  - lockbit
  - esxi
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
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: The group utilizes cross-platform ransomware payloads capable of encrypting Windows, Linux, and VMware ESXi environments.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/vsphere/persistence_esxi_account_created.toml
  - https://lolesxi-project.github.io/LOLESXi/#
  - https://blogs.vmware.com/security/2022/10/esxi-targeting-ransomware-tactics-and-techniques-part-2.html
  - https://detect.fyi/vmware-esxi-logging-detection-opportunities-4fb56411ec21
  - https://www.ransomware.live/group/lockbit5
  - https://securelist.com/virtualization-security-esxi-and-proxmox-ransomware-cases/121819/
iocs:
  - type: hash_md5
    value: 2513d6678b476a432af2e84fff485b44
  - type: hash_md5
    value: 274e5ff2aa33e7ec980700e617eb2214
  - type: hash_md5
    value: 2908589ca1a1f5d98c7f71563a3abac6
  - type: hash_md5
    value: 48b0a4505a96a640300e43e2af712276
  - type: hash_md5
    value: 5e1f61b9c1c27cad3b7a81c804ac7b86
  - type: hash_md5
    value: 8f718979876dd1050ce4f729d69e0072
  - type: hash_md5
    value: 95daa771a28eaed76eb01e1e8f403f7c
  - type: hash_md5
    value: a1539b21e5d6849a3e0cf87a4dc70335
  - type: hash_md5
    value: bf4443f6dbbdee8816aa9a1098374326
  - type: hash_md5
    value: c462c6b02b35df2910689947c5090fae
  - type: hash_md5
    value: ca93d47bcc55e2e1bd4a679afc8e2e25
  - type: hash_md5
    value: e47032b3d1b9cbbcf77741d5d260004d
  - type: hash_md5
    value: eb0c1d82187ec3fe980eed2419875e4b
ioc_counts:
  hash_md5: 13
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block the provided MD5 hashes across all EDR/AV solutions.
      owner: SOC
      due: 24h
      evidence: IOC list provided in source.
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
    - lead: Hunt for VM power-off sequences in ESXi environments.
      technique_id: T1486
      data_needed:
        - VMware ESXi host logs (e.g., /var/log/hostd.log)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: LockBit 5.0 ESXi VM Power-Off Sequence Preceding VMDK Encryption
  mitigation_plan:
    - priority: medium
      action: Remove unauthorized accounts via esxcli system account remove --id <name>
      owner: IT Operations
      addresses: T1136.001
      evidence: Source investigation guide provides removal command for unauthorized accounts.
    - priority: immediate
      action: Apply least-privilege access to VMware management interfaces and ensure secure offline backups.
      owner: IT Operations
      addresses: ESXi virtualization environment
      evidence: Observed targeting of VMware ESXi infrastructure.
updates:
  - at: "2026-11-05T08:52:20Z"
    level: L2
    summary: added coverage for ESXi
    sources:
      - ransomware-live
    source_urls:
      - https://www.ransomware.live/group/lockbit5
  - at: "2026-11-06T15:07:08Z"
    level: L3
    summary: exploited:true
    sources:
      - securelist
    source_urls:
      - https://securelist.com/virtualization-security-esxi-and-proxmox-ransomware-cases/121819/
---

Local account creation on VMware ESXi hosts serves as a persistence mechanism that survives session termination. Unauthorized accounts, often created via the Host Client or `esxcli` system commands, are a known precursor to hypervisor-level control, particularly in ransomware campaigns. Organizations should audit account creation events against expected administrative activity.

## Impact
Unauthorized local accounts provide persistent access to the ESXi hypervisor, enabling potential lateral movement, data exfiltration, or deployment of ransomware by threat actors who have gained initial management access.

## Recommendation
- Deploy log collection for VMware ESXi using the Elastic vSphere integration to ensure visibility into `hostd` and shell execution logs.
- Establish a baseline of authorized administrative accounts for all ESXi hosts.
- Monitor for the creation of local accounts (`esxcli system account add`) or logs indicating an account was created on a host.
- Investigate any account creation not tied to documented onboarding or break-glass procedures by identifying the user who performed the action and checking for subsequent assignment of administrative roles.
