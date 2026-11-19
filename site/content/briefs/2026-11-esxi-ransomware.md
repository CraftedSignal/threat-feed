---
brief_id: brief-2026-11-17-esxi-ransomware
event_id: brief-2026-11-17-esxi-ransomware
revision: 2
activity_at: "2026-11-19T16:15:02Z"
revision_history:
  - revision: 2
    at: "2026-11-19T16:15:02Z"
    checksum: sha256:dce8308155388f4dbc5def8158777395c765bf50ebb236a0c86826ffc3b4749f
    summary: KEV CVE-2024-38812; KEV CVE-2024-40711; KEV CVE-2021-21972; KEV CVE-2021-21985; KEV CVE-2021-22005; KEV CVE-2023-34048
    changed_fields:
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: 'BlackNevas: Destructive attacks on virtualized environments'
slug: 2026-11-esxi-ransomware
description: The BlackNevas threat group performed a destructive campaign against a virtualization estate by leveraging legitimate administrative interfaces to compromise ESXi hosts, virtual machines, and backup infrastructure without exploiting hypervisor-layer vulnerabilities.
date: "2026-11-17T09:00:18Z"
lastmod: "2026-11-19T16:14:17Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - BlackNevas
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-11-17T09:00:18Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source material is a high-confidence incident analysis.
tags:
  - ransomware
  - virtualization
  - infrastructure
  - destructive
vendors:
  - Veeam
  - VMware
products:
  - Backup and Recovery
  - ESXi
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.002
    subtechnique_name: Domain Accounts
    evidence: Every action taken against ESXi was executed through legitimate VMware management interfaces.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: This article examines why the hypervisor layer remains difficult to monitor, what common access paths adversaries use to reach it, and how they establish persistence on the management plane.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: We also look into the architecture of ESXi encryptors, the deliberate destruction of backup infrastructure, and the log sources that enable post-incident reconstruction.
    confidence_band: high
cves:
  - id: CVE-2021-21972
    kev: true
    kev_status: "true"
  - id: CVE-2021-21974
    kev_status: "false"
  - id: CVE-2021-21985
    kev: true
    kev_status: "true"
  - id: CVE-2021-22005
    kev: true
    kev_status: "true"
  - id: CVE-2023-34048
    kev: true
    kev_status: "true"
  - id: CVE-2024-37085
    kev: true
    kev_status: "true"
  - id: CVE-2024-38812
    kev: true
    kev_status: "true"
  - id: CVE-2024-40711
    kev: true
    kev_status: "true"
references:
  - https://securelist.com/esxi-ransomware/121959/
  - https://cveawg.mitre.org/api/cve/CVE-2021-21972
  - https://cveawg.mitre.org/api/cve/CVE-2021-22005
  - https://cveawg.mitre.org/api/cve/CVE-2021-21974
  - https://cveawg.mitre.org/api/cve/CVE-2021-21985
  - https://cveawg.mitre.org/api/cve/CVE-2023-34048
  - https://cveawg.mitre.org/api/cve/CVE-2024-37085
  - https://cveawg.mitre.org/api/cve/CVE-2024-38812
  - https://cveawg.mitre.org/api/cve/CVE-2024-40711
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit access logs for vCenter and ESXi for non-standard administrative logins.
      owner: SOC
      due: 24h
      evidence: Every action taken against ESXi was executed through legitimate VMware management interfaces.
    - action: Ensure all virtualization infrastructure is patched against listed CVEs.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability exploitation is one of the most probable entry routes.
  hunt_leads:
    - lead: Search vCenter and ESXi management logs for unexpected configuration changes or modification of VMDK files originating from administrative accounts.
      technique_id: T1078
      data_needed:
        - VMware vCenter Server Audit Logs
        - ESXi Host Shell Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: In the engagement examined here, host-native and management-plane telemetry central to the incident timeline reconstruction.
updates:
  - at: "2026-11-19T16:14:17Z"
    level: L3
    summary: KEV CVE-2024-38812; KEV CVE-2024-40711; KEV CVE-2021-21972; KEV CVE-2021-21985; KEV CVE-2021-22005; KEV CVE-2023-34048
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The Kaspersky Global Emergency Response Team investigated a 10-day destructive campaign by the BlackNevas group, which targeted an organization's virtualization estate. The attackers compromised four ESXi hosts, their associated virtual machines, vCenter Server Appliances, and all linked backup infrastructure. Notably, the threat actor did not exploit hypervisor-layer memory corruption or guest-to-host escapes; instead, they relied on legitimate VMware management interfaces to execute destructive operations. This incident highlights the risks of credential reuse, Active Directory integration abuse, and the insufficient visibility into the hypervisor management plane.

## Attack Chain

1. Initial access established through one of the four common routes (vulnerability exploitation, credential reuse, AD integration abuse, or backup infrastructure compromise).
2. Gained unauthorized access to the centralized virtualization management plane (vCenter Server).
3. Established persistence within the management infrastructure.
4. Utilized legitimate management interfaces to gain control over ESXi hosts.
5. Interacted directly with the ESXi datastores to perform unauthorized actions on virtual machine disks (VMDK).
6. Destroyed backup infrastructure to prevent recovery efforts.
7. Executed ransomware encryptors to render all virtualized workloads unavailable.

## Impact

Full destruction of the organization's virtualized estate, including ESXi hosts, all hosted virtual machines, vCenter Server instances, and backup infrastructure, over a 10-day period.

## Recommendation

- Audit and restrict access to vCenter Server and ESXi administrative interfaces; enforce multi-factor authentication (MFA) for all management plane access.
- Monitor management-plane logs for unusual administrative activity, especially access from non-standard source IPs or unexpected user accounts.
- Review Active Directory integration settings for ESXi hosts to prevent unauthorized group modifications (CVE-2024-37085).
- Patch all virtualization-related vulnerabilities, including CVE-2021-21972, CVE-2021-22005, CVE-2021-21974, CVE-2021-21985, CVE-2023-34048, CVE-2024-37085, CVE-2024-38812, and CVE-2024-40711, on affected VMware and Veeam systems.
- Enhance visibility by aggregating infrastructure-level telemetry, as traditional EDR agents inside guest VMs cannot detect hypervisor-level disk modifications.
