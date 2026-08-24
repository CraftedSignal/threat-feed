---
title: Modification of ESXi Security and Encryption Enforcement Settings
slug: 2026-08-esxi-encryption-modification
description: Detection of unauthorized modifications to VMware ESXi security settings, such as disabling secure boot or executable verification, which are techniques used by actors like Black Basta to compromise hypervisor integrity.
date: "2026-08-24T15:46:16Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - VMware
products:
  - ESXi
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_encryption_settings_modified.yml
rules:
  - title: Detect ESXi Security Settings Modification
    description: Detects the disabling of critical encryption enforcement settings on an ESXi host, such as secure boot or executable verification requirements, which may indicate an attempt to weaken hypervisor integrity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to SIEM and validate log ingestion from ESXi hosts.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific detection logic for ESXi configuration tampering.
  mitigation_plan:
    - priority: immediate
      action: Restrict shell access on ESXi hosts and enforce strict change management for hypervisor configuration changes.
      owner: IT Operations
      addresses: T1685
      evidence: Source identifies setting modification as a critical integrity risk.
---

This alert addresses the modification of critical security and encryption enforcement settings on VMware ESXi hosts. Attackers, including those associated with Black Basta ransomware, have been observed targeting the configuration of hypervisors to weaken their security posture. By disabling features such as secure boot or executable verification requirements, threat actors can bypass integrity checks to execute unauthorized or malicious code directly within the hypervisor environment. This behavior is typically identified through the monitoring of ESXi system logs where configuration commands are audited. Defenders should prioritize alerting on these modifications as they are often a precursor to further post-compromise activity, including payload deployment and persistent control over virtual infrastructure.

## Impact

Successful modification of ESXi security settings grants an attacker the ability to bypass hypervisor protections, potentially leading to unauthorized execution of malicious binaries, persistence within the virtualization layer, and increased risk of widespread ransomware deployment across virtualized guest environments. This technique directly undermines the isolation guarantees of the hypervisor.

## Recommendation

* Ingest VMware ESXi syslog data into the SIEM and ensure the appropriate Technology Add-on for VMware ESXi is configured to extract relevant command-line fields.
* Monitor for the specific command-line arguments identified in the detection logic below to identify attempts to lower the security threshold of ESXi hosts.
* Investigate any alert triggered by these rules with high priority, as legitimate administrative changes to security settings on production ESXi hosts should be infrequent and managed through change control.
