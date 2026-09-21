---
title: Detection of Bulk Virtual Machine Termination on VMware ESXi
slug: 2026-09-esxi-bulk-vm-termination
description: This brief details the detection of malicious bulk virtual machine termination on VMware ESXi hosts using command-line utilities, a tactic frequently observed during ransomware staging or deliberate service disruption.
date: "2026-09-21T19:09:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - hypervisor
  - impact
  - esxi
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1529
    technique_name: System Shutdown/Reboot
    evidence: The following analytic detects when all virtual machines on an ESXi host are abruptly terminated.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: which may indicate malicious activity such as a deliberate denial-of-service.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_bulk_vm_termination.yml
  - https://www.securityweek.com/microsoft-says-ransomware-gangs-exploiting-just-patched-vmware-esxi-flaw/
rules:
  - title: Detect Bulk Virtual Machine Termination on ESXi
    description: Detects mass termination of virtual machines on an ESXi host using pkill or esxcli, which may indicate ransomware activity.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1529
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule for bulk VM termination on all ESXi hosts.
      owner: Detection Engineering
      due: 48h
      evidence: This detection monitors for the mass termination of virtual machines on VMware ESXi hosts.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to ESXi command-line interfaces to only authorized administrative accounts and perform regular audits of system logs.
      owner: IT Operations
      addresses: T1529
      evidence: Source documentation identifies this as a post-compromise activity.
---

Monitoring of VMware ESXi infrastructure has identified a significant threat vector involving the mass termination of running virtual machines. Threat actors, including groups associated with Black Basta ransomware, use native ESXi management utilities to force-stop VMs, effectively creating a denial-of-service condition or preparing for data exfiltration and encryption. This activity is characterized by the use of 'pkill' or 'esxcli vm process kill' commands against all hosted instances. Because these commands perform administrative functions that are destructive in nature when applied in bulk, monitoring syslog streams for specific command-line strings allows for high-fidelity detection of post-compromise activity on hypervisors.

## Impact

Successful bulk VM termination leads to the immediate loss of availability for all workloads hosted on the affected ESXi server. In ransomware scenarios, this is often a precursor to unauthorized encryption, causing widespread business operational outages, loss of data integrity, and significant recovery costs for impacted organizations.

## Recommendation

Detection engineering teams should focus on ingesting VMware ESXi syslog data and applying behavioral analysis to identify unauthorized administrative commands.

- Configure ESXi hosts to forward syslog events to the central SIEM, ensuring the Splunk Technology Add-on for VMware ESXi is utilized for proper CIM-compliant parsing.
- Implement the detection logic below to alert on the execution of 'pkill' and 'esxcli vm process kill' commands that target virtual machine processes.
- Investigate any occurrences of the command-line patterns identified in the analytic to determine if they originate from authorized maintenance scripts or unauthorized actor activity.
