---
title: ESXi Bulk VM Termination Detection
slug: 2024-01-03-esxi-bulk-vm-termination
description: Detection of abrupt virtual machine termination on ESXi hosts, potentially indicating denial-of-service, ransomware staging, or destruction of critical workloads.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - vmware
  - virtual_machine
  - ransomware
  - denial_of_service
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1529
    technique_name: System Shutdown/Reboot
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_bulk_vm_termination.yml
rules:
  - title: ESXi Bulk VM Termination via pkill
    description: Detects bulk VM termination on ESXi hosts using the pkill command.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - syslog
      - vmware
  - title: ESXi Bulk VM Termination via esxcli
    description: Detects bulk VM termination on ESXi hosts using the esxcli command.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This brief addresses the abrupt termination of virtual machines on VMware ESXi hosts, a behavior that can indicate malicious activity. Attackers might employ this technique for various purposes, including causing a denial-of-service (DoS), staging ransomware attacks, or disrupting critical workloads by terminating VMs. While the specific actors behind such attacks can vary, the impact on affected organizations is significant. The detection logic focuses on identifying specific command patterns within ESXi syslog data that signal bulk VM termination, enabling security teams to respond swiftly to potential threats. This activity is associated with post-compromise scenarios on ESXi infrastructure and has been linked to ransomware groups like Black Basta.

## Attack Chain

1.  Attacker gains initial access to the ESXi host through an undisclosed method.
2.  Attacker executes commands via the ESXi shell or through `esxcli`.
3.  Attacker uses `esxcli vm process list` to enumerate running virtual machines on the host.
4.  The attacker filters the output of `esxcli vm process list` using `awk` or similar tools to extract VM process IDs.
5.  Attacker uses `esxcli vm process kill` with the `--format-param` option to terminate multiple virtual machine processes.
6.  Alternatively, the attacker uses `pkill -9 vmx-*` to forcibly terminate all VM processes.
7.  Virtual machines are abruptly shut down, leading to data loss and service disruption.
8.  The attack may be a precursor to data exfiltration or encryption as part of a ransomware attack.

## Impact

Successful bulk VM termination can lead to significant disruption of services, data loss, and potential financial losses. The number of victims and the scope of impact depend on the criticality of the virtual machines affected. In ransomware scenarios, this action serves to maximize the impact and pressure victims into paying the ransom. Sectors heavily reliant on virtualization, such as cloud providers, financial institutions, and healthcare organizations, are particularly vulnerable.

## Recommendation

*   Configure ESXi hosts to forward syslog output to your SIEM to collect the necessary data (VMWare ESXi Syslog).
*   Deploy the Sigma rules provided in this brief to your SIEM to detect bulk VM termination activity and tune them based on your environment.
*   Investigate any alerts triggered by these rules to determine the scope and impact of the activity.
*   Review and harden access controls to ESXi hosts to prevent unauthorized command execution.
*   Consider implementing rate limiting or alerting on ESXi command execution to detect anomalous activity.
*   Ingest logs with the appropriate Splunk Technology Add-on for VMware ESXi Logs, ensuring field extractions and CIM compatibility, to properly utilize the provided Splunk search query.
