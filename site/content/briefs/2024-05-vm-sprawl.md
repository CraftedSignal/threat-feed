---
title: Uncontrolled VM Growth Leading to Security Gaps in Cloud Environments
slug: 2024-05-vm-sprawl
description: Uncontrolled growth of virtual machines (VM sprawl) in cloud environments allows attackers to exploit unmonitored VMs with overly permissive access for lateral movement, data exfiltration, and ransomware deployment.
date: "2026-03-25T10:00:00Z"
severities:
  - high
tags:
  - cloud
  - vm-sprawl
  - identity-abuse
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.002
    technique_name: 'Remote Services: SMB/Windows Admin Shares'
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Windows Event Logs'
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.welivesecurity.com/en/business-security/virtual-machines-virtually-everywhere-real-security-gaps/
rules:
  - title: Detect Suspicious Process Execution via East-West Traffic
    description: Detects potential lateral movement attempts by identifying suspicious processes executed on VMs after network connections originating from within the same VPC/VNet.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Azure VM Creation from Uncommon Source IPs
    description: Detects the creation of Azure VMs initiated from IP addresses not typically associated with administrative activity, which may indicate compromised Azure accounts being used to spin up resources for malicious purposes.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1583.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The increasing adoption of cloud services has led to a phenomenon known as "VM sprawl," where organizations experience uncontrolled growth in the number of virtual machines (VMs) provisioned across multiple cloud providers such as AWS, Azure, and GCP. This often results in VMs being left unmonitored, unpatched, and with overly broad access permissions. While cloud service providers (CSPs) offer baseline security, maintaining the ongoing security posture of these VMs falls to the customer. This…
