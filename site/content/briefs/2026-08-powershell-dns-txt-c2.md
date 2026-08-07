---
title: Detection of PowerShell-Based Command and Control via DNS TXT Records
slug: 2026-08-powershell-dns-txt-c2
description: This brief describes a detection methodology for identifying malware utilizing DNS TXT records to retrieve commands via PowerShell to bypass network egress restrictions.
date: "2026-08-07T15:15:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - c2
  - powershell
  - dns
  - malware
vendors:
  - Microsoft
products:
  - PowerShell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The detection monitors for malicious use of PowerShell script blocks.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The analytic detects execution of powershell commands retrieved from a remote DNS TXT query response.
    confidence_band: high
rules:
  - title: Detect PowerShell Commands Retrieving Data from DNS TXT Records
    description: Detects execution of PowerShell scripts that use DNS lookup utilities (resolve-dnsname, nslookup, dig) to retrieve TXT records, followed by immediate execution of the content via IEX.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1071.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 7d
      evidence: Required for visibility into script execution as per implementation guide.
    - action: Deploy Sigma detection rule for DNS TXT/IEX PowerShell patterns.
      owner: Detection Engineering
      due: 3d
      evidence: Primary detection mechanism for this threat.
---

This threat involves the use of DNS TXT records as a covert channel for command-and-control (C2) communications. By embedding commands or configuration data within DNS TXT records, attackers can exfiltrate data or retrieve instructions that are often overlooked by standard firewall and proxy egress filtering, as DNS traffic is typically permitted for name resolution. The technique leverages native Windows PowerShell commands, specifically utilities like `resolve-dnsname`, `nslookup`, or `dig`, in conjunction with execution primitives such as `Invoke-Expression` (IEX) to execute the contents of the DNS response. This method provides a resilient communication channel that is difficult to disrupt without impacting legitimate network name resolution. Detection relies on monitoring PowerShell Script Block Logging (Event ID 4104) to capture the specific script blocks that perform both the DNS lookup and the subsequent execution of the retrieved data.

## Impact

Successful implementation of this C2 technique allows attackers to maintain persistent, stealthy control over compromised hosts, facilitate lateral movement, or coordinate multi-stage malware execution while avoiding traditional network security boundaries. This represents a significant risk for organizations with strict egress filtering policies, as it exploits the necessary reliance on DNS infrastructure to bypass these controls.

## Recommendation

Deploy detection for PowerShell execution patterns involving DNS query utilities and script execution commands. Ensure PowerShell Script Block Logging (Event ID 4104) is enabled across all endpoints to provide the visibility required to identify this activity. Use the provided Sigma rule to monitor for concurrent invocation of DNS lookup utilities and script execution functions.
