---
title: Detection of Local User Enumeration via PowerShell
slug: 2026-10-getlocaluser-powershell
description: Adversaries utilize the Get-LocalUser PowerShell cmdlet for account discovery and situational awareness on compromised Windows endpoints.
date: "2026-10-12T17:46:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - windows
  - powershell
  - reconnaissance
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Adversaries and Red Teams may use it to enumerate local users for situational awareness and Active Directory discovery.
    confidence_band: high
rules:
  - title: Detect Get-LocalUser PowerShell Execution
    description: Detects the execution of powershell.exe with the Get-LocalUser commandlet, which is used to query local user accounts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for historical instances of Get-LocalUser to establish a baseline of administrative behavior
      technique_id: T1087.001
      data_needed:
        - Process command line logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Adversaries use it to enumerate local users.
---

Adversaries and Red Team operators frequently leverage the native Windows PowerShell `Get-LocalUser` cmdlet to perform account enumeration during the discovery phase of an attack. This activity is a common precursor to lateral movement, privilege escalation, or targeting of specific high-value accounts. While this command is a standard administrative utility, its execution in non-administrative contexts or as part of a broader reconnaissance script often indicates malicious activity. Security operations teams should monitor process execution telemetry for `powershell.exe` command lines containing this specific cmdlet to maintain visibility into internal network discovery efforts.

## Impact

Successful local user enumeration allows attackers to identify potential targets for lateral movement and privilege escalation, increasing the risk of unauthorized access to sensitive data and critical system components within the target environment.

## Recommendation

Deploy the following Sigma rule to monitor for `Get-LocalUser` execution in environments where such activity is not expected from standard administrative accounts.

* Ingest `Sysmon Event ID 1` or `Windows Security Event ID 4688` into your SIEM and map to the CIM `Endpoint` data model.
* Tune alerts by filtering known administrative service accounts or common management scripts that legitimately query local user databases.
