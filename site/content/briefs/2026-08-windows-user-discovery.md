---
title: Detection of Windows User Enumeration via Net Utility
slug: 2026-08-windows-user-discovery
description: Adversaries perform account enumeration using 'net.exe' or 'net1.exe' to facilitate situational awareness, privilege escalation, and lateral movement in Windows environments.
date: "2026-08-05T21:12:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The following analytic detects the execution of net.exe or net1.exe with command-line arguments user or users to query local and domain accounts.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The following analytic detects the execution of net.exe or net1.exe with command-line arguments user or users to query local and domain accounts.
    confidence_band: high
rules:
  - title: Detect Windows User Discovery via Net
    description: Detects execution of net.exe or net1.exe with user/users arguments to query local or domain accounts, often used for reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.001
      - T1087.002
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
    - action: Deploy the provided Sigma rule to detect user enumeration activity.
      owner: Detection Engineering
      due: 72h
      evidence: Analytic detects potential account enumeration reconnaissance by identifying the execution of 'net.exe' or 'net1.exe'.
  hunt_leads:
    - lead: Search for instances of net.exe/net1.exe running with 'user' or 'users' arguments in historical telemetry.
      technique_id: T1087
      data_needed:
        - Process creation events with command-line arguments
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This activity is significant as it indicates potential reconnaissance efforts by adversaries.
---

Adversaries often use the built-in Windows 'net.exe' or 'net1.exe' utilities to enumerate local and domain user accounts as part of initial reconnaissance. This activity is a common precursor to more intrusive actions, such as identifying high-value targets for privilege escalation or lateral movement within an Active Directory environment. While these commands are legitimate administrative tools, their use in an unauthorized context or by unusual processes indicates potential threat actor presence. This behavior has been observed in campaigns associated with various groups, including those using Medusa ransomware or known Sandworm tools, to map internal account structures. Security teams should monitor process execution telemetry for these commands and tune alerts to minimize noise from authorized administrative troubleshooting.

## Attack Chain

1. Attacker gains initial access to a compromised Windows host via phishing, exploitation, or credential theft.
2. The attacker executes command-line reconnaissance to understand the environment.
3. The attacker calls 'net.exe user' or 'net1.exe user' to list local accounts on the current system.
4. The attacker calls 'net.exe user /domain' or 'net1.exe user /domain' to query Active Directory domain user accounts.
5. The attacker parses the output of these commands to identify potential administrative or service accounts.
6. The attacker uses the discovered account information to conduct targeted password spraying or credential brute-forcing.
7. The attacker leverages compromised credentials to facilitate lateral movement to domain-joined workstations or servers.
8. The final objective includes data exfiltration, ransomware deployment, or long-term persistence in the target environment.

## Impact

Successful user enumeration allows attackers to map the internal structure of an organization, identifying critical accounts that lead to escalated privileges and increased reach across the network. If ignored, this activity often precedes lateral movement, data theft, and the deployment of ransomware, potentially impacting all systems joined to the compromised domain.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to monitor for 'net.exe' or 'net1.exe' account discovery patterns.
* Enable Sysmon Event ID 1 (Process Creation) or Windows Security Event ID 4688 with command-line logging to ensure the necessary fields are captured for detection.
* Use the Splunk Common Information Model (CIM) to map process execution logs to the Endpoint data model.
* Investigate occurrences of these commands by non-administrative users or processes that lack a legitimate business justification for user account management.
