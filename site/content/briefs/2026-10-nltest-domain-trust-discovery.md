---
title: Detection of Domain Trust Discovery via NLTest
slug: 2026-10-nltest-domain-trust-discovery
description: Adversaries leverage nltest.exe to enumerate Active Directory domain trust relationships, facilitating lateral movement and network reconnaissance in post-compromise environments.
date: "2026-10-12T17:54:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - active-directory
  - lateral-movement
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
    evidence: The following analytic identifies the execution of `nltest.exe` with command-line arguments `/domain_trusts` or `/all_trusts` to query Domain Trust information.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1482/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md
  - https://thedfirreport.com/2020/10/08/ryuks-return/
rules:
  - title: Detect NLTest Domain Trust Discovery
    description: Detects the execution of nltest.exe with arguments intended to query domain trust relationships, which is a common reconnaissance technique.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1482
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to detect T1482 activity.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for nltest discovery.
  hunt_leads:
    - lead: Search logs for past execution of nltest.exe with /domain_trusts or /all_trusts.
      technique_id: T1482
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic provided by Splunk ES content.
---

Adversaries often use built-in Windows administrative utilities to perform reconnaissance on compromised hosts. The nltest.exe utility is frequently abused to query domain trust relationships, providing attackers with critical information about network architecture, domain hierarchies, and potential paths for lateral movement. By executing nltest.exe with the /domain_trusts or /all_trusts arguments, actors can map the trust topography of an Active Directory environment. This behavior is highly indicative of post-exploitation activity, as legitimate administrative use of these specific flags is rare. This TTP is commonly associated with various ransomware and trojan operations, including Qakbot, Ryuk, IcedID, and Medusa, which utilize the gathered information to identify high-value targets and pivoting opportunities within the victim network.

## Impact

Successful domain trust discovery provides adversaries with the necessary intelligence to escalate privileges, conduct cross-domain authentication attacks, and propagate ransomware or malware across an entire enterprise. This reconnaissance step is a critical precursor to wide-scale network compromise and data exfiltration.

## Recommendation

Detection engineering teams should implement monitoring for process execution of nltest.exe with suspicious arguments.
- Deploy the provided Sigma rule to monitor for domain trust discovery attempts.
- Enable Sysmon or Windows Security event logging (Event ID 4688) to capture detailed command-line arguments.
- Establish an alert baseline for nltest.exe usage to distinguish between authorized administrative troubleshooting and anomalous reconnaissance.
- Investigate any hits against this rule to confirm if the activity aligns with known attacker infrastructure or unauthorized account behavior.
