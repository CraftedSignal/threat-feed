---
title: Detection of Domain Trust Discovery via Dsquery
slug: 2026-10-dsquery-domain-discovery
description: Adversaries leverage the native Windows utility dsquery.exe to map Active Directory domain trusts, facilitating lateral movement and privilege escalation.
date: "2026-10-12T17:42:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
tags:
  - active-directory
  - discovery
  - lateral-movement
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
    evidence: The following analytic detects the execution of dsquery.exe with arguments targeting TrustedDomain queries directly from the command line.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md
  - https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/
rules:
  - title: Detect Dsquery Domain Trust Discovery
    description: Detects the execution of dsquery.exe with arguments targeting trusted domain objects, which is indicative of domain trust reconnaissance.
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
  immediate_actions:
    - action: Deploy the Sigma rule to detect dsquery domain trust discovery
      owner: Detection Engineering
      due: 48h
      evidence: Source explicitly identifies dsquery.exe usage as high-fidelity TTP
  hunt_leads:
    - lead: Search for historical dsquery.exe executions with 'trustedDomain' arguments
      technique_id: T1482
      data_needed:
        - Endpoint process logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Common TTP for domain reconnaissance
  mitigation_plan:
    - priority: medium
      action: Implement application control or block lists for unnecessary administrative binaries on workstations
      owner: IT Operations
      addresses: T1482
      evidence: Defense-in-depth practice
---

Adversaries often use the built-in Windows utility `dsquery.exe` to perform Active Directory domain trust discovery. By executing `dsquery.exe` with arguments targeting `TrustedDomain` objects, an attacker can map the trust relationships within a Windows domain environment. This information is vital for planning lateral movement and identifying targets for privilege escalation. This technique is well-documented in adversary tradecraft (MITRE ATT&CK T1482) as a standard step during the post-compromise reconnaissance phase. Defenders should monitor EDR telemetry for process executions of `dsquery.exe` that include indicators of trust discovery, as such activity is rarely required for standard administrative tasks in a production environment and serves as a high-fidelity indicator of potentially malicious activity.

## Attack Chain

1. Attacker gains initial access to a compromised Windows host via phishing or exploited vulnerabilities.
2. Attacker establishes a foothold and executes initial reconnaissance commands.
3. Attacker identifies the native binary `dsquery.exe` (typically located in System32) to query Active Directory.
4. Attacker executes `dsquery.exe * -scope subtree -filter "(objectCategory=trustedDomain)"` to enumerate trust relationships.
5. The binary communicates with a Domain Controller via LDAP to retrieve trust information.
6. The command output is displayed to the console or captured into a file by the attacker.
7. Attacker uses the mapped domain trusts to identify targets for lateral movement.
8. Attacker proceeds to authenticate to or exploit targets in the discovered trusted domains.

## Impact

Successful domain trust discovery provides attackers with a roadmap of the enterprise infrastructure, significantly increasing the probability of successful lateral movement and domain-wide compromise. This activity is a precursor to more severe impacts, including data exfiltration, ransomware deployment, and long-term persistence across multiple connected domains.

## Recommendation

* Deploy the Sigma rule provided below to your SIEM/EDR platform to detect the specific command-line arguments associated with trust discovery.
* Enable Sysmon (Event ID 1) or Windows Security Log (Event ID 4688) with full command-line logging enabled across all domain-joined endpoints.
* Investigate instances of `dsquery.exe` spawning from non-standard parent processes or originating from non-administrative users.
* Use the Splunk Common Information Model (CIM) to normalize process creation logs and ensure that `dsquery.exe` executions are captured within the `Endpoint.Processes` data model.
