---
title: Detection of SharpHound Domain Enumeration Activity
slug: 2026-10-sharphound-recon
description: SharpHound is a reconnaissance tool used to gather Active Directory domain data, and the presence of its output files on an endpoint indicates active domain enumeration, often a precursor to privilege escalation and lateral movement.
date: "2026-10-12T17:41:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - discovery
  - bloodhound
  - sharphound
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: The following analytic detects the creation of files typically associated with SharpHound, a reconnaissance tool used for gathering domain and trust data.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: It leverages file modification events from the Endpoint.Filesystem data model, focusing on default file naming patterns like *_BloodHound.zip and various JSON files.
    confidence_band: high
rules:
  - title: Detect SharpHound Reconnaissance Output Files
    description: Detects the creation of files associated with SharpHound domain enumeration, such as JSON outputs and ZIP archives.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.001
      - T1087.002
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for SharpHound file signatures.
      owner: Detection Engineering
      due: 24h
      evidence: Analytic provided in the Splunk ES content.
  hunt_leads:
    - lead: Search for instances of SharpHound binaries or ZIP outputs in common temp directories.
      technique_id: T1087
      data_needed:
        - File creation logs (Sysmon Event ID 11)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly flags file patterns as the primary detection mechanism.
  mitigation_plan:
    - priority: medium_term
      action: Review Active Directory permissions to minimize the amount of information non-admin users can query via LDAP.
      owner: IT Operations
      addresses: Reconnaissance TTPs
      evidence: BloodHound enumeration relies on standard domain user permissions.
---

SharpHound is the primary data collector for the BloodHound project, used by both authorized security testers and threat actors to map Active Directory environments. The tool automates the collection of domain, trust, group, and user information, exporting results into structured JSON files or compressed archives (e.g., BloodHound.zip). Attackers utilize this reconnaissance data to identify high-value targets, paths to domain dominance, and misconfigurations within the identity infrastructure. The generation of these files on an endpoint is a high-fidelity indicator of reconnaissance activity. Defenders should monitor for the creation of these specific file patterns, as they often precede lateral movement, the deployment of ransomware, or other malicious actions in a compromised network.

## Attack Chain

1. Attacker establishes initial access on a domain-joined machine using compromised credentials or existing persistence.
2. Attacker downloads or stages the SharpHound executable (e.g., SharpHound.exe) on the target host.
3. Attacker executes the collector with specific flags to enumerate domain objects.
4. SharpHound queries the Domain Controller via LDAP to extract user, group, and GPO data.
5. The tool writes the collected metadata to the local disk in JSON or ZIP format.
6. Attacker exfiltrates the resulting archives to a remote C2 server.
7. Attacker analyzes the output in the BloodHound graph database to identify attack paths.
8. Attacker executes lateral movement or privilege escalation steps based on identified paths.

## Impact

Successful domain enumeration via SharpHound provides attackers with a comprehensive map of the target environment. This reconnaissance significantly increases the probability of successful privilege escalation, lateral movement, and the ultimate compromise of the Active Directory forest. It has been observed in association with various ransomware operations, including BlackSuit.

## Recommendation

* Deploy the Sigma rule below to detect the creation of SharpHound-specific output files using Sysmon Event ID 11.
* Monitor for suspicious process execution patterns associated with SharpHound, such as non-standard process names or command-line arguments involving domain enumeration.
* Investigate the identity associated with the detected process, as this user account is likely compromised.
* Use the file path and process metadata from the file creation event to locate and isolate the source SharpHound binary.
