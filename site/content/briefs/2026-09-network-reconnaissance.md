---
title: Detection of Domain Controller Discovery via Nslookup
slug: 2026-09-network-reconnaissance
description: Adversaries utilize the nslookup utility to identify domain controllers through specific LDAP service record queries, a common step in network reconnaissance to facilitate domain-wide enumeration.
date: "2026-09-03T12:40:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - discovery
  - reconnaissance
  - active-directory
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Adversaries utilize the nslookup utility to identify domain controllers through specific LDAP service record queries.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: A specific technique involves the misuse of the legitimate Windows utility 'nslookup' to perform DNS service record lookups.
    confidence_band: high
references:
  - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_nslookup_domain_discovery.yml
rules:
  - title: Detect Nslookup Domain Controller Discovery
    description: Detects the use of nslookup to query the Active Directory LDAP service record, a technique used for domain reconnaissance.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1082
      - T1087
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
    - action: Deploy the provided Sigma rule for nslookup discovery detection.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides established detection logic for reconnaissance TTPs.
  hunt_leads:
    - lead: Search logs for process execution of 'nslookup.exe' with command-line arguments containing SRV records.
      technique_id: T1087
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Identified as a common reconnaissance pattern in DFIR reports.
---

This threat brief focuses on detecting network reconnaissance activity performed by adversaries during the early stages of an intrusion. Attackers often execute queries against the Active Directory environment to locate domain controllers, which helps them map the network topology and identify high-value targets for lateral movement or domain privilege escalation. A specific technique observed in past campaigns, such as those involving the Qbot (Qakbot) malware, involves the misuse of the legitimate Windows utility 'nslookup' to perform DNS service record lookups for the '_ldap._tcp.dc._msdcs.' SRV record. This query specifically targets the domain controller location infrastructure, revealing the names and locations of available domain controllers in a domain environment. Defenders should monitor for these specific command-line patterns, as they often deviate from standard administrative behavior and indicate malicious discovery efforts.

## Attack Chain

1. Initial access is established via a malicious document or payload execution on a domain-joined host.
2. The adversary executes a command-line utility to perform reconnaissance on the local network environment.
3. The attacker invokes 'nslookup.exe' via the command shell or a script.
4. The process initiates a DNS SRV record request for '_ldap._tcp.dc._msdcs.' to identify domain controllers.
5. The DNS server responds with the list of FQDNs for the domain controllers.
6. The adversary processes this information to verify the target domain architecture.
7. The attacker proceeds to use the discovered domain controller information to perform further lateral movement, such as password spraying or exploitation of AD-integrated services.

## Impact

Successful domain reconnaissance allows adversaries to map the internal network structure, identify critical infrastructure such as Domain Controllers, and refine their lateral movement strategies. This intelligence enables attackers to pivot more effectively within the environment, potentially leading to unauthorized access to sensitive data, domain-wide compromise, and long-term persistence within the organization.

## Recommendation

Prioritize the implementation of process-creation logging and alert on the execution of nslookup with the identified LDAP SRV record query string.

* Enable Sysmon Event ID 1 (Process Creation) across all domain-joined endpoints to capture detailed command-line arguments.
* Deploy the provided Sigma rule to your SIEM environment to detect discovery attempts targeting the DC service record.
* Investigate any detected 'nslookup' process executions that do not originate from known administrative management scripts or automated network health monitors.
