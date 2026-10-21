---
brief_id: brief-2026-10-21-goldendmsa
event_id: brief-2026-10-21-goldendmsa
revision: 1
activity_at: "2026-10-21T01:43:03Z"
title: GoldenDMSA HackTool Execution
slug: 2026-10-goldendmsa
description: The GoldenDMSA tool facilitates unauthorized manipulation and authentication bypass against Active Directory Group Managed Service Accounts (gMSA).
date: "2026-10-21T01:43:03Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Validated against SigmaHQ source.
tags:
  - hacktool
  - active-directory
  - windows
  - privilege-escalation
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Detects execution of GoldenDMSA hacktool used for Directory Service Account manipulation.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Detects execution of GoldenDMSA hacktool used for Directory Service Account manipulation.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.001
    technique_name: Password Guessing
    evidence: Detects execution of GoldenDMSA hacktool used for Directory Service Account manipulation.
    confidence_band: high
rules:
  - title: Detect GoldenDMSA HackTool Execution
    description: Detects execution of GoldenDMSA hacktool used for Directory Service Account manipulation.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - persistence
      - privilege-escalation
    techniques:
      - T1098
      - T1110.001
      - T1558.003
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
    - action: Deploy the provided Sigma rule to SIEM environment.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific binary and command-line patterns.
  hunt_leads:
    - lead: Search for instances of GoldenDMSA.exe in historical process execution logs.
      technique_id: T1098
      data_needed:
        - Process creation logs (Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tool name is unique and high fidelity for malicious activity.
  mitigation_plan:
    - priority: medium_term
      action: Restrict execution of unauthorized tools via AppLocker or WDAC.
      owner: IT Operations
      evidence: Tooling is typically brought into the environment by attackers.
---

GoldenDMSA is a specialized offensive security tool designed to target Active Directory environments by exploiting the authentication mechanisms of Group Managed Service Accounts (gMSA). The tool allows attackers to perform account manipulation and authentication bypass, potentially leading to unauthorized privilege escalation or persistence within a compromised domain. The tool's capabilities center on leveraging vulnerabilities in gMSA handling, often involving brute-force techniques against service accounts to recover credentials or impersonate accounts. Its use is typically associated with post-exploitation phases where an adversary seeks to solidify their hold on a domain controller or privileged identity management service. Defenders should monitor for the execution of this specific binary and suspicious command-line patterns indicating brute-force or service account enumeration attempts.

## Attack Chain

1. Initial compromise of a workstation or server joined to the Active Directory domain.
2. Escalation of privileges to reach a security context capable of executing administrative utilities.
3. Delivery of the GoldenDMSA.exe utility to the local system disk.
4. Execution of the tool with command-line arguments specifying a security identifier (SID) or target account.
5. Utilization of dictionary files or provided wordlists to conduct brute-force attacks against gMSA targets.
6. Interaction with domain controllers to attempt authentication bypass or credential recovery.
7. Successful exploitation resulting in the capture of service account secrets or unauthorized access to sensitive service resources.

## Impact

Successful use of GoldenDMSA allows attackers to bypass standard AD authentication controls, gain control over service accounts, and potentially perform unauthorized actions within the enterprise domain. This poses a severe risk to service integrity, as compromised gMSAs are often used for critical infrastructure and automated system tasks.

## Recommendation

- Deploy the provided Sigma rule to detect the execution of the GoldenDMSA binary or associated command-line patterns on all endpoints and domain controllers.
- Audit logs for the use of high-privilege service account operations that deviate from established baselines for gMSA authentication.
- Implement stringent monitoring for brute-force patterns targeting AD service accounts using Event ID 4625 and 4768.
