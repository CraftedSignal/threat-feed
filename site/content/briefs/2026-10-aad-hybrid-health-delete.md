---
brief_id: brief-2026-10-21-aad-hybrid-health-delete
event_id: brief-2026-10-21-aad-hybrid-health-delete
revision: 1
activity_at: "2026-10-21T02:44:27Z"
title: Azure AD Hybrid Health AD FS Service deletion
slug: 2026-10-aad-hybrid-health-delete
description: Attackers may delete Azure AD Hybrid Health AD FS service instances to conceal the removal of fake servers used for spoofing AD FS signing logs.
date: "2026-10-21T02:44:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - defense-impairment
  - cloud
  - azure
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Azure AD Hybrid Health
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    subtechnique_id: T1578.003
    subtechnique_name: Delete Cloud Instance
    evidence: A threat actor can create a new AD Health ADFS service and create a fake server to spoof AD FS signing logs.
    confidence_band: high
references:
  - https://web.archive.org/web/20220619212736/https://o365blog.com/post/hybridhealthagent/
  - https://aadinternals.com/talks/HelSec%20August%202021.pdf
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/identity#microsoftadhybridhealthservice
  - https://www.inversecos.com/2023/01/detecting-fake-events-in-azure-sign-in.html
rules:
  - title: Detect Azure AD Hybrid Health AD FS Service Deletion
    description: Detects the deletion of an Azure AD Hybrid health AD FS service instance which may indicate cleanup of spoofed infrastructure.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1578.003
    data_sources:
      - administrative
      - azure
      - activitylogs
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect AD Hybrid Health service deletions
      owner: Detection Engineering
      due: 24h
      evidence: Rule allows monitoring for infrastructure cleanup after potential log spoofing
  hunt_leads:
    - lead: Identify all instances of AD Hybrid Health service deletion in the past 90 days
      technique_id: T1578.003
      data_needed:
        - Azure activity logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known TTP for cleaning up spoofed AD FS health infrastructure
---

Threat actors can manipulate Azure AD Hybrid Health for AD FS to compromise the integrity of authentication logs. By creating a rogue AD FS service instance and registering a fake server, attackers can inject spoofed AD FS signing events into the environment. Once the malicious activity is completed or the attacker no longer requires the persistence mechanism, they delete the rogue AD FS service instance via the Azure Management API. This deletion is a critical telemetry point for security operations centers, as it often marks the conclusion of a log manipulation campaign that may have been used to bypass identity-based detections or hide unauthorized access. Monitoring for these specific service deletions provides visibility into potential efforts to impair defensive visibility within a hybrid identity environment.

## Attack Chain

1. Attacker gains administrative access to the Azure tenant (e.g., via compromised credentials).
2. Attacker registers a new Azure AD Hybrid Health AD FS service instance.
3. Attacker adds a rogue server to the AD FS health environment.
4. Attacker leverages the rogue server to inject spoofed AD FS authentication logs.
5. Attacker performs malicious operations elsewhere in the environment, masked by spoofed events.
6. Attacker initiates a delete request via the Azure AD Hybrid Health API for the malicious service instance.
7. Azure Resource Manager processes the 'MICROSOFT.ADHYBRIDHEALTHSERVICE/SERVICES/DELETE' operation.
8. Unauthorized health service is removed, effectively cleaning up evidence of the spoofing infrastructure.

## Impact

The primary impact is the loss of reliable authentication telemetry. If successful, an attacker can mask lateral movement or account manipulation by injecting benign-appearing authentication logs from a non-existent or rogue source. This undermines the capability of identity protection systems to flag anomalous login activity, potentially allowing attackers to maintain access for extended periods without detection.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to monitor for the deletion of AAD Hybrid Health service instances.
* Audit all current AD Hybrid Health service instances within the tenant to ensure only authorized infrastructure is present.
* Establish an alert for any new 'MICROSOFT.ADHYBRIDHEALTHSERVICE/SERVICES/WRITE' operations to detect the creation of unauthorized AD FS health instances.
* Restrict Azure RBAC roles that allow the modification or deletion of Hybrid Health service configurations to a limited set of verified identity administrators.
