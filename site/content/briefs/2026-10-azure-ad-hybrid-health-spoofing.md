---
brief_id: brief-2026-10-21-azure-ad-hybrid-health-spoofing
event_id: brief-2026-10-21-azure-ad-hybrid-health-spoofing
revision: 1
activity_at: "2026-10-21T02:44:19Z"
title: Microsoft Entra ID Hybrid Health AD FS service manipulation
slug: 2026-10-azure-ad-hybrid-health-spoofing
description: Threat actors can register unauthorized server instances within the Microsoft Entra ID (formerly Azure AD) Hybrid Health AD FS service to spoof signing logs and bypass authentication monitoring.
date: "2026-10-21T02:44:19Z"
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
  validation_status: Validated against provided sigma-hq source
cpes:
  - cpe:2.3:a:microsoft:entra_id_hybrid_health:*:*:*:*:*:*:*:*
tags:
  - azure
  - identity
  - defense-evasion
  - cloud-security
vendors:
  - Microsoft
products:
  - Entra ID Hybrid Health AD FS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: A threat actor can create a new AD Health ADFS service and create a fake server instance to spoof AD FS signing logs.
    confidence_band: high
references:
  - https://web.archive.org/web/20220619212736/https://o365blog.com/post/hybridhealthagent/
  - https://aadinternals.com/talks/HelSec%20August%202021.pdf
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/identity#microsoftadhybridhealthservice
  - https://www.inversecos.com/2023/01/detecting-fake-events-in-azure-sign-in.html
rules:
  - title: Detect Azure Hybrid Health AD FS New Server Instance
    description: Detects the creation or update of a server instance in an Azure AD Hybrid health AD FS service, which could indicate unauthorized manipulation.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1578
    data_sources:
      - administrative
      - azure
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect unauthorized service member additions.
      owner: Detection Engineering
      due: 48h
      evidence: Rule reduces visibility gap for service manipulation.
  hunt_leads:
    - lead: Identify all existing service members in ADHybridHealthService to establish a baseline.
      technique_id: T1578
      data_needed:
        - Azure Resource Manager logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Identification of unknown or orphaned service instances is critical for threat hunting.
  mitigation_plan:
    - priority: medium_term
      action: Review and tighten Azure RBAC permissions for the Microsoft.ADHybridHealthService resource provider.
      owner: IT Operations
      addresses: Unauthorized infrastructure modification
      evidence: Principle of least privilege reduces the surface for unauthorized modification.
---

Research indicates that attackers can manipulate the Microsoft Entra ID Hybrid Health AD FS service to report fraudulent server instances. By programmatically interacting with the Azure resource provider, an attacker can create a new AD FS service and register a rogue server instance without needing access to the physical, on-premises Active Directory Federation Services (AD FS) infrastructure. This technique allows adversaries to inject fake authentication events into the environment, potentially masking malicious activity or generating noise to facilitate unauthorized access. Defenders should monitor the administrative activity logs in Azure for the creation or modification of these service members, as this behavior is often indicative of reconnaissance or persistence attempts within the identity environment.

## Impact

Successful manipulation of the AD FS Hybrid Health service can allow attackers to spoof identity provider signing logs. This impacts the integrity of authentication telemetry, complicates incident response by introducing false event data, and may allow attackers to bypass security monitoring systems that rely on AD FS telemetry to detect anomalous authentication patterns.

## Recommendation

- Monitor Azure Activity Logs for the registration of new AD FS service members using the detection rule provided in this brief.
- Audit existing AD FS service instances in the Azure portal to ensure all registered servers are legitimate and authorized.
- Enforce strict Azure Role-Based Access Control (RBAC) to limit the ability of service principals or users to perform operations within the Microsoft.ADHybridHealthService resource provider.
- Deploy the Sigma rule below to the SIEM to detect suspicious service member additions.
