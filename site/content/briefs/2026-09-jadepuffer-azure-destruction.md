---
title: JadePuffer (Storm-3168) Conducts Destructive Azure Tenant Compromise
slug: 2026-09-jadepuffer-azure-destruction
description: The threat actor Storm-3168 (JadePuffer) leveraged compromised service principal credentials to conduct high-speed reconnaissance and a large-scale destructive campaign against an Azure environment.
date: "2026-09-28T16:19:49Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-3168
vendors:
  - Microsoft
products:
  - Azure (Cloud Services)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The first compromised service principal spent about 15-1/2 hours mapping virtual machines (VMs), subscriptions, resource groups, and other resources.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The destructive activity began, with more than 100 attempts to delete storage accounts, most of which succeeded.
    confidence_band: high
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Cloud Security Team
  immediate_actions:
    - action: Scan GitHub and internal code repositories for exposed Azure service principal secrets
      owner: Cloud Security Team
      due: 24h
      evidence: Source notes that secrets were exposed in a public GitHub issue history.
  hunt_leads:
    - lead: Service principals executing unusual enumeration and mass deletion commands in short succession
      technique_id: T1485
      data_needed:
        - Azure Activity Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source details parallel deletion attempts of storage accounts and database resources.
  mitigation_plan:
    - priority: immediate
      action: Rotate all service principal secrets and enforce least-privilege RBAC roles
      owner: Cloud Security Team
      addresses: Azure Workload Identities
      evidence: Microsoft recommendation in source text.
---

In June 2026, the threat actor Storm-3168, tracked as JadePuffer, executed a coordinated, highly automated attack against a Microsoft Azure tenant. The actor gained initial access via two service principals, likely utilizing secrets exposed in a public GitHub issue history. The campaign unfolded in two distinct phases: a reconnaissance phase involving over 300 successful read operations to map virtual machines, subscriptions, and resource groups, followed by a rapid destructive phase. During the destruction, the actor systematically attempted to delete storage accounts, Key Vaults, and App Service plans. Following the deletions, the actor performed inventory requests and retrieved access keys from remaining storage accounts, indicating an intent to secure persistent access to residual data. This incident demonstrates the capability of agentic or highly automated actors to conduct rapid, complex post-compromise operations at cloud scale.

## Attack Chain

1. Initial Access: Compromised service principal client ID, client secret, and tenant ID credentials likely obtained from plaintext exposure in a public GitHub repository edit history.
2. Environment Mapping: The first service principal conducted 15.5 hours of reconnaissance, performing over 300 read operations to identify subscriptions, resource groups, and VM inventory.
3. Escalated Discovery: The second service principal enumerated resource groups across two subscriptions in 5 seconds to expand the scope of impact.
4. Credential Hunting: The attacker enumerated Azure App Service configuration stores and attempted unauthorized ListKey operations against storage accounts.
5. Destructive Operations: The actor initiated a parallelized destruction campaign, successfully deleting over 100 storage accounts, Azure Key Vaults, Function Apps, and App Service plans.
6. Data Exfiltration/Persistence: Following destructive actions, the attacker made inventory requests for Site Recovery storage accounts and executed 30+ successful ListKeys requests to compromise long-term access keys.
7. Impact: Operational disruption resulting from the deletion of core cloud infrastructure, applications, and storage assets.

## Impact

The campaign resulted in significant operational disruption through the unauthorized deletion of critical Azure cloud infrastructure, including storage accounts, databases, Key Vaults, and application plans. While no ransom note was observed, the speed and scope of the deletion are consistent with extortion-based ransomware tactics, threatening the availability and integrity of the victim's cloud data and services.

## Recommendation

Prioritize the following actions to secure Azure environments against identity-based cloud attacks:
- Immediately audit public-facing source code repositories for exposed service principal secrets, client IDs, and tenant IDs.
- Implement a credential rotation policy for all service principals and workload identities, particularly those used in automated CI/CD pipelines.
- Apply the principle of least privilege to all service principals, ensuring they only have the minimum permissions required for their specific function.
- Enable Microsoft Defender for Cloud for all critical Azure workloads to gain visibility into anomalous resource enumeration and destructive API calls.
- Monitor Azure activity logs for sudden bursts of 'Delete' or 'ListKeys' operations initiated by service principals, especially when originating from unexpected source IPs.
