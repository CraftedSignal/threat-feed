---
title: Probo Cross-Tenant IDOR Vulnerability (CVE-2026-63505)
slug: 2026-08-probo-idor
description: Probo versions 0.222.2 and earlier are vulnerable to a cross-tenant Insecure Direct Object Reference (IDOR) flaw allowing unauthorized retrieval of confidential risk information due to missing tenant scoping.
date: "2026-08-17T14:53:37Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Probo
products:
  - Probo (<= 0.222.2)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An attacker can perform cross-tenant data access by referencing a risk ID belonging to another organization when creating or updating a finding.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52650
  - https://github.com/Pig-Tail/security-research/tree/master/CVE-2026-63505-probo
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Probo to 0.223.1 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor release fixes the underlying tenant scoping issue in 0.223.1
---

Probo version 0.222.2 and earlier contains an Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2026-63505. The flaw exists because the Finding and Risk data resolvers fail to enforce tenant-scoped validation when referencing Risk IDs during the creation or update of Findings. Specifically, the system authorizes the parent Finding, but the dataloader uses the GID of the Risk object itself to scope the retrieval, effectively bypassing multi-tenancy isolation. An attacker belonging to one organization can reference a Risk ID belonging to a different organization, resulting in unauthorized cross-tenant data access. This vulnerability was disclosed alongside a PoC demonstrating the ability to read sensitive, cross-tenant risk data. The issue is resolved in Probo version 0.223.1.

## Attack Chain

1. Attacker authenticates to a legitimate tenant account in the target Probo instance.
2. Attacker enumerates or identifies a target Risk ID belonging to a different tenant.
3. Attacker crafts a POST/PUT request to the FindingService API endpoint responsible for creation or updates.
4. Attacker includes the target Risk ID (from a different tenant) within the 'riskId' parameter of the API request.
5. The application performs a server-side store operation without validating if the provided Risk ID belongs to the current user's tenant.
6. The application later triggers a read operation for the Finding via the audit_resolvers.
7. The application's dataloader incorrectly scopes the retrieval by the Risk object's own GID rather than the user's tenant.
8. The application discloses the confidential data associated with the cross-tenant Risk object to the attacker.

## Impact

Successful exploitation allows for the unauthorized retrieval of sensitive and confidential risk data across different organizational tenants. This leads to the compromise of data integrity and confidentiality for any user of a multi-tenant Probo deployment. The severity is high for platforms hosting multiple distinct organizations.

## Recommendation

Prioritize the upgrade of all Probo instances to version 0.223.1 or later to remediate CVE-2026-63505. Implement monitoring for API requests targeting the 'FindingService' where the 'riskId' parameter is supplied by the user. Ensure that internal data access layers enforce mandatory tenant-scope checks that cannot be overridden by object-specific GID lookups.
