---
title: Active Directory Group Policy Deletion Detected
slug: 2024-01-ad-gpo-deleted
description: Detection of Active Directory Group Policy deletion using event ID 5136, indicating potential malicious activity or misconfiguration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - group-policy
  - gpo
  - deletion
  - t1484.001
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484.001
    technique_name: Group Policy Modification
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Enabling_an_audit_trail_from_Active_Directory
rules:
  - title: AD GPO Deleted via Event 5136
    description: Detects Active Directory Group Policy deletion events based on Windows Event ID 5136.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1484.001
    data_sources:
      - wineventlog
      - windows
  - title: AD GPO Deleted - PowerShell
    description: Detects AD GPO deletion via PowerShell command Remove-GPO
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1484.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies when an Active Directory Group Policy Object (GPO) is deleted, potentially indicating malicious activity aimed at disrupting organizational policies or misconfigurations leading to unintended changes. The detection leverages Windows Event Log Security (event ID 5136) and Active Directory monitoring data to correlate the deletion event with the GPO name and the user responsible. It is important to investigate these events promptly, as GPO deletions can have significant impact on the security posture and functionality of a Windows domain. This alert helps defenders identify unauthorized or accidental GPO deletions, enabling rapid response and remediation.

## Attack Chain

1.  An attacker gains unauthorized access to an account with sufficient privileges to manage Group Policy Objects (GPOs).
2.  The attacker uses the Group Policy Management Console (GPMC) or PowerShell cmdlets (e.g., `Remove-GPO`) to initiate the deletion of a targeted GPO.
3.  The deletion event generates Windows Security Event ID 5136, logging details of the object being modified (the GPO). The `AttributeLDAPDisplayName` is `gpLink`.
4.  The event includes OperationType codes %%14675 (old value) and %%14674 (new value) showing the before and after states of the GPO.
5.  The event also includes the `ObjectDN` (Distinguished Name) of the deleted GPO.
6.  Active Directory monitoring (`admon`) events, specifically updates to `Group-Policy-Container`, provide the `displayName` of the GPO based on its `distinguishedName`.
7.  The `gpLink` attribute is removed from the affected Organizational Units (OUs) or domains where the GPO was applied, effectively removing the policies associated with that GPO.
8.  The deletion of the GPO can lead to changes in user and computer settings, potentially weakening security controls or disrupting normal operations.

## Impact

Successful deletion of GPOs can severely impact an organization's security posture. Deleted GPOs can lead to systems reverting to default configurations, removal of security policies, and potential exposure to vulnerabilities. The scope of impact depends on the criticality and scope of the deleted GPOs, ranging from affecting a small group of users to compromising the entire domain. This can lead to data breaches, system compromise, or disruption of services. Early detection and remediation are crucial to minimize potential damage.

## Recommendation

*   Ensure Active Directory auditing is enabled and ingesting Windows Security Event ID 5136 and Active Directory monitoring data. See the referenced Splunk Lantern article for guidance.
*   Configure the `wineventlog_security` and `admon` macros in your Splunk environment to point to the correct indexes as described in the "how_to_implement" section.
*   Deploy the provided Sigma rule "AD GPO Deleted via Event 5136" to detect GPO deletion events. Tune the rule's filter (`windows_ad_gpo_deleted_filter`) to exclude any known legitimate GPO deletion activities.
*   Investigate all triggered alerts by examining the source user (`src_user`) and the deleted GPO (`policyName`) to determine if the deletion was authorized.
*   Utilize the provided drilldown searches to investigate the activity of the source user and any associated risk events.
