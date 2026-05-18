---
title: Microsoft Graph Multi-Category Reconnaissance Burst
slug: 2026-05-microsoft-graph-recon
description: The rule detects Microsoft Graph activity from delegated user tokens where a single user session and source IP rapidly touches multiple high-value Graph paths indicative of reconnaissance, suggesting a broad enumeration playbook.
date: "2026-05-18T09:02:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - api
  - azure
  - microsoft-entra-id
  - microsoft-graph
  - threat-detection
  - discovery
vendors:
  - Microsoft
products:
  - Microsoft Graph
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/discovery_graph_activity_delegated_user_multi_category_recon.toml
rules:
  - title: Detect Microsoft Graph Multi-Category Reconnaissance Burst
    description: Detects Microsoft Graph activity from delegated user tokens rapidly accessing multiple high-value Graph paths indicative of reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087
      - T1526
    data_sources:
      - webserver
  - title: Detect Microsoft Graph Role Enumeration
    description: Detects Microsoft Graph activity attempting to enumerate directory roles via delegated user tokens.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087
    data_sources:
      - webserver
rules_count: 2
---

This detection rule identifies suspicious reconnaissance activity within Microsoft Graph Activity Logs. It focuses on delegated user tokens (client_auth_method 0) where a single user session and source IP rapidly access multiple high-value Graph paths. The rule categorizes these requests into distinct areas such as role discovery, cross-tenant relationship queries, mailbox paths, contact harvesting, and organization/licensing metadata. A short burst of activity touching three or more distinct categories suggests a broader enumeration playbook, potentially indicating malicious reconnaissance efforts. The rule leverages Microsoft Graph Activity Logs ingested into `logs-azure.graphactivitylogs-*`.

## Attack Chain

1.  Attacker gains unauthorized access to a user account or leverages a compromised application with delegated permissions.
2.  The attacker or compromised application initiates a series of Microsoft Graph API requests using a delegated user token (client_auth_method 0).
3.  The requests target high-value Graph endpoints related to role management, cross-tenant relationships, mailbox settings, contacts, and organization metadata.
4.  The requests are classified into categories such as role_discovery, cross_tenant_recon, mailbox_recon, contact_harvesting, and org_and_licensing_recon based on the accessed URL paths.
5.  The system aggregates the API requests based on user principal object ID, source IP, session ID (c_sid), and tenant ID.
6.  The rule identifies instances where at least four distinct recon categories are accessed within a short time frame (60 seconds), exceeding a threshold of 20 total high-value calls.
7.  The system flags this behavior as a potential reconnaissance burst, indicating a broad enumeration attempt.
8.  The attacker gains insights into the organization's structure, roles, user information, and other sensitive data, facilitating further malicious activities such as privilege escalation or data exfiltration.

## Impact

Successful reconnaissance can provide attackers with valuable information about an organization's cloud environment, including user roles, relationships with other tenants, mailbox configurations, contact lists, and licensing details. This information can be used to facilitate privilege escalation, data theft, or other malicious activities. The scope of the impact depends on the level of access granted to the compromised user or application and the sensitivity of the data exposed through the Graph API.

## Recommendation

*   Deploy the Sigma rule `Detect Microsoft Graph Multi-Category Reconnaissance Burst` to your SIEM and tune the threshold (`Esql.distinct_categories >= 4 and Esql.total_high_value_calls >= 20`) and path lists for your tenant, to reduce false positives.
*   Review the `Esql.categories` and `Esql.sample_paths` fields in the alert to understand which Graph endpoints were accessed and whether they align with the expected application behavior.
*   Validate `azure.graphactivitylogs.properties.app_id` and `user_agent.original` against approved applications.
*   Correlate with Entra ID sign-in logs for the same user and session to investigate MFA, conditional access, and token issuance context.
*   Check whether `failed_calls` indicates probing or permission errors, which could indicate a more targeted attack.
*   Revoke refresh tokens for the user, disable or restrict the application consent, and reset credentials per policy if malicious activity is confirmed (see rule `Microsoft Graph Multi-Category Reconnaissance Burst`).
*   Add conditional access or block rules for high-risk Graph patterns to prevent future reconnaissance attempts.
