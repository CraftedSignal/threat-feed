---
title: SharePoint Sensitive Term Discovery via O365 Logs
slug: 2024-01-sharepoint-sensitive-term-discovery
description: Adversaries may search for sensitive terms within SharePoint to identify valuable data for exfiltration or further compromise, leaving traces in O365 audit logs.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sharepoint
  - discovery
  - sensitive-data
  - o365
vendors:
  - Microsoft
products:
  - SharePoint
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/o365/discovery_sharepoint_sensitive_term_search.toml
rules:
  - title: Detect SharePoint Sensitive Term Search
    description: Detects searches for sensitive terms within SharePoint based on O365 audit logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - dns_query
      - windows
  - title: Detect SharePoint Sensitive Term Search via User Agent
    description: Detects searches for sensitive terms within SharePoint based on O365 audit logs with a specific User Agent.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

While the provided document focuses on a detection rule name within the Elastic detection-rules repository on GitHub, it doesn't directly describe an active threat or campaign. The title "discovery_sharepoint_sensitive_term_search" implies a potential attack vector where malicious actors attempt to locate sensitive information stored within a SharePoint environment. The adversary would likely leverage search functionalities, leaving audit trails within Microsoft 365 (O365) logs. Successful identification of sensitive data could lead to data exfiltration, privilege escalation, or further targeted attacks. Defenders need to monitor for unusual search activity and access patterns within SharePoint to detect potential reconnaissance attempts. This highlights the importance of robust logging and monitoring within cloud-based collaboration platforms like SharePoint.

## Attack Chain

1.  The attacker gains initial access to a compromised account or through an insider threat.
2.  The attacker authenticates to the Microsoft 365 environment.
3.  The attacker begins performing searches within SharePoint, targeting potentially sensitive terms (e.g., "password," "financial," "confidential").
4.  SharePoint processes the search queries and returns results based on the attacker's permissions.
5.  Microsoft 365 logs the search activity, including the user, timestamp, and search terms used.
6.  The attacker reviews the search results and identifies documents or sites containing sensitive information.
7.  The attacker accesses and potentially downloads the sensitive documents.
8.  The attacker exfiltrates the data or uses it to further compromise the environment (e.g., privilege escalation).

## Impact

Successful discovery of sensitive terms within SharePoint could expose confidential data, intellectual property, or personally identifiable information (PII). The impact could range from reputational damage and financial losses due to regulatory fines to compromised business operations and competitive disadvantage. The number of victims depends on the scope of the targeted SharePoint environment, but even a single successful breach can have significant consequences.

## Recommendation

*   Enable and actively monitor Microsoft 365 Unified Audit Logging to capture SharePoint search activities (Attack Chain step 5).
*   Deploy the Sigma rule provided to detect suspicious searches for sensitive terms within SharePoint audit logs.
*   Implement multi-factor authentication (MFA) to mitigate the risk of compromised accounts (Attack Chain step 1).
*   Review and enforce least privilege access principles for SharePoint to limit the potential impact of a successful breach (Attack Chain step 6).
