---
title: City-Forum Campaign Targeting Salesforce and ServiceNow Guest Access
slug: 2026-08-city-forum-attacks
description: An unidentified threat actor is leveraging a custom multi-platform toolset to exploit misconfigured guest user permissions in Salesforce and ServiceNow, performing high-volume data enumeration and exfiltration.
date: "2026-08-12T13:47:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - data-exfiltration
  - cloud-security
  - reconnaissance
  - guest-access-abuse
vendors:
  - Salesforce
  - ServiceNow
products:
  - Salesforce Aura
  - Salesforce LWR
  - ServiceNow Service Portal
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Researchers observed the novel campaign exploiting unauthenticated guest access to quietly enumerate and exfiltrate exposed data from both platforms.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: The campaign uses a single machine... The exfiltration is not noisy – it is high volume but protocol-legitimate.
    confidence_band: high
references:
  - https://www.securityweek.com/stealthy-city-forum-attacks-target-salesforce-and-servicenow-with-custom-toolset/
iocs:
  - type: ip
    value: 158.220.87.79
  - type: domain
    value: city-forum.com
ioc_counts:
  domain: 1
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Security Architecture
  immediate_actions:
    - action: Block IP 158.220.87.79 and domain city-forum.com at egress points.
      owner: SOC
      due: 24h
      evidence: Source identifies this as the long-standing campaign infrastructure.
  mitigation_plan:
    - priority: immediate
      action: Audit Salesforce and ServiceNow guest user permissions to remove public access to sensitive records.
      owner: Security Architecture
      addresses: Guest user configuration
      evidence: Source notes that if the guest can read a record, so can anyone on the internet.
---

The 'City-Forum' campaign is a sophisticated, stealthy operation targeting enterprise environments by abusing exposed Guest User access within Salesforce and ServiceNow. First reported in August 2026, the campaign employs a custom Go-based multi-platform toolset to enumerate data through Salesforce Aura, Salesforce LWR implementations (via GraphQL), and undocumented ServiceNow Service Portal search endpoints. 

Unlike previous campaigns such as the one attributed to ShinyHunters, City-Forum is notable for its persistence and reliance on a single, long-standing IP address (158.220.87.79) that has remained active since March 2025. The attack focuses on protocol-legitimate traffic to minimize detection by traditional security tools. By exploiting the inherent permissions assigned to Guest Users, the actor systematically scrapes sensitive information that site owners have unintentionally exposed to anonymous users. The campaign primarily targets telecommunications, financial services, enterprise software vendors, and public-sector portals, with some instances logging over 560,000 enumeration events.

## Attack Chain

1. Attacker conducts reconnaissance to identify Salesforce Aura/LWR instances and ServiceNow portals with publicly accessible guest endpoints.
2. Attacker interacts with Salesforce Aura surfaces, utilizing the UI-API to enumerate records accessible to unauthenticated guest profiles.
3. Attacker interacts with Salesforce LWR sites, leveraging GraphQL queries to extract structured data in an unauthenticated context.
4. Attacker targets undocumented ServiceNow search endpoints on the Service Portal, systematically iterating through queries.
5. Attacker monitors response sizes from the ServiceNow search endpoint to identify and filter queries that returned meaningful content versus baseline empty results.
6. Attacker exfiltrates identified data through high-volume, protocol-legitimate requests directed to the static C2 infrastructure.
7. Attacker maintains persistent connectivity through a single IP address to evade detection systems relying on infrastructure rotation or domain flux.

## Impact

The campaign results in unauthorized exposure and exfiltration of sensitive information, including customer records, financial data, and proprietary enterprise details. The impact is primarily driven by the misconfiguration of guest user sharing rules and permissions, allowing anonymous internet access to sensitive records. While no direct breach of the Salesforce or ServiceNow platforms themselves has been observed, thousands of individual customer instances are potentially exposed, with some targets experiencing over half a million unauthorized data retrieval events.

## Recommendation

Prioritized, concrete actions for detection and remediation:
- Audit and restrict Guest User permissions in Salesforce Experience Cloud, ensuring no sensitive data is exposed to unauthenticated anonymous users.
- Disable 'self-registration' features in Salesforce instances to prevent Guest Users from upgrading their privileges to authenticated user sessions.
- Review ServiceNow Service Portal search configurations and apply appropriate ACLs to ensure undocumented search endpoints are not accessible to public guest users.
- Block the IP address 158.220.87.79 and the domain city-forum.com at the network perimeter, as these have been associated with long-term scanning and data retrieval.
- Implement monitoring for unusually high volumes of search queries or UI-API/GraphQL requests originating from unauthenticated sessions in your Salesforce and ServiceNow environments.
