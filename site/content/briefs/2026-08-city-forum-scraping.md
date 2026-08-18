---
title: City Forum Campaign Scraping Salesforce and ServiceNow Portals
slug: 2026-08-city-forum-scraping
description: A persistent threat actor is utilizing a single VPS infrastructure to perform unauthorized data scraping from Salesforce and ServiceNow guest portals by exploiting over-privileged guest account permissions.
date: "2026-08-18T11:50:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Salesforce
  - ServiceNow
products:
  - Salesforce Experience Cloud
  - ServiceNow Service Portal
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1595.002
    technique_name: 'Vulnerability Scanning: Client-side Scanning'
    evidence: Most known attackers in this space lean on Salesforce's older Aura framework, sending high volumes of guest requests to enumerate objects and page through records.
    confidence_band: high
references:
  - https://thehackernews.com/2026/08/one-attacker-has-scraped-both.html
iocs:
  - type: ip
    value: 158.220.87.79
ioc_counts:
  ip: 1
rules:
  - title: Detect City Forum Campaign Scraping Activity
    description: Detects potential scraping activity by the City Forum campaign using the identified Go-http-client user agent against web portals.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1595.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block IP 158.220.87.79 at the corporate firewall.
      owner: SOC
      due: 1h
      evidence: Source explicitly identifies this as the primary attacker infrastructure.
  mitigation_plan:
    - priority: immediate
      action: Review Salesforce and ServiceNow guest profile permissions.
      owner: IT Operations
      addresses: Over-privileged guest identities
      evidence: Source identifies persistent guest identities as the core vulnerability.
---

The 'City Forum' campaign, identified by researchers at Reco, involves a persistent threat actor systematically scraping sensitive records from Salesforce and ServiceNow customer portals since at least March 2025. The activity originates from a single server (158.220.87.79) hosted on a Contabo VPS. The attacker utilizes a custom-compiled program written in Go that relies on the 'Go-http-client' user agent to interact with portal APIs. Targets identified span multiple sectors, including telecommunications, financial services, enterprise software vendors, and public sector organizations. 

Unlike previous Salesforce-focused guest access abuse that primarily leveraged the Aura framework, this campaign demonstrates a more advanced capability by targeting newer Lightning Web Runtime (LWR) sites via the UI-API, iterating through versions v56.0 to v66.0. Additionally, the actor interacts with the ServiceNow Service Portal search endpoint (/api/now/sp/search) to extract data. The vulnerability is fundamentally rooted in the configuration of persistent 'guest' identities which, if not properly restricted, allow unauthenticated access to data objects that the organization intended to remain private.

## Attack Chain

1. Attacker reconnaissance identifies Salesforce Experience Cloud and ServiceNow portals with misconfigured or over-privileged guest identities.
2. Attacker initiates automated requests from the infrastructure 158.220.87.79 using a custom Go-based scraper.
3. For Salesforce targets, the attacker enumerates objects via the Aura framework (legacy) or the Lightning Web Runtime UI-API (v56.0-v66.0).
4. For ServiceNow targets, the attacker sends automated POST requests to the /api/now/sp/search endpoint to retrieve Knowledge Base or internal records.
5. The target application processes the requests under the context of the persistent 'guest' user, which lacks sufficient object-level security restrictions.
6. The attacker iterates through API versions and page enumerations to systematically scrape records.
7. Extracted data is exfiltrated to the attacker's primary infrastructure for further processing.

## Impact

The campaign results in the unauthorized mass exfiltration of proprietary or sensitive business data from affected organizations. Victims include enterprises across the financial, telecommunications, and public sectors. The specific volume of impact is demonstrated by reports of single targets logging over 560,000 malicious events, indicating significant data exposure risks for companies relying on default guest account configurations in their public-facing SaaS portals.

## Recommendation

Prioritized actions for security and IT teams:
- Block the IP 158.220.87.79 at the network perimeter or WAF to immediately mitigate active scraping from this infrastructure.
- Implement monitoring for the 'Go-http-client' user agent within Salesforce AuraRequest and Sites logs to identify automated scraping attempts.
- Audit ServiceNow transaction logs (syslog_transaction) for requests originating from external IPs targeting the /api/now/sp/search endpoint.
- Review and restrict Salesforce guest profile object/field-level permissions to the minimum necessary for public site functionality.
- Disable self-registration features on Salesforce Communities where not explicitly required by business process.
- Audit ServiceNow Knowledge Base read criteria to ensure that public-facing portal search results do not include non-public records.
