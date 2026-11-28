---
brief_id: brief-2026-11-28-o365-compliance-search-export
event_id: brief-2026-11-28-o365-compliance-search-export
revision: 1
activity_at: "2026-11-28T20:52:22Z"
title: O365 Compliance Content Search Exported
slug: 2026-11-o365-compliance-search-export
description: This detection monitors for the 'SearchExported' operation within the Office 365 Security and Compliance Center to identify potential data exfiltration.
date: "2026-11-28T20:52:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
    subtechnique_id: T1114.002
    subtechnique_name: Remote Email Collection
    evidence: This activity is significant because exporting search results can involve sensitive or critical organizational data, potentially leading to data exfiltration.
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/o365_compliance_content_search_exported.yml
  - https://attack.mitre.org/techniques/T1114/002/
  - https://learn.microsoft.com/en-us/purview/ediscovery-content-search-overview
  - https://learn.microsoft.com/en-us/purview/ediscovery-keyword-queries-and-search-conditions
  - https://learn.microsoft.com/en-us/purview/ediscovery-search-for-activities-in-the-audit-log
rules:
  - title: O365 Compliance Content Search Exported
    description: This detection monitors for the 'SearchExported' operation in the Office 365 Security and Compliance Center.
    platform: sigma
    severity: medium
    techniques:
      - T1114.002
    data_sources:
      - cloud
rules_count: 1
---

## Overview

The O365 Compliance Content Search Exported analytic identifies when the results of a content search within the Office 365 Security and Compliance Center are exported. This detection uses the SearchExported operation from the SecurityComplianceCenter workload in the o365_management_activity data source.

## Attack Chain

- The attacker initiates an export of search results from the Office 365 Security and Compliance Center.
- The operation is recorded as 'SearchExported' in the o365_management_activity logs.

## Impact

If confirmed malicious, an attacker could gain access to and exfiltrate sensitive information, posing a severe risk to the organization's data security and compliance posture.

## Recommendation

Install the Splunk Microsoft Office 365 Add-on and ingest Office 365 management activity events. Note that compliance content search exports may be executed for legitimate purposes; filter as needed.
