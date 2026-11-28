---
brief_id: brief-2026-11-28-ad-replication-traffic
event_id: brief-2026-11-28-ad-replication-traffic
revision: 1
activity_at: "2026-11-28T20:41:47Z"
title: 'Microsoft Active Directory: Unauthorized replication traffic detection'
slug: 2026-11-ad-replication-traffic
description: The detection of Active Directory replication traffic originating from non-domain controller endpoints may indicate unauthorized use of DRSR protocols for credential theft or domain persistence.
date: "2026-11-28T20:41:47Z"
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
qa_status:
  verdict: pass
  validation_status: Detection logic needs environment-specific tuning to filter legitimate domain controller traffic.
tags:
  - network
  - active-directory
  - persistence
  - credential-access
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.006
    technique_name: DCSync
    evidence: Detection of such traffic from other sources may indicate malicious activities like DCSync or DCShadow, which are used for credential dumping.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1207
    technique_name: Rogue Domain Controller
    evidence: Detection of such traffic from other sources may indicate malicious activities like DCSync or DCShadow, which are used for credential dumping.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/network/windows_ad_replication_service_traffic.yml
  - https://adsecurity.org/?p=1729
  - https://attack.mitre.org/techniques/T1003/006/
  - https://attack.mitre.org/techniques/T1207/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify non-domain controller assets generating traffic via DRSR, ms-dc-replication, or ad drs applications.
      technique_id: T1003.006
      data_needed:
        - Application-aware firewall logs
        - Proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The analytic identifies unexpected Active Directory replication traffic from non-domain controller sources.
  mitigation_plan:
    - priority: short_term
      action: Categorize and whitelist all authorized domain controllers in network monitoring assets to eliminate false positives.
      owner: IT Operations
      addresses: Active Directory replication integrity
      evidence: To successfully implement this search, you need to be ingesting application aware firewall or proxy logs into the Network Datamodel.
---

## Overview

Active Directory replication traffic, facilitated by the Directory Replication Service Remote (DRSR) protocol, is strictly intended for communication between domain controllers. The appearance of this traffic originating from endpoints other than known domain controllers is anomalous. Such activity is associated with adversarial techniques used to exfiltrate sensitive credentials or manipulate domain objects, specifically targeting the Active Directory infrastructure.

## Impact

If unauthorized replication is confirmed, it may indicate that an attacker has achieved sufficient privilege to perform credential harvesting via DCSync or domain persistence via DCShadow. This could lead to full domain compromise and unauthorized access to protected resources.

## Recommendation

Security teams should identify and document all legitimate domain controller IP addresses to reduce false positives. Implement monitoring for network traffic using application-aware firewalls or proxies to identify the 'ms-dc-replication', 'drsr', or 'ad drs' applications. Any traffic matching these signatures originating from an unauthorized source should be investigated immediately as a potential security incident.
