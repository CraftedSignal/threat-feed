---
title: Active Exploitation of SharePoint Deserialization Vulnerability (CVE-2026-20963)
slug: 2026-03-sharepoint-deserialization
description: CVE-2026-20963, a SharePoint deserialization vulnerability, is under active exploitation and has been added to the CISA Known Exploited Vulnerabilities (KEV) catalog, requiring immediate patching and auditing of potentially compromised data.
date: "2026-03-20T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-20963
  - sharepoint
  - deserialization
  - cisa-kev
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ryccv6/cve202620963_sharepoint_deserialization_hit_the/
  - https://www.cisa.gov/news-events/alerts/2026/03/18/cisa-adds-one-known-exploited-vulnerability-catalog-0
  - http://ktlystlabs.com/signals
rules:
  - title: Detect Suspicious Deserialization Activity in SharePoint (Generic)
    description: Detects potential exploitation attempts of deserialization vulnerabilities in SharePoint by monitoring for specific process creation events associated with deserialization processes.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Network Connection from SharePoint w3wp.exe
    description: Detects outbound network connections from SharePoint's w3wp.exe process that are not typically associated with normal SharePoint operations, potentially indicating data exfiltration after successful exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 18, 2026, CISA added CVE-2026-20963, a SharePoint deserialization vulnerability, to its Known Exploited Vulnerabilities catalog, signaling active exploitation in the wild. This vulnerability allows attackers to execute arbitrary code on affected SharePoint servers through the deserialization of untrusted data. Organizations utilizing SharePoint are urged to apply the necessary patches promptly. Beyond patching, it's crucial to conduct a thorough audit of SharePoint assets, particularly…
