---
brief_id: brief-2024-01-26-sharepoint-spinstall0-webshell
event_id: brief-2024-01-26-sharepoint-spinstall0-webshell
revision: 2
activity_at: "2026-11-20T03:11:01Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:eb3f5abfb82fc015a013bf6d6aab47cfffd2391f32c3184ad69f2d3744abe148
    summary: exploited:true; KEV CVE-2025-53770
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: SharePoint spinstall0.aspx Webshell Activity
slug: 2024-01-sharepoint-spinstall0-webshell
description: This brief describes the detection of GET requests to the spinstall0.aspx webshell, commonly deployed after exploiting CVE-2025-53770 in Microsoft SharePoint, indicating potential command execution, data exfiltration, or credential harvesting.
date: "2024-01-26T12:00:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2025-07-20T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:subscription:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YOSASASUTSUT-BLACKASH-CVE-2025-53770&utm_source=rss&utm_medium=rss
tags:
  - sharepoint
  - webshell
  - cve-2025-53770
  - t1190
  - t1505.003
  - t1552
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    subtechnique_id: T1505.003
    subtechnique_name: Web Shell
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2025-53770
    cvss: 9.8
    epss: 0.99982
    kev: true
    kev_status: "true"
references:
  - https://research.eye.security/sharepoint-under-siege/
  - https://www.cisa.gov/news-events/alerts/2025/07/20/microsoft-releases-guidance-exploitation-sharepoint-vulnerability-cve-2025-53770
  - https://msrc.microsoft.com/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770/
  - https://splunkbase.splunk.com/app/3185
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YOSASASUTSUT-BLACKASH-CVE-2025-53770&utm_source=rss&utm_medium=rss
rules:
  - title: SharePoint spinstall0.aspx Webshell GET Request
    description: Detects GET requests to the spinstall0.aspx webshell, indicating potential post-exploitation activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
      - T1552
    data_sources:
      - webserver
      - windows
  - title: SharePoint spinstall0.aspx Webshell POST Request
    description: Detects POST requests to the spinstall0.aspx webshell, indicating potential command execution.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
      - T1552
    data_sources:
      - webserver
      - windows
rules_count: 2
updates:
  - at: "2026-08-28T07:23:30Z"
    level: L2
    summary: poc_available; added CVE-2025-53770
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YOSASASUTSUT-BLACKASH-CVE-2025-53770&utm_source=rss&utm_medium=rss
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-53770
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The Microsoft SharePoint vulnerability CVE-2025-53770 allows attackers to deploy a webshell named "spinstall0.aspx" within the SharePoint layouts directory after successful exploitation via the ToolPane.aspx endpoint. This webshell serves as a backdoor, enabling attackers to execute commands, exfiltrate data, and extract sensitive information such as encryption keys and authentication tokens from the compromised SharePoint server. The presence of "spinstall0.aspx" and subsequent GET requests to it strongly indicate active post-exploitation activity, potentially leading to significant data breaches and privilege escalation within the organization. The exploitation of CVE-2025-53770 and the use of the spinstall0.aspx webshell pose a significant threat to organizations utilizing vulnerable SharePoint instances.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the SharePoint server, exploiting CVE-2025-53770 via a specially crafted request to the ToolPane.aspx endpoint.
2. **Webshell Deployment:** Successful exploitation leads to the deployment of the "spinstall0.aspx" webshell in the SharePoint layouts directory, typically located at `/_layouts/15/`.
3. **Backdoor Establishment:** The webshell acts as a persistent backdoor, allowing the attacker to execute arbitrary commands on the SharePoint server.
4. **Reconnaissance:** The attacker uses the webshell to perform reconnaissance activities, gathering information about the system, network, and user accounts.
5. **Credential Access:** The attacker attempts to extract sensitive information, such as encryption keys, authentication tokens, and stored credentials, from the compromised SharePoint server.
6. **Data Exfiltration:** The attacker uses the webshell to exfiltrate sensitive data from the SharePoint server to an external location.
7. **Lateral Movement:** The attacker leverages the compromised SharePoint server as a pivot point to move laterally within the network, targeting other systems and resources.

## Impact

Successful exploitation of CVE-2025-53770 and deployment of the spinstall0.aspx webshell can lead to complete compromise of the SharePoint server and potentially the entire network. Attackers can steal sensitive data, including confidential documents, employee credentials, and customer information. This can result in significant financial losses, reputational damage, and legal liabilities. The number of victims and the extent of the damage depend on the attacker's objectives and the security measures in place.

## Recommendation

*   Deploy the Sigma rule `SharePoint spinstall0.aspx Webshell GET Request` to detect GET requests to the spinstall0.aspx webshell.
*   Monitor web server logs for requests to URLs matching the pattern `*/_layouts/15/spinstall0.aspx*`, as indicated in the IOCs, to identify potential webshell activity.
*   Investigate any alerts generated by the Sigma rule or manual analysis of web server logs to determine the source and scope of the attack.
*   Patch CVE-2025-53770 on all SharePoint servers immediately to prevent initial exploitation.
*   Enable comprehensive logging for SharePoint web servers and ensure that all HTTP requests are being captured and forwarded to your SIEM, as described in the "How to Implement" section of the original source.
