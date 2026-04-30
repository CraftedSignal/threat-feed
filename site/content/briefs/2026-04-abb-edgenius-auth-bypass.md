---
title: ABB Edgenius Management Portal Authentication Bypass Vulnerability
slug: 2026-04-abb-edgenius-auth-bypass
description: An authentication bypass vulnerability in ABB Edgenius Management Portal versions 3.2.0.0 and 3.2.1.1 allows attackers to execute arbitrary code and modify application configurations by sending a specially crafted message to the system node.
date: "2026-04-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - abb
  - edgenius
  - authentication bypass
  - CVE-2025-10571
  - critical infrastructure
vendors:
  - ABB
products:
  - Edgenius Management Portal 3.2.0.0
  - Edgenius Management Portal 3.2.1.1
  - Ability Edgenius 3.2.2.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2025-10571
    cvss: 9.6
    epss: 0.00031
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-03
  - https://www.cve.org/CVERecord?id=CVE-2025-10571
  - https://search.abb.com/library/Download.aspx?DocumentID=7PAA022088&LanguageCode=en&DocumentPartId=&Action=Launch
  - https://psirt.abb.com/csaf/2025/7paa022088.json
rules:
  - title: Detect ABB Edgenius Management Portal Exploitation Attempt
    description: Detects network traffic patterns indicative of an attempt to exploit the authentication bypass vulnerability (CVE-2025-10571) in ABB Edgenius Management Portal.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect ABB Edgenius Management Portal Malicious Configuration Changes
    description: Detects suspicious configuration changes within the ABB Edgenius Management Portal that may indicate exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

ABB Edgenius Management Portal versions 3.2.0.0 and 3.2.1.1 are vulnerable to an authentication bypass (CVE-2025-10571). An attacker who has gained network access to a vulnerable Edgenius deployment can send a specially crafted message to the system node, bypassing authentication controls. Successful exploitation allows an attacker to install and run arbitrary code, uninstall applications, and modify the configuration of installed applications. ABB reported this vulnerability to CISA. ABB has released version 3.2.2.0 to address the vulnerability. As a mitigation, ABB advises customers to disable the Edgenius Management Portal until the upgrade can be applied.

## Attack Chain

1. The attacker gains access to the network where the Edgenius Management Portal is deployed.
2. The attacker identifies a vulnerable ABB Edgenius Management Portal instance (versions 3.2.0.0 or 3.2.1.1).
3. The attacker crafts a malicious message designed to exploit the authentication bypass vulnerability (CVE-2025-10571).
4. The attacker sends the specially crafted message to the system node of the Edgenius Management Portal.
5. The vulnerable Edgenius Management Portal improperly processes the crafted message, bypassing authentication.
6. The attacker leverages the bypassed authentication to install and execute arbitrary code on the system.
7. The attacker uninstalls applications, further compromising the system's functionality.
8. The attacker modifies the configuration of installed applications to maintain persistence and control.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain full control over the ABB Edgenius Management Portal. The attacker can install malicious software, uninstall critical applications, and modify configurations, leading to significant disruption of industrial processes, data theft, or further lateral movement within the OT network. Affected sectors include critical manufacturing and information technology, with deployments worldwide.

## Recommendation

*   Upgrade to ABB Ability Edgenius version 3.2.2.0 to remediate CVE-2025-10571, as this version contains the vendor fix.
*   Until the upgrade is applied, disable the Edgenius Management Portal to mitigate the vulnerability as recommended by ABB.
*   Minimize network exposure for all control system devices by ensuring they are not accessible from the internet, as suggested by CISA.
*   Locate control system networks and remote devices behind firewalls, isolating them from business networks per CISA recommendations.
*   Implement the Sigma rule "Detect ABB Edgenius Management Portal Exploitation Attempt" to identify potential exploitation attempts based on network traffic patterns.
