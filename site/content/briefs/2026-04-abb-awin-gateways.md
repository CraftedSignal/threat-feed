---
title: ABB AWIN Gateway Vulnerabilities Allow Remote Reboot and Information Disclosure
slug: 2026-04-abb-awin-gateways
description: Multiple vulnerabilities in ABB AWIN Gateways allow an unauthenticated attacker to remotely reboot the device (CVE-2025-13778) or disclose sensitive system configuration details (CVE-2025-13777, CVE-2025-13779).
date: "2026-04-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - vulnerability
  - industrial_control_systems
vendors:
  - ABB
products:
  - ABB AWIN Firmware (2.0-0)
  - ABB AWIN Firmware (2.0-1)
  - ABB AWIN Firmware (1.2-0)
  - ABB AWIN Firmware (1.2-1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2025-13778
    cvss: 6.5
    epss: 0.00034
  - id: CVE-2025-13777
    cvss: 8.3
    epss: 0.00029
  - id: CVE-2025-13779
    cvss: 8.3
    epss: 0.00027
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05
  - https://www.cve.org/CVERecord?id=CVE-2025-13777
  - https://www.cve.org/CVERecord?id=CVE-2025-13778
  - https://www.cve.org/CVERecord?id=CVE-2025-13779
  - https://search.abb.com/library/Download.aspx?DocumentID=4JNO000329&LanguageCode=en&DocumentPartId=&Action=Launch
  - https://psirt.abb.com/csaf/2026/4jno000329.json
rules:
  - title: Detect Unauthenticated Requests to ABB AWIN Gateways
    description: Detects unauthenticated requests to ABB AWIN Gateways which may indicate an attempt to exploit CVE-2025-13777, CVE-2025-13778 or CVE-2025-13779.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential ABB AWIN Gateway Reboot Attempt via Web Request
    description: Detects GET requests to the '/reboot' endpoint of an ABB AWIN Gateway, potentially indicating an attempt to exploit CVE-2025-13778.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Potential ABB AWIN Gateway Configuration Disclosure via Web Request
    description: Detects GET requests to the '/getConfig' endpoint of an ABB AWIN Gateway, potentially indicating an attempt to exploit CVE-2025-13777 or CVE-2025-13779.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1005
    data_sources:
      - webserver
      - linux
rules_count: 3
---

ABB AWIN Gateways are vulnerable to multiple security flaws that could be exploited by unauthenticated attackers. These vulnerabilities impact ABB AWIN GW100 rev.2 and GW120 devices running specific firmware versions (2.0-0, 2.0-1, 1.2-0, and 1.2-1). Successful exploitation of these vulnerabilities can lead to a denial-of-service condition via remote reboot or the disclosure of sensitive system configuration information, potentially compromising critical manufacturing infrastructure. The vulnerabilities stem from authentication bypass and missing authentication for critical functions. Firmware versions 2.1-0 for GW100 rev. 2 and 2.0-0 for GW120 address these issues.

## Attack Chain

1.  Attacker identifies an exposed ABB AWIN Gateway on a network (likely adjacent network).
2.  Attacker sends a crafted, unauthenticated request to the targeted gateway to trigger CVE-2025-13778.
3.  The ABB AWIN Gateway processes the request without authentication.
4.  The gateway initiates a reboot, causing a denial-of-service condition.
5.  Alternatively, the attacker sends another crafted, unauthenticated request to trigger CVE-2025-13777 or CVE-2025-13779.
6.  The gateway responds to the request, disclosing sensitive system configuration information.
7.  The attacker uses the disclosed information to gain further insight into the network and potentially plan further attacks.

## Impact

Successful exploitation of these vulnerabilities can have significant impacts, particularly within critical manufacturing sectors where these gateways are deployed. A remote reboot (CVE-2025-13778) can disrupt operations, leading to production downtime and financial losses. Disclosure of sensitive system configuration information (CVE-2025-13777, CVE-2025-13779) can provide attackers with valuable insights, enabling them to plan further attacks, such as gaining unauthorized access to other systems or manipulating industrial processes.

## Recommendation

*   Immediately patch affected ABB AWIN Gateways to the fixed versions (ABB AWIN Firmware 2.1-0 installed on ABB AWIN GW100 rev. 2 and ABB AWIN Firmware 2.0-0 installed on ABB AWIN GW120) as recommended in the ABB PSIRT security advisory 4JNO000329.
*   Minimize network exposure for all control system devices and systems, ensuring they are not accessible from the internet as recommended by CISA.
*   Monitor network traffic for unauthenticated requests to ABB AWIN Gateways, specifically targeting endpoints related to system reboot or configuration retrieval using the provided Sigma rule.
