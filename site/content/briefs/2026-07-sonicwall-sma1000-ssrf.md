---
title: SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability (CVE-2026-15409)
slug: 2026-07-sonicwall-sma1000-ssrf
description: A critical server-side request forgery (SSRF) vulnerability, identified as CVE-2026-15409, exists in SonicWall SMA1000 Appliances, allowing a remote, unauthenticated attacker to force the appliance to make requests to arbitrary internal or external locations, potentially leading to information disclosure or access to restricted network services.
date: "2026-07-14T19:45:40Z"
lastmod: "2026-07-15T16:51:13Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.4.3-03245:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.4.3-03387:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.4.3-03434:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.5.0-02283:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.5.0-02624:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.5.0-02800:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.4.3-03245:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.4.3-03387:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.4.3-03434:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.5.0-02283:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.5.0-02624:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.5.0-02800:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.4.3-03245:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.4.3-03387:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.4.3-03434:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.5.0-02283:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.5.0-02624:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.5.0-02800:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=A8BC7F65-9698-5009-B9D5-F2E8F463F7AE&utm_source=rss&utm_medium=rss
tags:
  - ssrf
  - vulnerability
  - cisa-kev
  - remote-code-execution
  - network-appliance
vendors:
  - SonicWall
products:
  - SMA1000 Appliances
  - SMA1000 (models 6210, 7210, 8200v) < 12.4.3-03453
  - SMA1000 (models 6210, 7210, 8200v) < 12.5.0-02835
  - Sonicwall Sma6210_Firmware
  - SonicWall SMA 1000
  - SonicWall SMA1000 Series (6210, 7210, 8200v) < 12.4.3-03453
  - SonicWall SMA1000 Series (6210, 7210, 8200v) < 12.5.0-02835
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: a remote unauthenticated attacker to potentially cause the appliance to make requests to unintended location
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: This flaw could be exploited by a remote, unauthenticated attacker to force the appliance to make requests to unintended internal or external locations, potentially leading to information disclosure or access to restricted services.
    confidence_band: high
cves:
  - id: CVE-2026-15409
    cvss: 10
    epss: 0.01404
  - id: CVE-2026-15410
    cvss: 7.2
    epss: 0.01647
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-15409
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15409
  - https://www.cve.org/CVERecord?id=CVE-2026-15410
  - https://www.securityweek.com/sonicwall-issues-urgent-sma-patch-warning-for-two-zero-day-exploits/
  - https://sploitus.com/exploit?id=A8BC7F65-9698-5009-B9D5-F2E8F463F7AE&utm_source=rss&utm_medium=rss
  - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=A8BC7F65-9698-5009-B9D5-F2E8F463F7AE
  - type: url
    value: https://github.com/remmons-r7/rapid7-CVE-2026-15409
  - type: path
    value: /wsproxy
  - type: port
    value: "1050"
  - type: port
    value: "8188"
  - type: file_path
    value: ../../../../../tmp/1234.sh
ioc_counts:
  file_path: 1
  path: 1
  port: 2
  url: 2
updates:
  - at: "2026-07-14T19:46:01Z"
    level: L2
    summary: added CVE-2026-15410
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-15410
  - at: "2026-07-15T05:22:26Z"
    level: L2
    summary: added CVE-2026-15409
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/sonicwall-issues-urgent-sma-patch-warning-for-two-zero-day-exploits/
  - at: "2026-07-15T16:02:05Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=A8BC7F65-9698-5009-B9D5-F2E8F463F7AE&utm_source=rss&utm_medium=rss
  - at: "2026-07-15T16:51:13Z"
    level: L1
    summary: new IOCs
    sources:
      - rapid7
    source_urls:
      - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410
---

SonicWall SMA1000 Appliances are affected by CVE-2026-15409, a server-side request forgery (SSRF) vulnerability. This flaw enables a remote, unauthenticated attacker to manipulate the appliance into initiating requests to arbitrary internal or external network locations. The vulnerability, first disclosed on July 14, 2026, has been added to CISA's Known Exploited Vulnerabilities (KEV) catalog, signifying active in-the-wild exploitation. Exploitation of this vulnerability could lead to sensitive information disclosure, allow an attacker to bypass network segmentation, or gain unauthorized access to internal services. Organizations utilizing affected SMA1000 Appliances are urged to apply mitigations promptly to prevent potential compromise of their infrastructure. CISA's directive emphasizes the critical need for immediate action for government agencies and recommends similar urgency for private sector entities.

## Attack Chain

1. **Reconnaissance and Vulnerability Identification**: An unauthenticated attacker identifies an internet-exposed SonicWall SMA1000 appliance and becomes aware of the Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-15409).
2. **Payload Crafting**: The attacker crafts a malicious HTTP request containing a specially formed URL or URI parameter that the vulnerable appliance will process without proper validation. This crafted URL targets an internal network resource (e.g., administrative interface, database, internal API) or an external service controlled by the attacker.
3. **Exploitation Request**: The attacker sends the crafted HTTP request to the vulnerable SonicWall SMA1000 appliance.
4. **Appliance Initiates Unintended Request**: The SMA1000 appliance, due to the SSRF vulnerability, processes the attacker's input and, acting as a proxy, initiates a request to the attacker-specified internal or external location from its trusted network context.
5. **Information Disclosure**: The appliance forwards the response from the unintended internal or external service back to the attacker. This response may contain sensitive information such as internal network topology, credentials, configuration data, or other proprietary details.
6. **Further Access/Action**: The attacker analyzes the disclosed information to identify additional vulnerabilities, gain access to other internal systems, or trigger actions on internal services (e.g., port scanning, credential harvesting, or bypassing firewall rules).

## Impact

Successful exploitation of CVE-2026-15409 in SonicWall SMA1000 Appliances can result in significant information disclosure, potentially exposing sensitive internal network details, configurations, or credentials. Attackers can leverage the appliance's trusted network position to bypass network segmentation, access internal systems, or interact with services that would otherwise be inaccessible from the external network. While specific victim counts and targeted sectors are not detailed in the available public information, the inclusion of this vulnerability in CISA's KEV catalog indicates observed in-the-wild exploitation, suggesting active campaigns by threat actors. The potential for unauthorized access and data compromise poses a high risk to organizations relying on these appliances.

## Recommendation

* Apply mitigations to your SonicWall SMA1000 Appliances immediately in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk guidance.
* If mitigations for CVE-2026-15409 are unavailable, discontinue use of the affected product as recommended by CISA.
* Evaluate each asset's internet exposure and ensure adherence to BOD 26-04 patching guidelines, as detailed in the CISA guidance available at `https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk`.
* Review CISA’s “Forensics Triage Requirements” at `https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk` to prepare for potential compromise.
