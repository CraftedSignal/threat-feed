---
title: Kieback & Peter DDC Building Controllers Cross-Site Scripting Vulnerability (CVE-2026-4293)
slug: 2026-05-kieback-peter-xss
description: A cross-site scripting vulnerability, CVE-2026-4293, exists in multiple Kieback & Peter DDC Building Controllers that could allow an attacker to take control of the victim's browser.
date: "2026-05-19T16:15:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - vulnerability
  - building-automation
vendors:
  - Kieback & Peter
products:
  - DDC4002
  - DDC4100
  - DDC4200
  - DDC4200-L
  - DDC4400
  - DDC4002e
  - DDC4200e
  - DDC4400e
  - DDC4020e
  - DDC4040e
  - DDC520
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-05
  - https://www.cve.org/CVERecord?id=CVE-2026-4293
  - https://cwe.mitre.org/data/definitions/79.html
rules:
  - title: Detect CVE-2026-4293 Exploitation Attempt via URI Parameter
    description: Detects CVE-2026-4293 exploitation attempt — Suspicious URI parameter values indicative of XSS attacks against Kieback & Peter DDC Building Controllers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-4293 Exploitation Attempt via URI Stem
    description: Detects CVE-2026-4293 exploitation attempt — Suspicious URI stem values indicative of XSS attacks against Kieback & Peter DDC Building Controllers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A cross-site scripting (XSS) vulnerability, identified as CVE-2026-4293, affects multiple versions of Kieback & Peter DDC Building Controllers. Specifically, versions DDC4002, DDC4100, DDC4200, DDC4200-L, and DDC4400, all at or below version 1.12.14, as well as DDC4002e, DDC4200e, DDC4400e, DDC4020e, and DDC4040e, all at or below version 1.23.4, and DDC520 at or below version 1.24.1 are vulnerable. Successful exploitation could allow an attacker to execute arbitrary JavaScript code in the victim's browser, potentially leading to session hijacking, defacement, or redirection to malicious websites. These building controllers are deployed across critical infrastructure sectors including commercial facilities, communications, financial services, food and agriculture, government services and facilities, healthcare, and information technology across Austria, China, France, Germany, and the United Arab Emirates.

## Attack Chain

1.  Attacker identifies a vulnerable Kieback & Peter DDC Building Controller web interface accessible on the network.
2.  Attacker crafts a malicious URL containing a cross-site scripting payload. The payload is designed to execute arbitrary JavaScript within the context of the user's browser.
3.  The attacker uses social engineering to trick an authorized user into clicking the malicious link or visiting a compromised webpage embedding the malicious URL.
4.  The victim's browser sends a request to the vulnerable DDC Building Controller web interface.
5.  The DDC Building Controller fails to properly sanitize user-supplied input, and the malicious JavaScript payload is reflected back to the user's browser.
6.  The victim's browser executes the attacker's JavaScript code.
7.  The malicious JavaScript code steals the user's session cookies or credentials.
8.  The attacker uses the stolen session cookies or credentials to gain unauthorized access to the DDC Building Controller web interface and manipulate building control systems.

## Impact

Successful exploitation of the XSS vulnerability (CVE-2026-4293) in Kieback & Peter DDC Building Controllers allows an attacker to control the victim's browser. This could lead to unauthorized access to building control systems, manipulation of environmental controls (e.g., HVAC, lighting), denial of service, or further lateral movement within the affected network. Given the controllers' deployment in critical infrastructure sectors, the potential impact includes disruption of essential services, financial losses, and physical safety risks.

## Recommendation

*   Apply available firmware updates to the latest versions to patch CVE-2026-4293: DDC4002e, DDC4200e, DDC4400e, DDC4020e, DDC4040e to version 1.23.5 or newer, and DDC520 to version 1.24.2 or newer.
*   For end-of-maintenance DDC4002, DDC4100, DDC4200, DDC4200-L and DDC4400 controllers, isolate them within a strictly separate OT network, and restrict network access to the DDC web portal to trusted individuals. Disable the web portal if not required, as recommended by the vendor.
*   Implement network segmentation and firewall rules to minimize network exposure of control system devices, as mentioned in the vendor mitigation guidance.
*   Deploy the Sigma rule "Detect CVE-2026-4293 Exploitation Attempt via URI Parameter" to identify potential exploitation attempts against the vulnerable web interfaces.
*   Educate users about the risks of clicking links from untrusted sources to prevent social engineering attacks that could lead to exploitation, as recommended by the vendor.
*   Monitor web server logs for suspicious activity, such as unusual URI requests or patterns indicative of XSS attacks.
