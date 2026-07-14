---
title: Multiple Critical and High-Severity Vulnerabilities in ABB T-MAC Plus
slug: 2026-07-abb-tmac-plus-vulnerabilities
description: CISA has issued an advisory regarding critical and high-severity vulnerabilities CVE-2025-14771, CVE-2025-14772, CVE-2025-14773, and CVE-2025-14774 in ABB T-MAC Plus version 4.0-24, which could allow authenticated attackers to exfiltrate sensitive files, bypass authorization for administrative operations, execute arbitrary client-side code via cross-site scripting, or for unauthenticated attackers to cause a denial-of-service condition.
date: "2026-07-14T15:47:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:abb:t-mac_plus:4.0-24:*:*:*:*:*:*:*
tags:
  - industrial-control-systems
  - scada
  - critical-manufacturing
  - vulnerability
  - web-application
vendors:
  - ABB
products:
  - ABB T-MAC Plus 4.0-24
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: File Disclosure in ABB T-MAC Plus web application allows authenticated users to exfiltrate files containing sensitive information via crafted HTTP GET request.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Broken access controls in ABB T-MAC Plus web application allows unprivileged users to performs administrative operations
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: Stored Cross-Site Scripting (XSS) in ABB T-MAC Plus web application allows authenticated users to execute arbitrary HTML or JavaScript code on victims browser.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Insecure network protocol in ABB T-MAC Plus allows unauthenticated attackers to perform a denial-of-service (DoS) of the Card Reader service.
    confidence_band: high
cves:
  - id: CVE-2025-14771
    cvss: 9.9
    epss: 0.00347
  - id: CVE-2025-14772
    cvss: 8.8
    epss: 0.00292
  - id: CVE-2025-14773
    cvss: 8
    epss: 0.00181
  - id: CVE-2025-14774
    cvss: 7.4
    epss: 0.0018
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-195-03
---

CISA has released an advisory highlighting multiple critical and high-severity vulnerabilities affecting ABB T-MAC Plus version 4.0-24, a product widely deployed in the Critical Manufacturing sector globally. These vulnerabilities include CVE-2025-14771, a critical file disclosure flaw allowing authenticated users to exfiltrate sensitive files via crafted HTTP GET requests; CVE-2025-14772, a high-severity authorization bypass enabling unprivileged users to perform administrative operations; CVE-2025-14773, a high-severity stored cross-site scripting (XSS) vulnerability that permits authenticated users to execute arbitrary JavaScript code on a victim's browser; and CVE-2025-14774, a high-severity insecure network protocol issue that can lead to an unauthenticated denial-of-service condition for the Card Reader service. Exploitation of these vulnerabilities could lead to significant system compromise, data exfiltration, privilege escalation, or service disruption. ABB has released T-MAC Plus version 4.0-25 to address these issues, urging customers to apply the update promptly.

## Attack Chain

1. An attacker gains initial access to the ABB T-MAC Plus web application, either through legitimate but compromised credentials or by exploiting another vulnerability (e.g., an unauthenticated attacker targeting CVE-2025-14774).
2. If authenticated with low privileges, the attacker exploits CVE-2025-14772 (Authorization Bypass) by crafting specific HTTP requests to the web application that perform administrative operations typically restricted to higher-privileged users, thereby escalating their privileges.
3. With elevated or existing authenticated access, the attacker exploits CVE-2025-14771 (File Disclosure) by sending a specially crafted HTTP GET request to the web application.
4. The vulnerable web application, due to the misconfiguration or flaw in file access controls, responds with sensitive files to the attacker, leading to the exfiltration of confidential information.
5. Alternatively, an authenticated attacker exploits CVE-2025-14773 (Stored Cross-Site Scripting) by injecting malicious HTML or JavaScript code into an input field or web form within the application.
6. When another user subsequently views the compromised web page or entity, the injected malicious script executes within their browser context, potentially leading to session hijacking, credential theft, or further client-side compromise.
7. In parallel, an unauthenticated attacker could directly exploit CVE-2025-14774 by gaining physical access to a serial device and sending a specially crafted message to the ABB T-MAC Plus Card Reader service.
8. This crafted message triggers an insecure network protocol flaw, causing the Card Reader service to become unresponsive, leading to a denial-of-service (DoS) condition that requires manual intervention to restore functionality.

## Impact

The combined impact of these vulnerabilities is severe for organizations utilizing ABB T-MAC Plus version 4.0-24. Successful exploitation of CVE-2025-14771 can lead to the full compromise and exfiltration of sensitive data from the system. CVE-2025-14772 allows for privilege escalation, enabling attackers with low-level access to gain full administrative control over the application. CVE-2025-14773 exposes users to arbitrary client-side code execution, potentially leading to session hijacking, credential theft, or further compromises of client machines. Finally, CVE-2025-14774 can result in a denial-of-service for critical card reader services, disrupting operations in critical manufacturing environments where ABB T-MAC Plus is deployed. The critical CVSSv3 base score of 9.9 for CVE-2025-14771 underscores the high risk of data confidentiality, integrity, and availability compromise.

## Recommendation

* **Patch CVE-2025-14771, CVE-2025-14772, CVE-2025-14773, and CVE-2025-14774 immediately** by upgrading ABB T-MAC Plus to version 4.0-25.
* Implement the mitigation strategy for CVE-2025-14771 by ensuring File Browsing Feature is disabled and the default IIS site is removed on the IIS server hosting the ABB T-MAC Plus web application.
* Review and correctly apply privileges associated with different user roles in the ABB T-MAC Plus web application as a mitigation for CVE-2025-14772, ensuring unprivileged users cannot perform administrative operations.
* For CVE-2025-14774, restrict physical access to serial devices connected to the ABB T-MAC Plus system to prevent unauthenticated denial-of-service attacks.
