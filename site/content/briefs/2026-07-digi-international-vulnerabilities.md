---
title: Multiple Vulnerabilities in Digi International PortServer TS and Digi One SP IA Devices
slug: 2026-07-digi-international-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-12352 (incorrect authorization) and CVE-2026-12948 (stored cross-site scripting), affect Digi International PortServer TS, Digi One SP, Digi One SP IA, and Digi One IA devices with firmware prior to 2025, allowing unauthenticated bypass, access to restricted resources, credential acquisition, and client-side script execution in critical infrastructure environments.
date: "2026-07-07T16:49:26Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ics
  - ot
  - network
  - webserver
  - vulnerability
  - authentication-bypass
  - xss
  - critical-manufacturing
  - communications
  - information-technology
  - transportation-systems
vendors:
  - Digi International
products:
  - PortServer TS (<Firmware_2025)
  - Digi One SP (<Firmware_2025)
  - Digi One SP IA (<Firmware_2025)
  - Digi One IA (<Firmware_2025)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an unauthenticated actor to bypass authentication and gain access to restricted resources on the device.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The script subsequently executes in the browser of a user who views the affected pages.
    confidence_band: high
cves:
  - id: CVE-2026-12352
    cvss: 5.9
  - id: CVE-2026-12948
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-188-07
  - https://www.cve.org/CVERecord?id=CVE-2026-12352
  - https://www.cve.org/CVERecord?id=CVE-2026-12948
---

This CISA advisory details multiple vulnerabilities, CVE-2026-12352 and CVE-2026-12948, affecting Digi International PortServer TS, Digi One SP, Digi One SP IA, and Digi One IA devices with firmware versions prior to 2025. An unauthenticated attacker can exploit CVE-2026-12352, an incorrect authorization vulnerability, to bypass authentication on the web management interface and gain access to restricted resources, potentially leading to credential acquisition. CVE-2026-12948 is a stored cross-site scripting (XSS) vulnerability that allows a remote, authenticated administrator to inject malicious scripts into system configuration fields. These scripts then execute in the browser of any user viewing the affected pages. The vulnerabilities pose a significant risk to critical infrastructure sectors including Manufacturing, Communications, Information Technology, and Transportation Systems, with devices deployed worldwide. While no active exploitation has been reported, successful attacks could lead to unauthorized control, data theft, and further compromise of operational technology environments.

## Attack Chain

1.  **Initial Access via Web Interface**: An unauthenticated attacker targets the web management interface of a vulnerable Digi International PortServer TS, Digi One SP, Digi One SP IA, or Digi One IA device.
2.  **Authentication Bypass (CVE-2026-12352)**: The attacker exploits the incorrect authorization vulnerability (CVE-2026-12352) to bypass the device's authentication mechanisms.
3.  **Access Restricted Resources**: Upon successful bypass, the attacker gains unauthorized access to restricted administrative resources and potentially sensitive configuration or operational data on the device.
4.  **Credential Acquisition**: Through access to restricted resources (or other means), the attacker obtains valid administrative credentials for the device.
5.  **Malicious Script Injection (CVE-2026-12948)**: As an authenticated administrator, the attacker injects malicious scripts (e.g., JavaScript) into system configuration fields through the web management interface, leveraging the stored XSS vulnerability (CVE-2026-12948).
6.  **Client-Side Script Execution**: A legitimate user, such as an IT or OT operator, views the affected administrative web pages, causing the injected malicious script to execute within their browser session.
7.  **Browser Session Compromise**: The executed script allows the attacker to steal the legitimate user's session cookies, impersonate the user, or potentially redirect them to malicious sites for further credential phishing.
8.  **Further Device Control or Data Exfiltration**: Leveraging the compromised session or stolen credentials, the attacker could perform unauthorized configuration changes, exfiltrate sensitive device data, or maintain persistence within the OT network segment.

## Impact

Successful exploitation of these vulnerabilities could lead to significant operational disruptions and security breaches within critical infrastructure sectors globally. An unauthenticated bypass (CVE-2026-12352) grants attackers access to restricted device resources, allowing for potential manipulation or theft of sensitive operational technology data and administrative credentials. The stored cross-site scripting (CVE-2026-12948) further enables attackers to compromise legitimate user browser sessions, potentially leading to additional credential theft or unauthorized actions in the browser context. Affected devices are deployed worldwide across Critical Manufacturing, Communications, Information Technology, and Transportation Systems. Digi International will not provide firmware fixes for CVE-2026-12948 for products nearing end-of-life, increasing long-term risk for organizations unable to upgrade.

## Recommendation

*   Upgrade affected Digi International devices to Digi Connect EZ or Digi Connect EZ TS as a long-term solution recommended by the vendor for CVE-2026-12352 and CVE-2026-12948.
*   For Digi PortServer TS, enable HTTPS on the web server to mitigate exploitation of CVE-2026-12352 and CVE-2026-12948.
*   For Digi One SP / Digi One SP IA / Digi One IA, disable the web server when not actively used for configuration to mitigate CVE-2026-12352 and CVE-2026-12948.
*   Restrict access to the web management interface of affected devices via a firewall or VPN as a compensating control for CVE-2026-12352 and CVE-2026-12948.
*   Safeguard administrator credentials, as exploitation of CVE-2026-12948 requires authenticated administrator access for script injection.
*   Deploy affected devices on trusted network segments, ensuring they are not exposed to untrusted or public networks, as a general recommended practice for all vulnerabilities discussed.
