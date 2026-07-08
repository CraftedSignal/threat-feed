---
title: 'CVE-2026-0279 PAN-OS: Multiple Cross-Site Scripting (XSS) Vulnerabilities'
slug: 2026-07-pan-os-xss
description: Palo Alto Networks has disclosed multiple low-severity cross-site scripting (XSS) vulnerabilities, CVE-2026-0279, in PAN-OS software affecting the User-ID Authentication Portal, GlobalProtect gateway/portal features, and Clientless VPN, which could allow a malicious unauthenticated user to inject and execute JavaScript in a victim's browser.
date: "2026-07-08T16:10:47Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
tags:
  - xss
  - vulnerability
  - firewall
  - network-device
  - web-application
vendors:
  - Palo Alto Networks
products:
  - PAN-OS 12.1
  - PAN-OS 11.2
  - PAN-OS 11.1
  - PAN-OS 10.2
  - Prisma Access 11.2.0
  - Prisma Access 10.2.0
  - PA-Series
  - VM-Series
  - Panorama
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Multiple cross site scripting vulnerabilities in the User-ID™ Authentication Portal (aka Captive Portal) service, GlobalProtect™ gateway/portal features and Clientless VPN of Palo Alto Networks PAN-OS® software enables a malicious unauthenticated user to store or execute malicious JavaScript payload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: enables a malicious unauthenticated user to store or execute malicious JavaScript payload.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0279
---

Palo Alto Networks has released an advisory concerning CVE-2026-0279, which identifies multiple low-severity cross-site scripting (XSS) vulnerabilities across various components of its PAN-OS software. These vulnerabilities specifically affect the User-ID™ Authentication Portal (also known as Captive Portal), GlobalProtect™ gateway/portal features, and Clientless VPN. An unauthenticated attacker could exploit these flaws to inject and store malicious JavaScript payloads, which would then execute in the context of a legitimate user's browser when they access the vulnerable component. The risk associated with this issue is significantly reduced by adhering to Palo Alto Networks' recommended best practices, which include restricting access to management interfaces and the User-ID Authentication Portal to only trusted internal IP addresses. Cloud NGFW products are not affected. Affected versions include PAN-OS 12.1 prior to 12.1.8, 11.2 prior to 11.2.13, 11.1 prior to 11.1.16, and all 10.2 versions, along with specific Prisma Access versions. No active exploitation has been reported.

## Attack Chain

1. **Vulnerability Identification**: An unauthenticated attacker identifies a vulnerable input field or parameter within the User-ID Authentication Portal, GlobalProtect gateway/portal, or Clientless VPN of an exposed PAN-OS device.
2. **Payload Crafting**: The attacker constructs a malicious JavaScript payload designed to achieve an objective such as session hijacking, credential theft, or redirection to a malicious website.
3. **Payload Injection**: The crafted JavaScript payload is injected by the attacker into the identified vulnerable component through an unauthenticated network request.
4. **Persistent Storage**: The PAN-OS application processes and stores the malicious payload, embedding it within the user-facing content of the vulnerable component.
5. **Victim Interaction**: A legitimate user accesses the compromised PAN-OS component (e.g., logs into the User-ID Authentication Portal or uses a GlobalProtect feature).
6. **Client-Side Execution**: The injected malicious JavaScript is rendered and executed by the victim's web browser as part of the legitimate PAN-OS application interface.
7. **Malicious Action**: The executed JavaScript performs its intended action, potentially leading to unauthorized access to the victim's session, exposure of sensitive information, or further client-side attacks.

## Impact

The vulnerabilities, categorized as low severity, primarily impact the confidentiality and integrity of users interacting with the affected PAN-OS portals and features. While no active exploitation has been reported, successful exploitation could lead to client-side attacks where an attacker executes malicious JavaScript within a victim's browser. This could result in session hijacking, allowing unauthorized access to the victim's user session, or credential theft if the script is designed to capture login information. The overall product confidentiality and integrity are rated as LOW, and availability is rated as NONE, indicating that the vulnerability does not directly compromise the firewall's core functions or lead to denial of service. The impact is minimized when the management interfaces and portal access are restricted to trusted internal networks, as per best practices.

## Recommendation

* Patch CVE-2026-0279 immediately by upgrading all affected PAN-OS devices and Prisma Access deployments to the specified fixed versions: PAN-OS 12.1.8 or later, PAN-OS 11.2.13 or later, PAN-OS 11.1.16 or later, or a supported fixed version for PAN-OS 10.2. Prisma Access 11.2 should be upgraded to 11.2.7-h18 or later, and Prisma Access 10.2 to 10.2.10-h39 or later.
* Implement network access restrictions to the management interface and User-ID Authentication Portal according to Palo Alto Networks' best practice deployment guidelines, ensuring access is limited to only trusted internal IP addresses.
