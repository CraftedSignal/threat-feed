---
title: 'CVE-2026-44752: SAP NetWeaver Application Server Java Cross-Site Scripting Vulnerability'
slug: 2026-07-sap-netweaver-xss
description: An unauthenticated attacker can exploit a cross-site scripting (XSS) vulnerability (CVE-2026-44752) in SAP NetWeaver Application Server Java by injecting malicious JavaScript through crafted URLs, leading to client-side script execution, access to sensitive session information, and modification of non-sensitive data, resulting in high confidentiality impact and low integrity impact.
date: "2026-07-14T01:21:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - sap
  - java
  - web-vulnerability
vendors:
  - SAP SE
products:
  - SAP NetWeaver Application Server Java (Configuration Wizard)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: When a victim accesses such a URL, the script executes in the user's browser
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: inject malicious JavaScript through crafted URLs. When a victim accesses such a URL, the script executes in the user's browser
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: allowing the attacker to access sensitive session information
    confidence_band: high
cves:
  - id: CVE-2026-44752
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44752
  - https://me.sap.com/notes/3748227
  - https://url.sap/sapsecuritypatchday
---

A critical client-side cross-site scripting (XSS) vulnerability, identified as CVE-2026-44752, has been discovered in SAP NetWeaver Application Server Java, specifically affecting Configuration Wizard (LMCTC 7.50). This vulnerability allows an unauthenticated attacker to inject arbitrary malicious JavaScript code into a crafted URL. When a victim accesses this malicious URL, the embedded script executes within their browser in the context of the vulnerable SAP application. This client-side execution grants the attacker the ability to access and potentially exfiltrate sensitive session-related information, such as cookies or session tokens, and to modify non-sensitive data displayed to the user. The exploitation leads to a high impact on confidentiality and a low impact on integrity, with no impact on the availability of the application.

## Attack Chain

1. **Malicious URL Crafting**: An unauthenticated attacker identifies a vulnerable SAP NetWeaver Application Server Java instance that improperly sanitizes URL input. The attacker crafts a malicious URL containing injected JavaScript code designed to perform actions within the victim's browser.
2. **Victim Enticement**: The attacker distributes the crafted URL to a potential victim, typically employing social engineering tactics such as phishing emails, instant messages, or compromised websites, to persuade the victim to click the malicious link.
3. **Client-Side Request**: Upon clicking the link, the victim's web browser sends an HTTP request containing the crafted URL to the vulnerable SAP NetWeaver Application Server Java.
4. **Vulnerable Server Response**: The SAP NetWeaver Application Server Java, due to CVE-2026-44752, processes the crafted URL and incorporates the attacker's malicious JavaScript directly into the HTML response without adequate sanitization.
5. **Malicious Script Execution**: The victim's web browser receives the server's response and executes the embedded malicious JavaScript within the security context of the legitimate SAP NetWeaver Application Server Java domain.
6. **Session Information Exfiltration**: The executed JavaScript accesses and exfiltrates sensitive session information, such as authentication cookies, session tokens, or other client-side credentials, back to an attacker-controlled server.
7. **Impersonation and Data Manipulation**: The attacker utilizes the stolen session information to hijack the victim's session, impersonate the victim within the SAP application, or manipulate non-sensitive data displayed in the victim's browser, potentially leading to unauthorized actions.

## Impact

Successful exploitation of CVE-2026-44752 allows an attacker to compromise the confidentiality of user sessions by stealing sensitive data like authentication tokens or cookies. This could lead to unauthorized access to the victim's SAP application session. While the integrity impact is described as low, an attacker can modify non-sensitive data displayed in the victim's browser, which could be used for further deception or targeted attacks. There is no direct impact on the availability of the SAP NetWeaver application itself. The lack of authentication required for exploitation makes this a significant risk.

## Recommendation

* Patch CVE-2026-44752 on all affected SAP NetWeaver Application Server Java instances immediately by applying the updates referenced in SAP Security Note 3748227.
* Implement robust content security policies (CSPs) on web servers hosting SAP NetWeaver to mitigate client-side script injection risks, even if server-side sanitization fails.
* Educate users on identifying and avoiding suspicious URLs and phishing attempts to prevent them from accessing crafted malicious links.
