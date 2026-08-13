---
title: Jewelbug APT Dual-Purpose Espionage and Fraud Operations
slug: 2026-08-jewelbug-apt
description: Jewelbug, a China-linked mercenary APT, uses a custom C2 platform called XG-Web to conduct both state-sponsored espionage and large-scale cryptocurrency theft using custom backdoors and malicious browser extensions.
date: "2026-08-13T10:39:34Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Jewelbug
tags:
  - apt
  - espionage
  - credential-theft
  - malware
  - china
  - middle-east
  - southeast-asia
  - browser-security
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: Jewelbug campaigns rely on three primary, custom malware implants... AI to generate thousands of cryptocurrency... themed phishing websites.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: The most interesting item in its toolset is a browser extension called PDF Viewer... it requests every possible permission from victims and then steals their cookies, session tokens.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: There is a Windows backdoor, Antino, and a Linux backdoor, ClientKing, most often seen in cyber-espionage attacks.
    confidence_band: high
---

Jewelbug is an advanced persistent threat (APT) group characterized by researchers as a mercenary unit likely operating at the behest of Chinese state agencies. The group exhibits a unique operational model, managing both state-level cyber espionage and high-volume financial fraud from a unified custom command-and-control platform known as XG-Web. Jewelbug targets government, military, telecommunications, and industrial organizations throughout the Middle East and Southeast Asia. 

The group demonstrates high technical capability, utilizing specialized malware such as the Antino (Windows) and ClientKing (Linux) backdoors. A primary component of their arsenal is a malicious browser extension disguised as a "PDF Viewer," which is used for extensive data harvesting, including session tokens and cookies, and enabling browser-in-the-browser attacks. The group manages a vast infrastructure for cryptocurrency-themed phishing, utilizing 44 content management servers and AI-generated lures to facilitate their financial operations, while simultaneously maintaining access to high-value government networks.

## Attack Chain

1. Initial Access: The group identifies and compromises shared web hosting infrastructure or utilizes spear-phishing to gain control of target environments.
2. Persistence: The group injects malicious scripts into webmail or legitimate application login pages to intercept user interactions.
3. Credential Harvesting: Users logging into the compromised portals have their session cookies and login credentials exfiltrated directly to the XG-Web panel.
4. Delivery: The compromised session is used to present fake update prompts (e.g., Adobe Flash) to victims, which act as a delivery mechanism for the Antino backdoor or the malicious 'PDF Viewer' extension.
5. Execution: The PDF Viewer extension executes in the browser context, harvesting data and allowing for the injection of arbitrary JavaScript on visited pages.
6. Persistence: The Antino (Windows) or ClientKing (Linux) backdoors are established for long-term remote control of the host systems.
7. Exfiltration: Stolen data (email bodies, cookies, credentials) is transmitted back to the XG-Web platform for analysis and use by the group's operators.
8. Final Objective: The group realizes their objectives by exfiltrating state secrets for their intelligence sponsors or stealing cryptocurrency assets from victim accounts.

## Impact

Jewelbug has successfully compromised thousands of victims, including government agencies, military, police, and aerospace manufacturers. Observed exfiltrated data includes over 580,000 full browser cookie jars and 2,300 email bodies. If successful, the attack results in total loss of session integrity, unauthorized access to sensitive communications, and direct financial theft of cryptocurrency assets from both individuals and organizations.

## Recommendation

* Implement browser-based security controls to monitor and restrict the installation of unauthorized browser extensions (e.g., via Group Policy or MDM).
* Monitor for unauthorized JavaScript injection or modifications to web application source code on internet-facing web portals.
* Enforce robust session management and multi-factor authentication (MFA) to mitigate the impact of stolen session cookies and credentials.
* Hunt for abnormal outbound network traffic originating from browser processes, specifically looking for traffic patterns that do not correlate with legitimate user activity.
* Audit web hosting infrastructure for unauthorized script inclusions or modifications, focusing on common landing pages and authentication portals.
