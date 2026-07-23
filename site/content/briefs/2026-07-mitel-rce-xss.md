---
title: Multiple Vulnerabilities in Mitel Products Allow Remote Code Execution and XSS
slug: 2026-07-mitel-rce-xss
description: Multiple vulnerabilities have been discovered in Mitel MiCollab and Openscape UC products, enabling a remote attacker to achieve arbitrary code execution and conduct indirect remote code injection (XSS), posing significant risks to affected organizations.
date: "2026-07-23T11:54:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - xss
  - mitel
vendors:
  - Mitel
products:
  - MiCollab versions 10.2.x antérieures à 10.2 SP1 FP2 (10.2.1.205)
  - MiCollab versions 10.3.x antérieures à 10.3.0.18
  - MiCollab versions antérieures à 9.8 SP3 FP2 (9.8.3.203)
  - Openscape UC versions V10 antérieures à V10 R6 FR18
  - Openscape UC versions V11 antérieures à V11 R1 FR2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De multiples vulnérabilités ont été découvertes dans les produits Mitel. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance et une injection de code indirecte à distance (XSS).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: et une injection de code indirecte à distance (XSS).
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0911/
  - https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2026-0006
  - https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2026-0007
iocs:
  - type: url
    value: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2026-0006
  - type: url
    value: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2026-0007
ioc_counts:
  url: 2
---

The French National Agency for the Security of Information Systems (ANSSI) has published an advisory regarding multiple critical vulnerabilities discovered in Mitel's MiCollab and Openscape UC products. These security flaws allow a remote attacker to achieve arbitrary code execution (RCE) and perform indirect remote code injection, commonly known as Cross-Site Scripting (XSS). The affected versions include MiCollab versions 10.2.x prior to 10.2 SP1 FP2 (10.2.1.205), versions 10.3.x prior to 10.3.0.18, and versions prior to 9.8 SP3 FP2 (9.8.3.203). Openscape UC versions V10 prior to V10 R6 FR18 and V11 prior to V11 R1 FR2 are also impacted. These vulnerabilities pose a severe risk to organizations using the affected communications platforms, potentially leading to full system compromise or client-side attacks against users.

## Attack Chain

1. **Reconnaissance & Vulnerability Identification**: An attacker identifies publicly exposed and unpatched Mitel MiCollab or Openscape UC servers within a target organization's network perimeter.
2. **Initial Exploitation (RCE)**: The attacker crafts and sends a specially malformed HTTP request or input payload designed to trigger an arbitrary code execution vulnerability on the vulnerable server.
3. **Initial Exploitation (XSS)**: Alternatively or in parallel, the attacker exploits an indirect remote code injection (XSS) vulnerability by injecting malicious client-side script into a data field or application response.
4. **Arbitrary Code Execution**: The vulnerable Mitel server processes the malicious input, leading to the execution of attacker-controlled code with the privileges of the affected service or system.
5. **Client-Side Script Execution**: If the XSS vulnerability is successfully exploited, the injected script executes within the web browser of any legitimate user who subsequently accesses the compromised application.
6. **Impact (RCE)**: Successful RCE provides the attacker with unauthorized control over the affected Mitel server, enabling actions such as deploying malware, establishing persistence, exfiltrating sensitive data, or pivoting to other systems.
7. **Impact (XSS)**: Successful XSS allows the attacker to compromise user sessions, steal credentials, deface web content, or perform other client-side malicious actions, affecting users interacting with the vulnerable application.

## Impact

The successful exploitation of these vulnerabilities can lead to severe consequences for organizations utilizing the affected Mitel products. Remote Code Execution allows attackers to gain complete control over the compromised server, potentially leading to unauthorized access to sensitive data, system disruption, installation of backdoors, or the deployment of ransomware. Cross-Site Scripting (XSS) attacks can compromise user accounts, steal session cookies, deface websites, or launch phishing attacks against users interacting with the vulnerable application. Organizations in various sectors relying on these communication platforms for their daily operations are at risk of significant operational disruption and data breaches.

## Recommendation

* Refer to the Mitel security advisories and promptly apply the recommended patches to all affected MiCollab and Openscape UC instances.
* Block network connections to indicators of compromise from the iocs table at the network perimeter.
* Regularly review web server logs for unusual requests or patterns associated with RCE or XSS exploitation attempts, including `webserver` category logs for unusual `cs-uri-stem` or `cs-uri-query` values.
