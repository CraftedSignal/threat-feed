---
title: Multiple Vulnerabilities in JetBrains TeamCity
slug: 2026-07-jetbrains-teamcity-vulnerabilities
description: Multiple vulnerabilities in JetBrains TeamCity could allow an attacker to execute arbitrary code, manipulate data, or perform Cross-Site Scripting (XSS) attacks, potentially leading to system compromise or client-side attacks.
date: "2026-07-13T10:02:51Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - code-execution
  - cross-site-scripting
  - data-manipulation
  - jetbrains
  - teamcity
vendors:
  - JetBrains
products:
  - TeamCity
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An Angreifer kann mehrere Schwachstellen in JetBrains TeamCity ausnutzen, um beliebigen Programmcode auszuführen
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Cross-Site-Scripting-Angriffe durchzuführen
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2288
---

JetBrains TeamCity, a widely used continuous integration and continuous delivery (CI/CD) server, is affected by multiple vulnerabilities recently disclosed by CERT-Bund. These critical flaws could allow an unauthenticated attacker to execute arbitrary code on the server, manipulate critical data within the platform, or conduct Cross-Site Scripting (XSS) attacks against legitimate users. While specific details about the nature of these vulnerabilities or any active exploitation campaigns are not provided in this advisory, successful exploitation could lead to full compromise of the CI/CD pipeline, potentially resulting in supply chain attacks, unauthorized data exfiltration, or defacement of build artifacts. Organizations using TeamCity are strongly advised to update their installations promptly to mitigate these significant risks.

## Attack Chain

1. An attacker identifies publicly exposed or internal JetBrains TeamCity instances using network scanning or reconnaissance techniques.
2. The attacker identifies specific vulnerabilities within the TeamCity instance that allow for arbitrary code execution, data manipulation, or Cross-Site Scripting.
3. The attacker crafts and sends a specially malformed request or input that exploits a code execution vulnerability.
4. Upon successful exploitation, the attacker's arbitrary code is executed on the TeamCity server, potentially gaining shell access or remote command execution capabilities.
5. Alternatively, the attacker exploits a data manipulation flaw to alter build configurations, project settings, or user permissions within TeamCity, leading to unauthorized changes in the CI/CD pipeline.
6. In another scenario, the attacker injects malicious JavaScript payloads into vulnerable TeamCity web interfaces via a Cross-Site Scripting (XSS) flaw.
7. The XSS payload executes within the browsers of unsuspecting TeamCity users who view the compromised pages, potentially leading to session hijacking, credential theft, or further client-side attacks.
8. Depending on the exploited vulnerability, the attacker achieves full system compromise of the TeamCity server and its underlying infrastructure, introduces malicious code into software builds, or compromises user accounts.

## Impact

Successful exploitation of these vulnerabilities can lead to severe consequences, ranging from full system compromise of the JetBrains TeamCity server to client-side attacks affecting users. Arbitrary code execution can allow attackers to gain control over the underlying infrastructure, potentially accessing sensitive source code, build artifacts, or deployment credentials. Data manipulation vulnerabilities can enable attackers to tamper with the software supply chain, injecting malicious code into released products. Cross-Site Scripting flaws can compromise user accounts, facilitate credential theft, and enable further attacks within the affected organization's network.

## Recommendation

* Immediately patch or update all JetBrains TeamCity instances to the latest secure version to remediate the multiple vulnerabilities.
* Restrict network access to your TeamCity server to only trusted IP ranges and necessary personnel to limit exposure.
