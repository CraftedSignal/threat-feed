---
title: 'Eclipse Jetty: Multiple Vulnerabilities Including Arbitrary Code Execution'
slug: 2026-07-eclipse-jetty-vulnerabilities
description: An authenticated remote attacker can exploit multiple vulnerabilities in Eclipse Jetty to achieve arbitrary code execution, bypass security measures, or perform an HTTP cache poisoning attack, necessitating immediate patching and enhanced monitoring of Jetty instances.
date: "2026-07-06T08:19:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - webserver
  - RCE
  - authentication-bypass
  - cache-poisoning
  - eclipse-jetty
vendors:
  - Eclipse
products:
  - Jetty
affected_os:
  - Linux
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated remote attacker can exploit multiple vulnerabilities in Eclipse Jetty to achieve arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An authenticated remote attacker can exploit multiple vulnerabilities in Eclipse Jetty to [...] bypass security measures.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-2359
---

The German Federal Office for Information Security (BSI) has published an advisory detailing multiple vulnerabilities in Eclipse Jetty, a widely used open-source HTTP server and servlet container. These vulnerabilities, which are still without assigned CVEs as of July 2026, can be exploited by a remote, authenticated attacker. Successful exploitation could lead to arbitrary code execution, allowing an attacker to run malicious commands on the underlying system, bypass existing security mechanisms to gain further access or persist, or conduct HTTP cache poisoning attacks. The lack of specific CVEs means that organizations must actively monitor vendor advisories for Eclipse Jetty for patch availability. This impacts organizations using vulnerable versions of Jetty across various operating systems (Linux, Windows, macOS), making it critical for defenders to apply updates promptly and enhance monitoring for suspicious activity on these internet-facing or internal applications.

## Attack Chain

[The source content does not describe a concrete, step-by-step attack chain, but rather lists potential outcomes of exploiting vulnerabilities. Therefore, a specific attack chain cannot be constructed.]

## Impact

If exploited, these vulnerabilities could lead to severe consequences. Arbitrary code execution grants the attacker full control over the compromised Jetty instance and potentially the underlying server, enabling data exfiltration, further network compromise, or deployment of additional malware. Bypassing security measures could allow an attacker to escalate privileges or access sensitive information protected by Jetty's authentication or authorization mechanisms. HTTP cache poisoning could lead to users receiving malicious or incorrect content from cached responses, enabling phishing, defacement, or other client-side attacks, potentially affecting a large number of users interacting with the application.

## Recommendation

*   Immediately review all Eclipse Jetty instances within your environment and apply available patches as soon as they are released to address these vulnerabilities.
*   Enable and review comprehensive HTTP access logs and application-specific logs for all Eclipse Jetty deployments, focusing on unusual request patterns or unexpected command execution originating from or targeting Jetty processes.
*   Implement strong authentication policies and monitor authentication logs for Eclipse Jetty to detect and prevent unauthorized access attempts, as the vulnerabilities require an authenticated attacker.
