---
title: Lucee CFML Server Reflected XSS Vulnerability (CVE-2026-29519)
slug: 2026-07-lucee-cfml-xss
description: Lucee CFML Server versions across the 5.3.x, 6.1.x, 6.2.x, and 7.0.x release lines are vulnerable to a reflected cross-site scripting (XSS) flaw in URL path parsing, allowing unauthenticated remote attackers to embed arbitrary HTML or JavaScript payloads within the request path which, when visited by a victim, enables the execution of arbitrary JavaScript in the victim's browser for purposes such as session hijacking or unauthorized actions against the Lucee administrative interface.
date: "2026-07-10T15:20:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - cve
  - network
  - lucee
vendors:
  - Lucee
products:
  - Lucee CFML Server (5.3.x)
  - Lucee CFML Server (6.1.x)
  - Lucee CFML Server (6.2.x)
  - Lucee CFML Server (7.0.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can craft a malicious URL containing injected script content... when a victim visits the crafted link.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows unauthenticated remote attackers to execute arbitrary JavaScript in a victim's browser by embedding HTML or JavaScript payloads within the request path.
    confidence_band: high
cves:
  - id: CVE-2026-29519
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29519
rules:
  - title: Detects CVE-2026-29519 Exploitation - Lucee CFML Server Reflected XSS Attempt
    description: Detects exploitation attempts for CVE-2026-29519, a reflected XSS vulnerability in Lucee CFML Server, by identifying common script tags or HTML entities in the URL path.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-29519 affects Lucee CFML Server versions 5.3.x, 6.1.x, 6.2.x, and 7.0.x, revealing a reflected cross-site scripting (XSS) vulnerability. This flaw resides within the URL path parsing mechanism, allowing unauthenticated remote attackers to inject arbitrary HTML or JavaScript directly into the request path. When a crafted malicious URL is accessed by a victim, the Lucee server reflects this unsanitized content back in its response, causing the victim's browser to execute the attacker-supplied script. This can lead to serious consequences, including session hijacking, unauthorized actions performed through the victim's authenticated session, or other client-side attacks. The vulnerability's impact is significant due to its unauthenticated nature and potential for direct client-side code execution.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable Lucee CFML Server instance.
2. The attacker crafts a malicious URL, embedding an HTML or JavaScript payload within the request path (e.g., `https://vulnerable.lucee.example/path/<script>alert(document.cookie)</script>/`).
3. The attacker then socially engineers a victim into clicking the crafted malicious URL, potentially via phishing emails or compromised websites.
4. The victim's web browser sends the request containing the malicious URL path to the vulnerable Lucee CFML Server.
5. The Lucee server processes the request, and due to the vulnerability, improperly parses and reflects the attacker's embedded HTML/JavaScript payload directly into the server's HTTP response without adequate output encoding.
6. The victim's browser receives the server's response and, upon rendering the page, executes the reflected JavaScript payload embedded in the response.
7. The malicious JavaScript executes in the context of the victim's browser, potentially leading to session hijacking by exfiltrating cookies, performing unauthorized actions against the Lucee administrative interface (if the victim is authenticated), or redirecting the victim to a malicious site.

## Impact

Successful exploitation of CVE-2026-29519 can result in various client-side attacks against unsuspecting users of the Lucee CFML Server. The primary impacts include session hijacking, where an attacker can gain unauthorized access to a victim's authenticated session (e.g., to the administrative interface), enabling them to perform actions as the victim. Furthermore, attackers can deface web pages, redirect users to malicious sites, or leverage the victim's browser for further attacks. The CVSS v3.1 Base Score of 8.2 reflects the high severity of this vulnerability, indicating significant potential damage if exploited.

## Recommendation

* Patch CVE-2026-29519 by updating Lucee CFML Server to a fixed version immediately to mitigate the reflected XSS vulnerability.
* Deploy the `Detects CVE-2026-29519 Exploitation - Lucee CFML Server Reflected XSS Attempt` Sigma rule to your SIEM to detect suspicious URL paths containing potential XSS payloads.
* Monitor web server access logs for unusual request patterns, particularly those with script-like content or HTML tags in the URL path, which could indicate exploitation attempts against this XSS vulnerability.
