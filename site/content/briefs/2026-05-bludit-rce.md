---
title: Bludit CMS 3.18.4 Remote Code Execution Vulnerability
slug: 2026-05-bludit-rce
description: A remote code execution vulnerability exists in Bludit CMS 3.18.4, for which a public exploit has been published, increasing the risk to unpatched systems.
date: "2026-05-08T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - rce
  - bludit
vendors:
  - Bludit
products:
  - Bludit CMS 3.18.4
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://www.exploit-db.com/exploits/52553
rules:
  - title: Detect Bludit CMS RCE Attempt via HTTP Request
    description: Detects potential RCE exploitation attempts against Bludit CMS based on suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
  - title: Detect Bludit CMS RCE via User-Agent
    description: Detects potential RCE exploitation attempts against Bludit CMS based on suspicious User-Agent strings.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
rules_count: 2
---

A remote code execution vulnerability has been identified in Bludit CMS version 3.18.4. The vulnerability is now considered critical due to the public availability of a working exploit (EDB-52553) on Exploit-DB. This exploit allows unauthenticated attackers to execute arbitrary code on systems running the vulnerable version of Bludit CMS. The availability of a public exploit lowers the barrier to entry for attackers, potentially leading to widespread exploitation attempts. Defenders should prioritize patching or mitigating this vulnerability to prevent potential compromise.

## Attack Chain

1.  Attacker identifies a Bludit CMS 3.18.4 instance accessible over the internet.
2.  Attacker crafts a malicious HTTP request containing the RCE exploit.
3.  The crafted request is sent to the vulnerable Bludit CMS server.
4.  The Bludit CMS processes the malicious request without proper sanitization.
5.  The exploit triggers arbitrary code execution on the server.
6.  Attacker executes commands to gain a persistent foothold (e.g., by writing a web shell).
7.  Attacker uses the web shell to perform further reconnaissance and lateral movement.
8.  Attacker achieves their objective, such as data exfiltration or defacement of the website.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the target system, potentially leading to full system compromise. This could result in data breaches, website defacement, or the use of the compromised server for malicious purposes such as hosting malware or participating in botnets. The impact is especially severe for publicly accessible Bludit CMS installations.

## Recommendation

*   Upgrade Bludit CMS to a patched version that addresses this RCE vulnerability if available.
*   Deploy the Sigma rule "Detect Bludit CMS RCE Attempt via HTTP Request" to identify exploitation attempts in web server logs.
*   Implement web application firewall (WAF) rules to filter out malicious requests targeting the RCE vulnerability.
*   Monitor web server logs for suspicious activity, such as unusual file access or command execution patterns.
*   Apply principle of least privilege to the web server user account to limit the impact of a successful exploit.
*   Consider using a runtime application self-protection (RASP) solution to detect and block RCE attempts in real-time.
