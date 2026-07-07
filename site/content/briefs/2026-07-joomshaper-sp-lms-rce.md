---
title: JoomShaper SP LMS PHP Object Injection Leads to RCE (CVE-2026-48909)
slug: 2026-07-joomshaper-sp-lms-rce
description: A critical PHP object injection vulnerability (CVE-2026-48909) in JoomShaper SP LMS versions <= 4.1.3 allows unauthenticated attackers to achieve remote code execution (RCE) via a crafted 'lmsOrders' cookie, leading to webshell deployment on vulnerable Joomla installations (< 5.2.2).
date: "2026-07-06T13:45:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - php
  - object-injection
  - rce
  - webshell
vendors:
  - JoomShaper
  - Joomla
products:
  - JoomShaper SP LMS <= 4.1.3
  - Joomla < 5.2.2
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public **webapps** exploit has been published on Exploit-DB for **Joomla Extension 4.1.4**, demonstrating a **PHP Object injection** vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Attack chain: ... FormattedtextLogger.__destruct() [Joomla gadget] → File::write($path, $format) → webshell on disk ... Finally, the attacker can interact with the deployed webshell by sending commands via URL parameters (e.g., `?c=id`), achieving unauthenticated remote code execution.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: ""
    evidence: 'Attack chain: ... File::write($path, $format) → webshell on disk ... This action writes an initial PHP loader ... and write the full PHP webshell to the same location.'
    confidence_band: high
cves:
  - id: CVE-2026-48909
    epss: 0.00796
references:
  - https://www.exploit-db.com/exploits/52617
rules:
  - title: Detect CVE-2026-48909 Exploitation - JoomShaper SP LMS PHP Object Injection
    description: Detects exploitation attempts of CVE-2026-48909 (JoomShaper SP LMS PHP Object Injection) by identifying HTTP GET requests to the vulnerable endpoint with a malformed 'lmsOrders' cookie, specifically looking for base64-encoded serialized objects crafted to bypass common filters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

A high-severity PHP object injection vulnerability, identified as CVE-2026-48909, has been discovered and publicly exploited in JoomShaper SP LMS versions up to 4.1.3. This vulnerability, affecting a popular Joomla Extension, enables an unauthenticated remote attacker to execute arbitrary code on the underlying server. Exploitation occurs by sending a specially crafted 'lmsOrders' cookie to the `com_splms&view=cart` endpoint. If the main Joomla CMS version is older than 5.2.2, a known gadget chain involving `FormattedtextLogger::__destruct()` can be leveraged to write a webshell to disk, granting the attacker full control over the compromised web server. The availability of a public exploit significantly increases the risk for unpatched systems.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious PHP serialized object payload designed to trigger the object injection gadget chain.
2.  The attacker carefully base64-encodes this payload, manipulating it to avoid characters (`/`, `+`, `=`) that would be filtered by Joomla's input sanitizer when transmitted in a cookie.
3.  The attacker sends an HTTP GET request to the `/index.php?option=com_splms&view=cart` endpoint of the vulnerable Joomla instance, including the specially crafted payload within the `lmsOrders` cookie.
4.  The vulnerable `com_splms` component retrieves the `lmsOrders` cookie, base64-decodes it, and then `unserialize()`s the PHP object.
5.  During the deserialization process, if the Joomla CMS version is less than 5.2.2, the `FormattedtextLogger::__destruct()` gadget is triggered, calling `File::write()` with attacker-controlled data.
6.  This action writes an initial PHP loader (containing `hex2bin()` to write the real payload) to a specified, PHP-writable path on the server (e.g., `/tmp/x.php`).
7.  The attacker then makes a subsequent HTTP GET request to the newly created loader file, causing it to execute and write the full PHP webshell to the same location.
8.  Finally, the attacker can interact with the deployed webshell by sending commands via URL parameters (e.g., `?c=id`), achieving unauthenticated remote code execution.

## Impact

Successful exploitation of CVE-2026-48909 grants unauthenticated remote code execution on the target server. This allows attackers to completely compromise the affected Joomla instance and the underlying server, leading to data exfiltration, website defacement, further network penetration, or the deployment of additional malicious payloads such as ransomware. Organizations running JoomShaper SP LMS versions 4.1.3 or earlier, particularly on Joomla CMS versions prior to 5.2.2, are at severe risk of server compromise and potential business disruption.

## Recommendation

*   **Patch CVE-2026-48909 immediately:** Upgrade JoomShaper SP LMS to version 4.1.4 or higher to remediate the PHP Object injection vulnerability.
*   **Update Joomla CMS:** Ensure your core Joomla CMS is updated to version 5.2.2 or higher to mitigate the RCE gadget chain, even if the SP LMS extension cannot be immediately patched.
*   **Deploy the Sigma rule in this brief** to your SIEM and tune for your environment to detect exploitation attempts.
*   **Enable webserver access logging:** Ensure comprehensive logging of HTTP requests, including full URI paths and cookie headers, to aid in detecting and investigating exploitation attempts.
