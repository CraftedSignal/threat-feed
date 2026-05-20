---
title: Eclipse GlassFish EL Injection Vulnerability (CVE-2026-2587) Exploit Publicly Available
slug: 2026-05-glassfish-rce
description: A remote code execution vulnerability (CVE-2026-2587) exists in Eclipse GlassFish due to unsanitized user-supplied values in XML attributes being evaluated by the Java Expression Language (EL) engine, and a public exploit is now available.
date: "2026-05-20T22:01:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - el-injection
  - glassfish
  - cve-2026-2587
vendors:
  - Eclipse Foundation
products:
  - GlassFish
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
cves:
  - id: CVE-2026-2587
    cvss: 9.6
    epss: 0.00153
references:
  - https://sploitus.com/exploit?id=27AB4091-5F44-5A52-AA96-3CD9317679E1&utm_source=rss&utm_medium=rss
  - https://github.com/Bhanunamikaze/CVE-2026-2587-Exploit-POC
rules:
  - title: Detect CVE-2026-2587 Exploitation Attempt via GET Request
    description: Detects CVE-2026-2587 exploitation attempt — HTTP GET request to the vulnerable endpoint with a suspicious gadget parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-2587 Exploitation Attempt via EL Injection in XML
    description: Detects CVE-2026-2587 exploitation attempt — Evaluated EL Expression in response.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

A critical Remote Code Execution vulnerability, CVE-2026-2587, has been identified in Eclipse GlassFish. The vulnerability lies in the GlassFish admin console gadget handler.  The application processes `.xml` files fetched from a URL supplied via the `gadget=` query parameter and evaluates user-supplied values inside `` attributes through the Java Expression Language (EL) engine without sanitization. A public exploit PoC has been published, increasing the risk to unpatched GlassFish servers. The exploit, available on Sploitus, targets the `/common/gadgets/gadget.jsf` endpoint and can be triggered via CSRF if an admin session is active. The vulnerability affects Eclipse GlassFish versions prior to 7.1.0.

## Attack Chain

1. Attacker hosts a malicious XML file containing EL expressions (e.g., `#{7*7}`) on a server.
2. Attacker crafts a CSRF page containing an iframe that targets the vulnerable GlassFish instance.
3. The CSRF page is delivered to a logged-in administrator via email or other means.
4. The administrator's browser loads the CSRF page, triggering the iframe.
5. The iframe sends a GET request to `/common/gadgets/gadget.jsf` with the `gadget` parameter pointing to the attacker's hosted XML file.
6. The GlassFish server fetches the XML file from the attacker's server.
7. The GlassFish server evaluates the EL expression within the `ModulePrefs` section of the XML file.
8. If the EL expression contains malicious Java code, the server executes it, leading to remote code execution.

## Impact

Successful exploitation of CVE-2026-2587 allows an attacker to execute arbitrary code on the GlassFish server. This could lead to complete system compromise, data theft, denial of service, or further lateral movement within the network. The availability of a public exploit increases the likelihood of exploitation, especially for organizations that have not yet patched their GlassFish instances. The CVSS score of 9.6 indicates the critical severity of this vulnerability.

## Recommendation

*   Upgrade Eclipse GlassFish to version 7.1.0 or later to patch CVE-2026-2587 (see References).
*   Deploy the Sigma rule "Detect CVE-2026-2587 Exploitation Attempt via GET Request" to detect exploitation attempts (see Rules).
*   Implement CSRF protection measures to mitigate the risk of exploitation through compromised administrator sessions (general security best practice).
*   Monitor web server logs for requests to `/common/gadgets/gadget.jsf` with unusual `gadget` parameter values, especially those pointing to external URLs (see References for vulnerable endpoint).
