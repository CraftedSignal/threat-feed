---
title: ericc-ch copilot-api Permissive Cross-Domain Policy Vulnerability (CVE-2026-6662)
slug: 2024-01-02-copilot-api-cors
description: CVE-2026-6662 is a vulnerability in ericc-ch copilot-api up to 0.7.0, specifically in the cors function of src/server.ts, leading to a permissive cross-domain policy that can be remotely exploited for cross-domain attacks.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - CORS
  - Cross-Site Scripting
  - API Vulnerability
vendors:
  - ericc-ch
products:
  - copilot-api
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6662
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6662
iocs:
  - type: email
    value: '[email&#160;protected]'
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect CVE-2026-6662 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-6662 based on unusual Origin headers when accessing the copilot-api endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect CVE-2026-6662 Exploitation Attempt - Method GET
    description: Detects potential exploitation attempts of CVE-2026-6662 using HTTP GET method with unusual referer.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability, identified as CVE-2026-6662, affects the ericc-ch copilot-api up to version 0.7.0. The weakness lies within the `cors` function of the `src/server.ts` file, specifically in the Token Endpoint component.  Successful exploitation of this vulnerability leads to a permissive cross-domain policy that includes untrusted domains. This flaw allows for remote exploitation, posing a risk to systems utilizing the vulnerable copilot-api versions. The exploit is publicly available, increasing the likelihood of malicious actors leveraging it. This vulnerability could allow attackers to perform actions on behalf of legitimate users.

## Attack Chain

1.  Attacker identifies a server running a vulnerable version (<=0.7.0) of ericc-ch copilot-api.
2.  The attacker crafts a malicious web page designed to exploit the permissive CORS policy.
3.  The attacker hosts the malicious web page on a server they control.
4.  The attacker lures a victim user to visit the malicious web page (e.g., via phishing or drive-by download).
5.  The victim's browser loads the malicious web page, which contains JavaScript code that interacts with the vulnerable copilot-api endpoint.
6.  Due to the permissive CORS policy, the attacker's JavaScript code is allowed to make cross-origin requests to the copilot-api endpoint, bypassing standard browser security restrictions.
7.  The attacker's script leverages the CORS vulnerability to impersonate the victim and performs unauthorized actions. This can include gaining unauthorized access or exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2026-6662 allows attackers to bypass cross-origin restrictions, potentially leading to unauthorized access to sensitive data or the ability to perform actions on behalf of legitimate users. The permissive CORS policy weakens the security posture of applications relying on the vulnerable copilot-api, increasing the risk of cross-site scripting (XSS) attacks and other malicious activities.

## Recommendation

*   Upgrade ericc-ch copilot-api to a version greater than 0.7.0 to patch CVE-2026-6662.
*   Monitor web server logs for suspicious cross-origin requests targeting the copilot-api endpoint to detect potential exploitation attempts. Use the rule "Detect CVE-2026-6662 Exploitation Attempt" to identify requests with unexpected origins.
*   Implement strict CORS policies to limit cross-origin access only to trusted domains, mitigating the impact of this vulnerability even in older versions.
