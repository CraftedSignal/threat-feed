---
title: Insecure Deserialization Vulnerability in Telerik UI for AJAX RadFilter Control (CVE-2026-6023)
slug: 2026-04-telerik-rce
description: An insecure deserialization vulnerability exists in Progress Telerik UI for AJAX's RadFilter control (versions 2024.4.1114 through 2026.1.421) allowing remote code execution via tampering with the filter state exposed to the client.
date: "2026-04-22T08:16:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-6023
  - telerik
  - deserialization
  - rce
  - webserver
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6023
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6023
  - https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-deserialization-of-untrusted-data-cve-2026-6023
rules:
  - title: Detect Suspicious Telerik RadFilter Deserialization Attempt
    description: Detects suspicious HTTP requests potentially exploiting the Telerik RadFilter deserialization vulnerability (CVE-2026-6023) by identifying requests with unusual patterns in the query string or body.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - windows|linux
  - title: Detect Telerik RadFilter ViewState Tampering
    description: Detects potential ViewState tampering attempts in Telerik RadFilter, indicative of deserialization exploits.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
rules_count: 2
---

CVE-2026-6023 exposes a critical vulnerability within the RadFilter control of Progress Telerik UI for AJAX. Affecting versions 2024.4.1114 to 2026.1.421, this flaw stems from insecure deserialization practices. The vulnerability arises when the filter state is exposed to the client, enabling malicious actors to manipulate this state. Successful exploitation grants attackers the ability to execute arbitrary code on the server. This vulnerability poses a significant risk to organizations utilizing the affected Telerik UI for AJAX versions, potentially leading to complete system compromise and data breaches. Defenders must promptly address this issue through patching or mitigation strategies.

## Attack Chain

1.  The attacker identifies a web application utilizing a vulnerable version of Progress Telerik UI for AJAX (2024.4.1114 - 2026.1.421) with the RadFilter control enabled.
2.  The attacker observes the RadFilter control's behavior, specifically how filter states are serialized and exposed to the client-side, typically within the HTTP request or response.
3.  The attacker intercepts the serialized filter state data, often Base64 encoded or similar, transmitted between the client and server.
4.  The attacker crafts a malicious serialized payload containing instructions to execute arbitrary code on the server. This involves exploiting the insecure deserialization process.
5.  The attacker replaces the original, legitimate serialized filter state with the malicious payload.
6.  The attacker sends the modified request containing the malicious serialized data to the server.
7.  The Telerik UI for AJAX application on the server attempts to deserialize the tampered data using the RadFilter control.
8.  Due to the insecure deserialization vulnerability, the malicious payload is executed, granting the attacker remote code execution on the server. The attacker can then perform actions such as installing malware, exfiltrating sensitive data, or disrupting services.

## Impact

Successful exploitation of CVE-2026-6023 can lead to complete compromise of the affected server. An attacker can gain remote code execution, enabling them to install malware, steal sensitive data, or disrupt critical business operations. Given the widespread use of Telerik UI in enterprise applications, this vulnerability could potentially impact a large number of organizations across various sectors. Unpatched systems are at high risk of being exploited, leading to significant financial and reputational damage.

## Recommendation

*   Immediately upgrade Progress Telerik UI for AJAX to a patched version outside the range of 2024.4.1114 through 2026.1.421 to remediate CVE-2026-6023.
*   Deploy the Sigma rule `Detect Suspicious Telerik RadFilter Deserialization Attempt` to identify attempts to exploit the deserialization vulnerability by monitoring for suspicious HTTP requests targeting the RadFilter control (Log source: webserver).
*   Implement input validation and sanitization on the server-side to prevent malicious data from being deserialized.
*   Monitor web server logs for unusual activity related to the RadFilter control, such as requests with abnormally large or malformed serialized data (Log source: webserver).
