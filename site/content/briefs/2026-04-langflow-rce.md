---
title: IBM Langflow Desktop Deserialization RCE (CVE-2026-3357)
slug: 2026-04-langflow-rce
description: IBM Langflow Desktop versions 1.6.0 through 1.8.2 is vulnerable to arbitrary code execution due to insecure deserialization of untrusted data, allowing an authenticated user to execute code on the system.
date: "2026-04-08T01:16:41Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-3357
  - deserialization
  - rce
  - langflow
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-3357
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3357
  - https://www.ibm.com/support/pages/node/7268428
rules:
  - title: Detect Langflow Deserialization Attempt via Suspicious POST Request
    description: Detects potential exploitation attempts of CVE-2026-3357 by monitoring for suspicious POST requests to the Langflow Desktop application that may contain serialized data.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
  - title: Detect Langflow Deserialization Attempt via Large POST Request
    description: Detects potential exploitation attempts of CVE-2026-3357 by monitoring for unusually large POST requests. Deserialization exploits often involve sending large amounts of data.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

IBM Langflow Desktop, a low-code platform designed to build custom LLM applications, is susceptible to a critical vulnerability (CVE-2026-3357) affecting versions 1.6.0 through 1.8.2. The flaw stems from an insecure default setting within the FAISS (Facebook AI Similarity Search) component, which permits the deserialization of untrusted data. This vulnerability allows an authenticated user to execute arbitrary code on the host system. Successful exploitation grants the attacker full control over the Langflow Desktop instance and potentially the underlying system. Due to the ease of exploitation, especially for authenticated users, defenders must prioritize patching or mitigating this issue to prevent potential breaches.

## Attack Chain

1. An authenticated user logs into the vulnerable IBM Langflow Desktop application (versions 1.6.0 through 1.8.2).
2. The attacker crafts malicious serialized data designed to exploit the insecure deserialization vulnerability in the FAISS component.
3. The attacker injects the malicious serialized data into the Langflow application, potentially through a manipulated API request or a crafted workflow file.
4. Langflow Desktop processes the malicious data using the vulnerable FAISS component.
5. The FAISS component deserializes the untrusted data without proper validation.
6. During deserialization, the malicious payload is executed, leading to arbitrary code execution within the context of the Langflow Desktop application.
7. The attacker gains control of the Langflow Desktop application.
8. The attacker leverages the code execution to escalate privileges, install malware, or exfiltrate sensitive data from the affected system.

## Impact

Successful exploitation of CVE-2026-3357 allows an attacker to execute arbitrary code on the system running IBM Langflow Desktop. This could lead to complete system compromise, including data theft, malware installation, and denial of service. Given the low complexity and the ability to exploit it with authentication, this vulnerability poses a significant risk to organizations using the affected versions of Langflow Desktop. The impact is amplified if the Langflow Desktop instance has access to sensitive data or critical infrastructure.

## Recommendation

*   Upgrade IBM Langflow Desktop to a patched version that addresses CVE-2026-3357. Refer to IBM's security advisory ([https://www.ibm.com/support/pages/node/7268428](https://www.ibm.com/support/pages/node/7268428)) for specific upgrade instructions.
*   Implement input validation and sanitization measures to prevent the deserialization of untrusted data.
*   Monitor network traffic for suspicious activity related to Langflow Desktop, such as unexpected API calls or data transfers.
*   Enable logging for Langflow Desktop and related components, and analyze logs for signs of exploitation.
*   Deploy a web application firewall (WAF) with rules to detect and block attempts to exploit deserialization vulnerabilities in web applications.
