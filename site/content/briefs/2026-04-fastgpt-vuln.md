---
title: Critical Vulnerability in FastGPT Allows API Key Exfiltration and Internal Network Access
slug: 2026-04-fastgpt-vuln
description: CVE-2026-34162 in FastGPT allows unauthenticated attackers to exfiltrate API keys and gain complete access to internal services managed by Docker Compose by sending arbitrary HTTP requests, leading to potential compromise of the internal network.
date: "2026-04-01T16:12:02Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - fastgpt
  - vulnerability
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34162
    cvss: 10
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-fastgpt-patch-immediately
  - https://github.com/labring/FastGPT/security/advisories/GHSA-w36r-f268-pwrj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34162
iocs:
  - type: url
    value: https://ccb.belgium.be/report-incident
ioc_counts:
  url: 1
rules:
  - title: Detect Access to FastGPT HTTP Testing Endpoint
    description: Detects unauthorized access to the FastGPT HTTP tools testing endpoint, which is vulnerable to CVE-2026-34162.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Requests via FastGPT Testing Endpoint
    description: Detects HTTP requests being made through the FastGPT testing endpoint, potentially indicating exploitation of CVE-2026-34162.
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

A critical vulnerability, CVE-2026-34162, has been identified in FastGPT, a framework for building AI-powered applications. The vulnerability resides in the HTTP tools testing endpoint, which is accessible without authentication. This allows an unauthenticated attacker to send arbitrary server-side HTTP requests and receive the responses. If the default admin token is not changed, an attacker can access the proxy management API to exfiltrate third-party API keys. Furthermore, the attacker can interact with and potentially exploit all Docker Compose internal services by manipulating HTTP headers. This issue was publicly disclosed on April 1, 2026, by CCB Belgium, who strongly recommends immediate patching. The vulnerability is patched in version 4.14.9.5. Successful exploitation can lead to complete control over the internal network and sensitive data exposure.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable FastGPT instance exposed to the network.
2.  The attacker accesses the FastGPT HTTP tools testing endpoint without authentication.
3.  The attacker uses the endpoint to send arbitrary HTTP requests to the FastGPT server itself or internal services.
4.  If the default admin token is unchanged, the attacker uses the HTTP proxy functionality to access the proxy management API.
5.  The attacker exfiltrates third-party API keys stored within the FastGPT configuration.
6.  The attacker leverages the exfiltrated API keys to access external services, potentially causing further damage.
7.  The attacker uses the HTTP proxy functionality, including custom headers, to interact with other Docker Compose internal services.
8.  The attacker exploits vulnerabilities in these internal services, leading to complete access to the internal network and sensitive data.

## Impact

Successful exploitation of CVE-2026-34162 can lead to the complete compromise of the FastGPT server and the internal network it manages. An attacker can exfiltrate sensitive API keys, gain unauthorized access to internal services, and potentially pivot to other systems within the network. The vulnerability poses a high risk to the confidentiality and integrity of data, potentially impacting numerous organizations relying on FastGPT for their AI-powered applications. The CCB Belgium advisory highlights the potential for widespread impact given the nature of the vulnerability and the popularity of FastGPT.

## Recommendation

*   Immediately patch FastGPT instances to version 4.14.9.5 to remediate CVE-2026-34162 as per the vendor advisory.
*   Implement the remediations documented in the vendor advisory to strengthen the security of FastGPT instances.
*   Upscale monitoring and detection capabilities to identify any related suspicious activity, ensuring a swift response in case of an intrusion, as recommended by the CCB.
*   Investigate and report any suspected intrusions using the incident reporting URL found in the advisory (https://ccb.belgium.be/report-incident).
