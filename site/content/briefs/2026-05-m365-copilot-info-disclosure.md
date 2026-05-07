---
title: M365 Copilot Information Disclosure Vulnerability (CVE-2026-26129)
slug: 2026-05-m365-copilot-info-disclosure
description: CVE-2026-26129 is a high-severity vulnerability in Microsoft's M365 Copilot that allows an unauthorized attacker to disclose information over a network due to improper neutralization of special elements.
date: "2026-05-07T22:16:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - information disclosure
  - cloud
  - m365 copilot
vendors:
  - Microsoft
products:
  - M365 Copilot
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-26129
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26129
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26129
rules:
  - title: Detect M365 Copilot Special Element Injection Attempt
    description: Detects CVE-2026-26129 exploitation attempt — HTTP request containing special elements indicative of injection attempts targeting M365 Copilot.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect M365 Copilot Network Information Disclosure
    description: Detects CVE-2026-26129 post-exploitation — Anomalous network traffic from M365 Copilot server potentially indicating information exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On May 7, 2026, CVE-2026-26129 was published, detailing an information disclosure vulnerability within Microsoft's M365 Copilot. The vulnerability stems from improper neutralization of special elements within the application, potentially enabling unauthorized attackers to access sensitive information over a network. Microsoft has assessed the vulnerability as having a CVSS v3.1 score of 7.5 (High), indicating a significant risk. Defenders should prioritize detection and mitigation strategies to prevent potential data breaches.

## Attack Chain

1. An attacker identifies an M365 Copilot instance exposed to network traffic.
2. The attacker crafts a malicious input containing special elements designed to exploit the improper neutralization vulnerability (CVE-2026-26129).
3. The crafted input is sent to the M365 Copilot instance via a network request.
4. M365 Copilot fails to properly neutralize the special elements within the input.
5. The special elements are processed, leading to unintended data access.
6. Sensitive information is extracted by the attacker.
7. The extracted information is transmitted over the network to a location controlled by the attacker.
8. The attacker gains unauthorized access to the disclosed information.

## Impact

Successful exploitation of CVE-2026-26129 can lead to the unauthorized disclosure of sensitive information accessible by M365 Copilot. The impact could range from exposure of internal documents and communications to the revelation of proprietary data and confidential customer information. The number of potential victims is dependent on the scope of M365 Copilot deployments and the sensitivity of the data it handles. A successful attack could result in significant reputational damage, financial losses, and legal liabilities for affected organizations.

## Recommendation

*   Apply the security update provided by Microsoft to address CVE-2026-26129 as soon as possible, referencing the advisory at [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26129](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26129).
*   Deploy the Sigma rule "Detect M365 Copilot Special Element Injection Attempt" to identify potential exploitation attempts based on specific special characters in network requests.
*   Monitor network traffic for suspicious patterns indicative of information disclosure, focusing on communications originating from M365 Copilot instances.
*   Review and strengthen input validation and output encoding mechanisms within M365 Copilot to prevent future instances of improper neutralization, referencing CWE-138.
