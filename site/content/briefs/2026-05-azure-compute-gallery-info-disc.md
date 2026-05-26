---
title: 'CVE-2026-26147: Azure Compute Gallery Information Disclosure via Improper Input Validation'
slug: 2026-05-azure-compute-gallery-info-disc
description: CVE-2026-26147 is an improper input validation vulnerability in Azure Compute Gallery that allows an authorized attacker to disclose information over a network.
date: "2026-05-26T13:32:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-26147
  - information-disclosure
  - cloud
vendors:
  - Microsoft
products:
  - Azure Compute Gallery
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-26147
    cvss: 7.7
    epss: 0.00107
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26147
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26147
rules:
  - title: Detect CVE-2026-26147 Exploitation Attempts via Suspicious Request Parameters
    description: Detects CVE-2026-26147 exploitation attempts — Monitors for suspicious API requests to Azure Compute Gallery potentially indicating attempts to exploit the improper input validation vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2026-26147 Exploitation - High Volume of Errors from Azure Compute Gallery
    description: Detects CVE-2026-26147 exploitation attempts — Monitors for an unusually high volume of server errors originating from the Azure Compute Gallery, potentially indicating an attempted exploit.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-26147 describes an information disclosure vulnerability affecting the Azure Compute Gallery. The vulnerability stems from improper input validation within the service, potentially allowing an authorized attacker to gain unauthorized access to sensitive information over a network. While the specific details of the input validation flaw are not described in the source, the vulnerability is classified as HIGH severity with a CVSS score of 7.7. This vulnerability matters because it can lead to unauthorized disclosure of sensitive data stored within Azure Compute Gallery.

## Attack Chain

1.  The attacker authenticates to the Azure environment with valid credentials, gaining access to the Azure Compute Gallery.
2.  The attacker crafts a malicious request targeting the Azure Compute Gallery API endpoint.
3.  The malicious request exploits the improper input validation flaw by including specially crafted input.
4.  The Azure Compute Gallery processes the malicious request without proper validation.
5.  Due to the lack of input sanitization, the system leaks sensitive information.
6.  The sensitive information is disclosed to the attacker over the network.

## Impact

Successful exploitation of CVE-2026-26147 allows an authorized attacker to disclose sensitive information stored in the Azure Compute Gallery. The impact of this vulnerability is limited to information disclosure and does not allow for code execution, modification of data, or denial of service. The number of victims and the extent of the damage depend on the sensitivity of the data stored within the Azure Compute Gallery and the scope of the attacker's access.

## Recommendation

*   Apply the patch provided by Microsoft to remediate CVE-2026-26147 on Azure Compute Gallery as soon as possible (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26147).
*   Monitor Azure Compute Gallery logs for suspicious API requests containing unusual characters or patterns that may indicate exploitation attempts.
*   Implement and enforce strict input validation on all user-provided input to prevent similar vulnerabilities in the future.
