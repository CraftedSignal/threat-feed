---
brief_id: brief-2026-05-ivanti-multiple-vulns
event_id: brief-2026-05-ivanti-multiple-vulns
revision: 2
activity_at: "2026-11-10T19:01:08Z"
revision_history:
  - revision: 2
    at: "2026-11-10T19:01:08Z"
    checksum: sha256:58f54deff3c8c98a5eebe21d981c789edf2b2edfc2c8b6ee91cd63c620592a21
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - priority_signals
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=IVANTI:A4908D8F65F5C1ADD74A86771B38F877&utm_source=rss&utm_medium=rss
title: Ivanti Addresses Multiple Vulnerabilities in Various Products
slug: 2026-05-ivanti-multiple-vulns
description: Ivanti released security advisories on May 12, 2026, to address vulnerabilities in Xtraction, Endpoint Manager (EPM), Virtual Traffic Manager (vTM), and Secure Access Client (Windows), urging users to apply necessary updates to mitigate potential risks from CVE-2026-8043, CVE-2026-8051, CVE-2026-7431, and CVE-2026-7432.
date: "2026-05-12T15:28:49Z"
lastmod: "2026-11-10T18:59:39Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:ivanti:xtraction:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:22.8:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:endpoint_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:endpoint_manager:2024:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:virtual_traffic_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:virtual_traffic_manager:22.9:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=IVANTI:80F01AAF33A0C6687CF93881EEFBC8CF&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=IVANTI:162C3488AD66213A68B5A49ACF39121E&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=IVANTI:A4908D8F65F5C1ADD74A86771B38F877&utm_source=rss&utm_medium=rss
tags:
  - ivanti
  - vulnerability
  - patch
  - cve
vendors:
  - Ivanti
products:
  - Xtraction (<= 2026.1)
  - Endpoint Manager (EPM) (<= 2024 SU5)
  - Virtual Traffic Manager (vTM) (<= 22.9r3)
  - Secure Access Client (Windows) (<= 22.8R5)
  - Ivanti Endpoint Manager (EPM) (< 2024 SU6)
  - Ivanti Secure Access Client (Windows) (< 22.8R6)
  - Ivanti Xtraction (< 2026.2)
  - Ivanti Virtual Traffic Manager (vTM) (vADC) (< 22.9r4)
  - Xtraction (< 2026.2)
affected_os:
  - Windows
cves:
  - id: CVE-2026-8043
    cvss: 9.6
    epss: 0.00869
    kev_status: "false"
  - id: CVE-2026-8051
    cvss: 7.2
    epss: 0.01914
    kev_status: "false"
  - id: CVE-2026-7431
    cvss: 4.4
    epss: 0.00176
    kev_status: "false"
  - id: CVE-2026-7432
    cvss: 7.8
    epss: 0.00284
    kev_status: "false"
  - id: CVE-2026-8111
    cvss: 8.8
    epss: 0.06308
    kev_status: "false"
  - id: CVE-2026-8110
    cvss: 7.8
    epss: 0.00245
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/ivanti-security-advisory-av26-450
  - https://forums.ivanti.com/s/article/kA1UL0000008mU50AI
  - https://forums.ivanti.com/s/article/kA1UL0000008mPF0AY
  - https://forums.ivanti.com/s/article/kA1UL0000008mST0AY
  - https://forums.ivanti.com/s/article/kA1UL0000008mQr0AI
  - https://forums.ivanti.com/s/searchallcontent?language=en_US#tab=All&sortCriteria=date%20descending&f-sfkbknowledgearticletypec=Security%20Advisory
  - https://ccb.belgium.be/advisories/warning-ivanti-has-released-security-updates-address-vulnerabilities-affecting-several
  - https://sploitus.com/exploit?id=IVANTI:80F01AAF33A0C6687CF93881EEFBC8CF&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=IVANTI:162C3488AD66213A68B5A49ACF39121E&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=IVANTI:A4908D8F65F5C1ADD74A86771B38F877&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-8051 Exploitation Attempt - Suspicious URI Access
    description: Detects CVE-2026-8051 exploitation attempt on Ivanti Virtual Traffic Manager (vTM) by monitoring for suspicious URI access patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-7431/7432 Exploitation Attempt - Ivanti Secure Access Client Suspicious Process
    description: Detects possible exploitation of CVE-2026-7431 or CVE-2026-7432 in Ivanti Secure Access Client (Windows) by monitoring process creation events.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-05-14T12:50:55Z"
    level: L2
    summary: added CVE-2026-8110 +1
    sources:
      - ccb-belgium
  - at: "2026-11-10T18:59:37Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=IVANTI:80F01AAF33A0C6687CF93881EEFBC8CF&utm_source=rss&utm_medium=rss
  - at: "2026-11-10T18:59:39Z"
    level: L1
    summary: new product
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=IVANTI:A4908D8F65F5C1ADD74A86771B38F877&utm_source=rss&utm_medium=rss
---

On May 12, 2026, Ivanti published security advisories addressing multiple vulnerabilities across several of their products. The advisories cover Ivanti Xtraction (version 2026.1 and prior), Ivanti Endpoint Manager (EPM) (version 2024 SU5 and prior), Ivanti Virtual Traffic Manager (vTM) (version 22.9r3 and prior), and Ivanti Secure Access Client (Windows) (version 22.8R5 and prior). These vulnerabilities could potentially be exploited by attackers to gain unauthorized access, execute arbitrary code, or cause denial-of-service conditions. It is crucial for organizations using these products to review the specific advisories and apply the recommended updates to protect against these risks. The broad range of affected products emphasizes the need for a comprehensive patching strategy across the Ivanti ecosystem.

## Attack Chain

1.  The attack begins with an unauthenticated attacker identifying a vulnerable Ivanti product within the target environment, potentially through scanning or reconnaissance.
2.  The attacker crafts a malicious request targeting a specific endpoint of the vulnerable product, exploiting a vulnerability such as command injection or authentication bypass (CVE-2026-8043, CVE-2026-8051, CVE-2026-7431, CVE-2026-7432).
3.  The vulnerable Ivanti application processes the malicious request without proper sanitization or validation.
4.  Due to the lack of input validation, the attacker injects arbitrary commands or code into the application's execution flow.
5.  The injected code executes with the privileges of the Ivanti application, potentially allowing the attacker to read sensitive data, modify system configurations, or install malicious software.
6.  The attacker establishes a foothold on the compromised system and attempts to escalate privileges to gain greater control.
7.  With elevated privileges, the attacker moves laterally within the network, compromising additional systems and resources.
8.  The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or disruption of critical services.

## Impact

Successful exploitation of these vulnerabilities could allow attackers to gain unauthorized access to sensitive data, execute arbitrary code, or cause denial-of-service conditions. Depending on the specific vulnerability and the compromised system, the impact could range from minor data breaches to significant disruptions of critical business operations. Organizations using the affected Ivanti products are at risk, and the potential consequences could include financial losses, reputational damage, and regulatory fines. The lack of specific exploitation details in the advisory makes quantifying the potential damage difficult, but the wide deployment of these products suggests a potentially broad impact.

## Recommendation

*   Immediately patch Ivanti Xtraction to a version greater than 2026.1, referencing the Ivanti Security Advisory for CVE-2026-8043.
*   Update Ivanti Endpoint Manager (EPM) beyond version 2024 SU5, as detailed in the Ivanti Security Advisory for Ivanti Endpoint Manager (EPM) May 2026.
*   Upgrade Ivanti Virtual Traffic Manager (vTM) past version 22.9r3, according to the May 2026 Security Advisory Ivanti Virtual Traffic Manager (vTM) addressing CVE-2026-8051.
*   Ensure Ivanti Secure Access Client (Windows) is updated beyond version 22.8R5 to mitigate CVE-2026-7431 and CVE-2026-7432, as per the May 2026 Security Advisory Ivanti Secure Access Client.
*   Deploy network monitoring rules to detect suspicious traffic to and from Ivanti products, specifically looking for patterns indicative of exploitation attempts targeting CVE-2026-8043, CVE-2026-8051, CVE-2026-7431, and CVE-2026-7432.
*   Enable logging on Ivanti products to capture relevant events for security analysis, focusing on authentication attempts, configuration changes, and process executions.
