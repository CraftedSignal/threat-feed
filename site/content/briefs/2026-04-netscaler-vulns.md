---
title: Critical Vulnerabilities in NetScaler ADC and Gateway Allow Sensitive Data Exposure and Session Hijacking
slug: 2026-04-netscaler-vulns
description: Unauthenticated attackers can exploit CVE-2026-3055 (out-of-bounds read) to exfiltrate sensitive data from NetScaler ADC and Gateway, while CVE-2026-4368 (race condition) enables user session hijacking, necessitating immediate patching and enhanced monitoring.
date: "2026-04-01T08:44:01Z"
severities:
  - critical
exploited: true
type: threat
types:
  - threat
tags:
  - netscaler
  - cve-2026-3055
  - cve-2026-4368
  - out-of-bounds read
  - race condition
  - memory corruption
  - session hijacking
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3055
    cvss: 9.8
    epss: 0.45194
  - id: CVE-2026-4368
    epss: 0.00017
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerabilities-netscaler-adc-netscaler-gateway-patch-immediately
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696300
rules:
  - title: Detect Netscaler CVE-2026-3055 GET Request
    description: Detects suspicious HTTP GET requests indicative of CVE-2026-3055 exploitation attempts targeting the SAML IDP in NetScaler ADC and Gateway.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Netscaler CVE-2026-4368 POST Request
    description: Detects suspicious HTTP POST requests indicative of CVE-2026-4368 exploitation attempts targeting the Gateway or AAA virtual server.
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

Citrix NetScaler ADC and Gateway are affected by two critical vulnerabilities, CVE-2026-3055 and CVE-2026-4368. CVE-2026-3055 is an out-of-bounds read vulnerability that allows an unauthenticated attacker to read arbitrary memory content. This could lead to the exfiltration of sensitive data like credentials and session tokens. CVE-2026-4368 is a race condition vulnerability that can lead to user session mix-up, potentially allowing one user to access another user's session. CISA has added CVE-2026-3055 to its Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild as of March 30, 2026. The affected versions include NetScaler ADC and NetScaler Gateway 14.1 before 14.1-66.59, 13.1 before 13.1-62.23, and NetScaler ADC FIPS and NDcPP before 13.1-37.262. Defenders should prioritize patching and closely monitor affected systems.

## Attack Chain

1.  An unauthenticated attacker sends a specially crafted request to a vulnerable NetScaler ADC or Gateway configured as a SAML IDP (for CVE-2026-3055).
2.  Due to insufficient input validation, the appliance attempts to read memory beyond the allocated buffer.
3.  The out-of-bounds read allows the attacker to access sensitive information stored in memory, such as session tokens, credentials, or other confidential data.
4.  The attacker exfiltrates the gleaned sensitive information via network communication.
5.  For CVE-2026-4368, multiple users attempt to authenticate to a NetScaler ADC or Gateway configured as a Gateway or AAA virtual server.
6.  A race condition occurs during session creation or management.
7.  One user's session is incorrectly associated with another user's account.
8.  The attacker gains unauthorized access to another user's session, potentially performing actions on their behalf or accessing sensitive data.

## Impact

Successful exploitation of CVE-2026-3055 allows attackers to steal sensitive information, potentially leading to account compromise, data breaches, and further unauthorized access to internal resources. CVE-2026-4368 can lead to unauthorized access to user accounts, potentially exposing sensitive data or enabling malicious activities under the guise of a legitimate user. Given that CISA has confirmed active exploitation of CVE-2026-3055, organizations using affected NetScaler products are at immediate risk. The impact spans across all sectors utilizing these products for application delivery and secure access.

## Recommendation

*   Immediately patch NetScaler ADC and Gateway to the latest versions: 14.1-66.59 or later, 13.1-62.23 or later, and 13.1-37.262 or later for FIPS and NDcPP to remediate CVE-2026-3055 and CVE-2026-4368 as described in the Citrix advisory ([https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696300](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696300)).
*   Deploy the Sigma rule `Detect Netscaler CVE-2026-3055 GET Request` to identify potential exploitation attempts of CVE-2026-3055 based on suspicious HTTP GET requests targeting the SAML IDP.
*   Enable and review NetScaler audit logs for unusual authentication patterns or session activity that could indicate exploitation of CVE-2026-4368.
*   Monitor web server logs for HTTP requests with abnormally long URIs, which may be indicative of attempts to trigger the out-of-bounds read in CVE-2026-3055.
*   Apply the Sigma rule `Detect Netscaler CVE-2026-4368 POST Request` to identify potential exploitation attempts of CVE-2026-4368 based on suspicious HTTP POST requests targeting the Gateway or AAA virtual server
