---
brief_id: brief-2024-01-03-citrix-bleed
event_id: brief-2024-01-03-citrix-bleed
revision: 1
activity_at: "2024-01-03T12:00:00Z"
title: Citrix ADC and Gateway Unauthorized Data Disclosure (CVE-2023-4966)
slug: 2024-01-citrix-bleed
description: Exploitation of CVE-2023-4966, known as Citrix Bleed, allows unauthorized data disclosure via the /oauth/idp/.well-known/openid-configuration endpoint, leading to session token theft and potential unauthorized access.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-10-29T02:49:02Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:fips:*:*:*
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:ndcpp:*:*:*
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:-:*:*:*
  - cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AKSHTHEJO-CVE-2023-4966-EXPLOIT&utm_source=rss&utm_medium=rss
tags:
  - citrix
  - cve-2023-4966
  - session-hijacking
  - data-disclosure
vendors:
  - Citrix
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2023-4966
    cvss: 9.4
    epss: 0.99999
    kev_status: "false"
references:
  - https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966
  - https://github.com/assetnote/exploits/tree/main/citrix/CVE-2023-4966
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AKSHTHEJO-CVE-2023-4966-EXPLOIT&utm_source=rss&utm_medium=rss
rules:
  - title: Citrix ADC and Gateway Unauthorized Data Disclosure
    description: Detects attempts to exploit the Citrix Bleed vulnerability (CVE-2023-4966) by monitoring for HTTP requests with a 200 status code targeting the /oauth/idp/.well-known/openid-configuration URL endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Citrix Bleed - Suspicious HTTP Method
    description: Detects potential Citrix Bleed exploitation attempts using unusual HTTP methods for the /oauth/idp/.well-known/openid-configuration endpoint.
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
updates:
  - at: "2026-10-29T02:49:02Z"
    level: L2
    summary: poc_available; added CVE-2023-4966
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AKSHTHEJO-CVE-2023-4966-EXPLOIT&utm_source=rss&utm_medium=rss
---

The Citrix Bleed vulnerability (CVE-2023-4966) is a critical security flaw affecting Citrix ADC and Gateway appliances. This vulnerability allows an unauthenticated attacker to perform unauthorized data disclosure. Successful exploitation leads to the leakage of session tokens, potentially enabling attackers to hijack legitimate user sessions. The vulnerability was widely discussed in late 2023, with proof-of-concept exploits rapidly emerging. Organizations that have not patched their Citrix ADC and Gateway appliances are vulnerable to session hijacking and subsequent data breaches. The scope of potential attacks is broad, affecting any organization using vulnerable Citrix appliances for remote access or application delivery.

## Attack Chain

1. An attacker sends a crafted HTTP request to a vulnerable Citrix ADC or Gateway appliance, specifically targeting the `/oauth/idp/.well-known/openid-configuration` endpoint.
2. The vulnerable appliance processes the request without proper sanitization, leading to information leakage.
3. The appliance responds with an HTTP 200 OK status code, including sensitive data in the response body.
4. The attacker captures leaked session tokens from the HTTP response.
5. The attacker uses the stolen session tokens to authenticate to Citrix resources as a legitimate user.
6. The attacker bypasses multi-factor authentication (MFA) if only session-based.
7. The attacker gains unauthorized access to internal applications and data.
8. The attacker exfiltrates sensitive information or performs other malicious actions within the compromised network.

## Impact

Successful exploitation of CVE-2023-4966 can have severe consequences. An attacker can hijack legitimate user sessions, bypassing authentication mechanisms, including MFA in some cases. This grants them unauthorized access to sensitive internal applications, data, and resources. The leaked session tokens can be used to move laterally within the network, potentially compromising additional systems. The impact includes data breaches, financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Apply the latest security patches provided by Citrix for CVE-2023-4966 immediately to your Citrix ADC and Gateway appliances.
*   Deploy the Sigma rule `Citrix ADC and Gateway Unauthorized Data Disclosure` to your SIEM to detect exploitation attempts, monitoring web traffic for requests to `/oauth/idp/.well-known/openid-configuration` with a 200 status code.
*   Review web server logs for unusual activity targeting the `/oauth/idp/.well-known/openid-configuration` endpoint, paying close attention to the `url` and `status` fields.
*   Implement multi-factor authentication (MFA) mechanisms that are resistant to session hijacking.
