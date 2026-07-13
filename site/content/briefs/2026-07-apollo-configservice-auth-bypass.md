---
title: Apollo ConfigService Authentication Bypass via Non-Canonical appId Matching
slug: 2026-07-apollo-configservice-auth-bypass
description: An unauthenticated remote attacker can exploit CVE-2026-59954 in Apollo ConfigService, which allows unauthorized access to sensitive configuration data by bypassing AccessKey authentication through a flaw in appId parsing and non-canonical matching due to database collation rules.
date: "2026-07-13T18:28:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - data-exfiltration
  - vulnerability
  - apollo
vendors:
  - Ctrip
products:
  - Apollo (< 2.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker may read configuration data from affected ConfigService endpoints
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An unauthenticated remote attacker may read configuration data from affected ConfigService endpoints
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4w3q-qpfq-v992
---

This vulnerability, tracked as CVE-2026-59954, affects Apollo ConfigService versions prior to 2.5.2. It enables an unauthenticated remote attacker to bypass AccessKey authentication and read sensitive configuration data. The flaw occurs when the ConfigService accepts a non-canonical `appId` variant in a request, which prevents the AccessKey authentication mechanism from performing signature verification. However, downstream processing, leveraging database collation rules (such as accent-insensitive or PAD SPACE), resolves this non-canonical `appId` to a protected application. This allows an attacker to retrieve confidential information from `/configs` and `/configfiles` endpoints without proper authorization. The issue impacts deployments with AccessKey authentication enabled and specific database collation settings.

## Attack Chain

1. An attacker identifies a publicly accessible Apollo ConfigService endpoint configured with AccessKey authentication.
2. The attacker crafts a malicious HTTP GET request targeting configuration read endpoints (e.g., `/configs` or `/configfiles`) and includes a non-canonical `appId` parameter. This `appId` variant might contain accent differences or trailing spaces, designed to bypass exact string matching.
3. The ConfigService receives the request. Its AccessKey authentication logic attempts to use the provided `appId` to look up available AccessKey secrets for signature verification.
4. Due to the non-canonical nature of the `appId` variant, it does not exactly match the cached AccessKey secrets, causing the authentication process to treat the request as unauthenticated and skip signature verification.
5. However, the request proceeds to downstream processing where the `appId` is used for release lookup, which utilizes database collation rules. These rules (e.g., accent-insensitive or PAD SPACE) cause the non-canonical `appId` to match a legitimate, protected `appId`.
6. The ConfigService then processes the request as if it were for the legitimate `appId` and returns the sensitive configuration data to the unauthenticated attacker.
7. The attacker receives and can exfiltrate the confidential application configuration details.

## Impact

An unauthenticated remote attacker can successfully read sensitive configuration data from affected Apollo ConfigService endpoints, including `/configs` and `/configfiles`. This data could contain credentials, API keys, or other proprietary information, leading to further system compromise, unauthorized access to other services, or data breaches. The impact is specifically observed when AccessKey authentication is enabled and the underlying database collation settings allow for non-canonical `appId` matching. This can expose critical internal application configurations.

## Recommendation

* Upgrade Apollo ConfigService to version 2.5.2 or later immediately to address CVE-2026-59954.
* Review database collation settings for the Apollo database to understand how `appId` variants are treated.
* Monitor web server and application logs for unusual or non-canonical `appId` patterns in requests to `/configs` and `/configfiles` endpoints, especially those not undergoing signature verification.
