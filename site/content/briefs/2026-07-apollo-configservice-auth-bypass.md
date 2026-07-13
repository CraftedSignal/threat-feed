---
title: Apollo ConfigService Authentication Bypass via Raw Config File AppId Parsing
slug: 2026-07-apollo-configservice-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-59955) in Apollo ConfigService allows unauthenticated remote attackers to read raw configuration data by exploiting an incorrect appId parsing logic for the raw config file endpoint, affecting versions prior to 2.5.2.
date: "2026-07-13T18:38:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - data-exposure
  - vulnerability
  - cloud
vendors:
  - Ctrip
products:
  - Apollo ConfigService (< 2.5.2)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An unauthenticated remote attacker may read raw configuration data from affected ConfigService endpoints
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Apollo ConfigService may allow unauthorized access to raw configuration data when AccessKey / management key authentication is enabled because authentication parsed the appId incorrectly for the raw config file endpoint.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h4pc-58cc-hc95
---

A critical authentication bypass vulnerability, tracked as CVE-2026-59955, has been identified in Apollo ConfigService versions prior to 2.5.2. This flaw allows unauthenticated remote attackers to gain unauthorized access to sensitive raw configuration data. The vulnerability arises when AccessKey / management key authentication is enabled, but the ConfigService incorrectly parses the `appId` for requests targeting the `/configfiles/raw/{appId}/{clusterName}/{namespace}` endpoint. Instead of recognizing the actual `appId` in the path, the service interprets it as the literal string "raw". If no AccessKey is specifically configured for an application named "raw", the service proceeds without verifying the request signature, effectively bypassing authentication for the intended target `appId` and leading to data exposure. This issue impacts organizations using vulnerable versions of Apollo ConfigService, potentially exposing critical system configurations and credentials.

## Attack Chain

1. An unauthenticated attacker identifies an internet-exposed Apollo ConfigService instance.
2. The attacker crafts an HTTP GET request targeting the raw configuration file endpoint: `/configfiles/raw/{targetAppId}/{clusterName}/{namespace}`.
3. The Apollo ConfigService, with AccessKey authentication enabled, receives the request and initiates the authentication parsing process.
4. Due to the vulnerability, the service incorrectly extracts the `appId` as the literal string "raw" from the raw config file endpoint path, instead of the `{targetAppId}` specified by the attacker.
5. The service then attempts to look up AccessKey secrets associated with an application named "raw".
6. If no AccessKey is found for an application literally named "raw" (which is often the case), the ConfigService bypasses the critical signature verification step.
7. The service proceeds to process the request for the original `{targetAppId}`, unknowingly granting unauthorized access.
8. The attacker successfully reads sensitive raw configuration data, which may contain API keys, database credentials, or other proprietary information.

## Impact

Successful exploitation of CVE-2026-59955 allows unauthenticated remote attackers to read sensitive raw configuration data from affected Apollo ConfigService endpoints. This direct access to configuration details can lead to severe consequences, including credential compromise, intellectual property theft, further system compromise, and unauthorized data access. The exact number of victims is not publicly available, but organizations using vulnerable versions of Apollo ConfigService are at risk.

## Recommendation

* Upgrade Apollo ConfigService to version 2.5.2 or later immediately to patch CVE-2026-59955.
* Review access logs for `/configfiles/raw` endpoints for unusual or unauthenticated access patterns prior to patching.
