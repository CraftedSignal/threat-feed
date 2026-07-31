---
title: Critical Hard-coded Credential Vulnerability in Rich Source DMS+ (Non-Mobile)
slug: 2026-07-dms-plus-hardcoded-creds
description: Rich Source DMS+ (Non-Mobile) versions 5.63 and earlier contain a hard-coded API key allowing unauthenticated remote attackers to gain full administrative control over affected devices.
date: "2026-07-31T07:36:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Rich Source
products:
  - DMS+ (Non-Mobile) (5.63)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote attackers can exploit a fixed API key to gain control over all installed DMS+ devices.
    confidence_band: high
cves:
  - id: CVE-2026-18452
    cvss: 10
references:
  - https://www.twcert.org.tw/en/cp-139-11073-de184-2.html
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18452
---

Rich Source DMS+ (Non-Mobile), a device management solution, contains a critical Use of Hard-coded Credentials vulnerability (CWE-798) tracked as CVE-2026-18452. The vulnerability resides in the application's API implementation, where a fixed, hard-coded API key is utilized for authentication purposes. This flaw allows an unauthenticated, remote attacker to bypass all authentication controls by supplying the hard-coded key in API requests. Successful exploitation grants the attacker full administrative access to the DMS+ device. Given the nature of a device management platform, this could lead to widespread system compromise, data exfiltration, and full control over connected infrastructure. This vulnerability affects all versions of DMS+ (Non-Mobile) up to and including version 5.63. Defenders should prioritize patching or restricting network access to these devices immediately.

## Impact

The vulnerability carries a CVSS base score of 10.0, indicating a critical severity level. Exploitation provides an unauthenticated remote attacker with full administrative control over the affected DMS+ devices, potentially enabling the compromise of all managed infrastructure, unauthorized data access, and the execution of arbitrary commands. Organizations utilizing DMS+ (Non-Mobile) versions 5.63 or earlier face significant risk of total device takeover.

## Recommendation

1. Upgrade to the latest version of DMS+ (Non-Mobile) as provided by the vendor, Rich Source, to remediate the vulnerability associated with CVE-2026-18452.
2. Implement strict network segmentation and firewall rules to limit exposure of DMS+ management interfaces to the public internet.
3. Monitor web server logs and API gateway traffic for anomalous, repetitive, or unauthorized API key usage patterns that deviate from baseline client behavior.
4. Perform an inventory audit of all assets to identify and isolate instances of DMS+ (Non-Mobile) version 5.63 or earlier that remain unpatched.
