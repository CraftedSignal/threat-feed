---
title: Authentication Bypass Vulnerability in CentreStack
slug: 2026-07-centrestack-auth-bypass
description: CentreStack versions prior to 17.2 are vulnerable to an authentication bypass that allows unauthenticated attackers to manipulate account settings and enumerate system data via exposed API endpoints.
date: "2026-07-30T13:41:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - cve-2026-54367
  - api-security
vendors:
  - CentreStack
products:
  - CentreStack (< 17.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The vulnerability allows unauthenticated attackers to read, write, or delete arbitrary account settings by exploiting exposed API endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-54367
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54367
---

CentreStack versions prior to 17.2 contain a critical authentication bypass vulnerability (CVE-2026-54367) originating from exposed API endpoints that fail to enforce necessary authorization checks. By leveraging a static shared encryption key, an unauthenticated attacker can generate valid, encrypted EntAcctId values. These values allow the attacker to forge identifiers for any user GUID, including those associated with system-wide cluster settings. Successful exploitation permits an attacker to perform unauthorized read, write, and delete operations on arbitrary account settings, and provides the capability to enumerate hosted tenant domains and administrative identities. This flaw poses a significant risk to organizations relying on CentreStack for managed file services, as it enables deep unauthorized access to the platform configuration and user data structures.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain administrative-level visibility and control over the platform's account settings. This leads to the exposure of sensitive organizational tenant information, potential account takeover of administrative roles, and the ability to modify core system configurations. The compromise of tenant enumeration and administrative identity metadata significantly increases the risk of further targeted attacks against the organization's infrastructure.

## Recommendation

- Upgrade all CentreStack deployments to version 17.2 or later immediately to remediate CVE-2026-54367.
- Review web server access logs for anomalous, high-frequency POST or GET requests targeting API endpoints associated with user or cluster setting management.
- Perform a security audit of current administrative accounts to ensure no unauthorized identities or modified settings were introduced while the system was unpatched.
